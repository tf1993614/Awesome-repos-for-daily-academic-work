"""Bounded streaming content evidence. No extraction and no business-file writes."""
from __future__ import annotations

import bz2
import contextlib
import csv
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zipfile
import remote_io

from inventory import (RELIABLE_INODES, RUNTIME_MARKER, absolute, connect, dump, is_runtime,
                       mark_runtime, meta, mount_for, mounts, no_symlink_path, now, within)
from registration import parent_handle

CHUNK = 1024 * 1024
MAX_EXPANDED = 1024 ** 4
MAX_MEMBERS = 1_000_000
PROTECTED = {'PROJECT.md', '.gitignore', 'inventory.sqlite', 'inventory.sqlite-wal', 'inventory.sqlite-shm', RUNTIME_MARKER}
SUFFIXES = ('.tar.gz', '.tar.bz2', '.tar.xz', '.tgz', '.tbz2', '.txz', '.tar', '.zip', '.gz', '.bz2', '.xz')


def fingerprint(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


@contextlib.contextmanager
def regular(path):
    path = absolute(str(path))
    with parent_handle(path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f'Not a regular file: {path}')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                yield remote_io.reader(stream, path), before, os.fstat(parent)
            if fingerprint(os.fstat(fd)) != fingerprint(before):
                raise ValueError(f'File changed while reading: {path}')
            if fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)) != fingerprint(before):
                raise ValueError(f'Path changed while reading: {path}')
        finally:
            os.close(fd)


def attributes(stream, s):
    try:
        names = os.listxattr(stream.fileno())
    except (OSError, AttributeError):
        names = None
    return {'mode': stat.S_IMODE(s.st_mode), 'uid': s.st_uid, 'gid': s.st_gid,
            'xattr_names': names, 'acl_restore': 'not_guaranteed', 'nlink': s.st_nlink}


def read_hash(stream, limit=None, compare=None):
    h = hashlib.sha256(); size = 0
    while True:
        block = stream.read(CHUNK)
        if not block:
            break
        size += len(block)
        if limit is not None and size > limit:
            raise ValueError('Expanded-byte limit exceeded')
        h.update(block)
        if compare is not None and compare.read(len(block)) != block:
            raise ValueError('Final byte comparison failed')
    if compare is not None and compare.read(1):
        raise ValueError('Final byte comparison length mismatch')
    return size, h.hexdigest()


def file_evidence(path):
    with regular(path) as (stream, s, parent):
        size, sha = read_hash(stream)
        result = {'kind': 'file', 'path': absolute(str(path)), 'member': None, 'length': size,
                  'sha256': sha, 'fingerprint': fingerprint(s),
                  'allocated': s.st_blocks * 512 if hasattr(s, 'st_blocks') and s.st_blocks >= 0 else None,
                  'parent_identity': [parent.st_dev, parent.st_ino], 'attributes': attributes(stream, s)}
    result['mount'] = mount_for(result['path'], mounts())
    return result


def archive_type(path):
    name = str(path).lower()
    return next((suffix for suffix in SUFFIXES if name.endswith(suffix)), None)


def safe_member(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts or '\\' in name or '\x00' in name or (p.parts and ':' in p.parts[0]):
        raise ValueError(f'Unsafe archive member: {name!r}')
    return str(p)


class PayloadReader:
    """Hash the uncompressed tar stream, including padding after its last member."""
    def __init__(self, stream, limit, compare=None):
        self.stream = stream; self.limit = limit; self.compare = compare
        self.length = 0; self.hash = hashlib.sha256()

    def read(self, size=-1):
        block = self.stream.read(size)
        self.length += len(block)
        if self.length > self.limit:
            raise ValueError('Expanded-byte limit exceeded')
        self.hash.update(block)
        if self.compare is not None and self.compare.read(len(block)) != block:
            raise ValueError('Final tar payload byte comparison failed')
        return block


def archive_evidence(path, max_expanded=MAX_EXPANDED, max_members=MAX_MEMBERS, comparisons=None,
                     source=None, comparison_open=regular):
    """Validate all members, optionally comparing selected members to ordinary files."""
    suffix = archive_type(path)
    if suffix is None:
        raise ValueError('Unsupported archive format')
    if max_expanded < 1 or max_members < 1:
        raise ValueError('Archive limits must be positive')
    comparisons = comparisons or {}
    entries = []; seen = set(); total = 0
    with contextlib.ExitStack() as stack:
        if source is None:
            raw, s, parent = stack.enter_context(regular(path))
            attrs = attributes(raw, s)
            common = {'path': absolute(str(path)), 'fingerprint': fingerprint(s),
                      'parent_identity': [parent.st_dev, parent.st_ino], 'attributes': attrs,
                      'mount': mount_for(absolute(str(path)), mounts())}
        else:
            raw, common = stack.enter_context(source())
        compare_streams = {key: stack.enter_context(comparison_open(value))[0] for key, value in comparisons.items()}

        def consume(stream, member, kind='member', member_attributes=None):
            nonlocal total
            length, sha = read_hash(stream, max_expanded - total, compare_streams.get((kind, member)))
            total += length
            entries.append({'kind': kind, 'member': member, 'length': length, 'sha256': sha,
                            'member_attributes': member_attributes})

        if suffix == '.zip':
            archive = stack.enter_context(zipfile.ZipFile(raw))
            if len(archive.infolist()) > max_members:
                raise ValueError('Archive member limit exceeded')
            for info in archive.infolist():
                name = safe_member(info.filename)
                if name in seen:
                    raise ValueError('Ambiguous duplicate archive member')
                seen.add(name)
                mode = info.external_attr >> 16
                if info.flag_bits & 1:
                    raise ValueError('Encrypted archive unsupported')
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError('Non-regular archive member unsupported')
                if info.is_dir():
                    continue
                if name == '.':
                    raise ValueError('Empty normalized regular member path')
                if info.file_size > max_expanded - total:
                    raise ValueError('Expanded-byte limit exceeded')
                with archive.open(info) as member:
                    consume(member, name, member_attributes={'mode': stat.S_IMODE(mode)})
        else:
            if suffix in ('.gz', '.tar.gz', '.tgz'):
                expanded = stack.enter_context(gzip.GzipFile(fileobj=raw))
            elif suffix in ('.bz2', '.tar.bz2', '.tbz2'):
                expanded = stack.enter_context(bz2.BZ2File(raw))
            elif suffix in ('.xz', '.tar.xz', '.txz'):
                expanded = stack.enter_context(lzma.LZMAFile(raw))
            else:
                expanded = raw
            is_tar = suffix not in ('.gz', '.bz2', '.xz')
            if is_tar:
                payload = PayloadReader(expanded, max_expanded, compare_streams.get(('payload', None)))
                archive = stack.enter_context(tarfile.open(fileobj=payload, mode='r|'))
                count = 0
                for info in archive:
                    count += 1
                    if count > max_members:
                        raise ValueError('Archive member limit exceeded')
                    name = safe_member(info.name)
                    if name in seen:
                        raise ValueError('Ambiguous duplicate archive member')
                    seen.add(name)
                    if info.isdir():
                        continue
                    if name == '.':
                        raise ValueError('Empty normalized regular member path')
                    if not info.isfile() or info.issparse():
                        raise ValueError('Non-regular or sparse archive member unsupported')
                    if info.size > max_expanded - total:
                        raise ValueError('Expanded-byte limit exceeded')
                    with archive.extractfile(info) as member:
                        consume(member, name, member_attributes={'mode': info.mode, 'uid': info.uid, 'gid': info.gid})
                while payload.read(CHUNK):
                    pass
                if payload.compare is not None and payload.compare.read(1):
                    raise ValueError('Final tar payload comparison length mismatch')
                if suffix != '.tar':
                    entries.append({'kind': 'payload', 'member': None, 'length': payload.length,
                                    'sha256': payload.hash.hexdigest(), 'member_attributes': None})
            else:
                consume(expanded, None, 'payload')
        keys = {(e['kind'], e['member']) for e in entries}
        if not set(comparisons).issubset(keys):
            raise ValueError('Retained archive member missing')
        return [dict(common, **entry) for entry in entries]


def key(ref):
    return (ref['kind'], ref['path'], ref.get('member'))


def verify_file(expected, path=None, relocated=False):
    actual = file_evidence(path or expected['path'])
    if actual['sha256'] != expected['sha256'] or actual['length'] != expected['length']:
        raise ValueError('File contents changed')
    before = expected['fingerprint']; after = actual['fingerprint']
    if (before[:4] if relocated else before) != (after[:4] if relocated else after):
        raise ValueError('File identity or timestamps changed')
    if actual['attributes']['nlink'] != expected['attributes']['nlink']:
        raise ValueError('File link count changed')
    if not relocated and actual['parent_identity'] != expected['parent_identity']:
        raise ValueError('Parent directory changed')
    if actual['mount'] != expected['mount']:
        raise ValueError('File mount changed')
    return actual


def compare_files(left, right):
    with regular(left) as (a, _, _), regular(right) as (b, _, _):
        read_hash(a, compare=b)


def runtime_roots(config):
    roots = (list(config.get('quarantine_roots', [])) + list(config.get('runtime_paths', []))
             + list(config.get('cleanup_registries', [])))
    for registry in config.get('cleanup_registries', []):
        no_symlink_path(registry)
        if not Path(registry).exists():
            continue
        with regular(registry) as (stream, _, _):
            value = json.load(stream)
        if not isinstance(value, dict) or value.get('kind') != 'data-manager-cleanup-registry' or value.get('schema_version') != 1:
            raise ValueError('Not a data-manager cleanup registry')
        if any(not isinstance(value.get(k), list) or any(not isinstance(p, str) or not os.path.isabs(p) for p in value[k])
               for k in ('quarantine_roots', 'runtime_paths')):
            raise ValueError('Invalid cleanup registry paths')
        roots.extend(absolute(p) for p in value.get('quarantine_roots', []))
        roots.extend(absolute(p) for p in value.get('runtime_paths', []))
    return roots


def protected(path, config, extra=()):
    return (Path(path).name in PROTECTED or '.git' in Path(path).parts
            or any(within(path, r) for r in [*config.get('out_of_scope', []),
                   *(e['path'] for e in config.get('system_paths', [])), *runtime_roots(config), *extra]))


def find_duplicates(run, output, max_expanded=MAX_EXPANDED, max_members=MAX_MEMBERS):
    output = Path(absolute(str(output))); no_symlink_path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    mark_runtime(output, 'duplicate-detection')
    db = connect(run)
    try:
        config = meta(db, 'config')
        remote_io.configure(config)
        rows = [dict(r) for r in db.execute('SELECT * FROM nodes WHERE kind="file" AND excluded=0 ORDER BY path')]
        scan_status = meta(db, 'scan_status')
    finally:
        db.close()
    issues = []; files = []; archives = []; hardlinks = []
    artifacts = [str(Path(r['path']).parent) for r in rows if Path(r['path']).name == RUNTIME_MARKER
                 and is_runtime(Path(r['path']).parent)]
    lengths = {}
    candidates = []
    for row in rows:
        path = row['path']
        if protected(path, config, [str(Path(run).absolute()), str(output), *artifacts]):
            continue
        try:
            no_symlink_path(path)
            s = os.lstat(path)
            if not stat.S_ISREG(s.st_mode):
                raise ValueError('Not a regular file')
            candidates.append(path); lengths[s.st_size] = lengths.get(s.st_size, 0) + 1
        except (OSError, ValueError) as exc:
            issues.append({'path': path, 'reason': str(exc)})
    has_archives = any(archive_type(p) for p in candidates)
    for path in candidates:
        try:
            if has_archives or lengths[os.lstat(path).st_size] > 1 or os.lstat(path).st_nlink > 1:
                ref = file_evidence(path)
                files.append(ref)
                if ref['attributes']['nlink'] > 1:
                    hardlinks.append(ref)
            if archive_type(path):
                archives.extend(archive_evidence(path, max_expanded, max_members))
            elif str(path).lower().endswith(('.7z', '.rar')):
                issues.append({'path': path, 'reason': 'Unsupported archive format'})
        except (OSError, ValueError, EOFError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, lzma.LZMAError) as exc:
            issues.append({'path': path, 'reason': str(exc)})
    groups = {}; refs = files + archives
    for ref in refs:
        groups.setdefault((ref['length'], ref['sha256']), []).append(ref)
    matches = []; archive_comparisons = {}
    identities = {}
    for ref in files:
        if ref['mount']['fstype'] in RELIABLE_INODES:
            identities.setdefault(tuple(ref['fingerprint'][:2]), []).append(ref)
    shared = {identity for identity, paths in identities.items() if len(paths) > 1}
    hardlinks = [ref for ref in files if ref['attributes']['nlink'] > 1 or tuple(ref['fingerprint'][:2]) in shared]
    for group in groups.values():
        plain = [r for r in group if r['kind'] == 'file']
        for target in plain:
            if target['attributes']['nlink'] != 1 or tuple(target['fingerprint'][:2]) in shared:
                continue
            for keeper in group:
                if keeper['path'] == target['path']:
                    continue
                match = {'target': target, 'keeper': keeper, 'content_equal': False,
                         'attributes_restore': 'not_guaranteed', 'redundancy': 'requires_review'}
                if keeper['kind'] == 'file':
                    try:
                        compare_files(target['path'], keeper['path'])
                        verify_file(target); verify_file(keeper)
                        match['content_equal'] = True; matches.append(match)
                    except (OSError, ValueError) as exc:
                        issues.append({'path': target['path'], 'reason': str(exc)})
                else:
                    archive_comparisons.setdefault(keeper['path'], []).append(match)
    for path, pending in archive_comparisons.items():
        comparisons = {}
        for match in pending:
            comparisons.setdefault((match['keeper']['kind'], match['keeper']['member']), match['target']['path'])
        try:
            current = {key(r): r for r in archive_evidence(path, max_expanded, max_members, comparisons)}
            for match in pending:
                keeper = match['keeper']; target = match['target']
                if current.get(key(keeper)) != keeper:
                    raise ValueError('Archive changed since detection')
                # One archive comparison establishes equality to the first disk reference;
                # additional files with the same digest still require byte comparison.
                compare_files(target['path'], comparisons[(keeper['kind'], keeper['member'])])
                verify_file(target)
            for match in pending:
                match['content_equal'] = True; matches.append(match)
        except (OSError, ValueError, EOFError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, lzma.LZMAError) as exc:
            issues.append({'path': path, 'reason': str(exc)})
    result = {'schema_version': 1, 'created': now(), 'run': str(Path(run).absolute()), 'config': config,
              'scan_status': scan_status, 'status': 'complete' if not issues and scan_status == 'complete' else 'partial',
              'limits': {'max_expanded': max_expanded, 'max_members': max_members},
              'matches': matches, 'hardlinks': hardlinks, 'issues': issues}
    dump(output / 'duplicates.json', result)
    selection = {'schema_version': 1, 'writers_stopped': False, 'actions': []}
    dump(output / 'selection.example.json', selection)
    with (output / 'duplicates.csv').open('w', newline='') as stream:
        writer = csv.writer(stream); writer.writerow(['target', 'keeper', 'kind', 'member', 'length', 'sha256'])
        for match in matches:
            t, k = match['target'], match['keeper']
            writer.writerow([t['path'], k['path'], k['kind'], k['member'], t['length'], t['sha256']])
    (output / 'REPORT.md').write_text('# 重复内容检测\n\n' +
        f'状态：{result["status"]}；匹配关系：{len(matches)}；硬链接记录：{len(hardlinks)}；问题：{len(issues)}。\n\n' +
        '内容等价不代表业务冗余。逐项审核 duplicates.csv 和 duplicates.json，明确用途及保留依赖。\n' +
        '仅保证字节内容证据，压缩包不保证恢复权限、属主、ACL 或扩展属性。远端清理须通过对应后端能力检查；硬链接仅报告。\n')
    return {'output': str(output), 'status': result['status'], 'matches': len(matches), 'issues': len(issues)}
