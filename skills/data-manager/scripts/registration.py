"""Prepare reviewable metadata changes and apply them with backups and readback checks."""
from __future__ import annotations

import contextlib
import errno
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

from inventory import (FIELDS, absolute, connect, digest, dump, meta, mount_for, mounts,
                       no_symlink_path, now, within)

ASSET = Path(__file__).resolve().parents[1] / 'assets' / 'PROJECT.template.v1.md'


@contextlib.contextmanager
def parent_handle(target):
    """Anchor mutations to an opened directory, never to a symlinked ancestor."""
    p = Path(absolute(str(target)))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in p.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        yield fd, p.name
    finally:
        os.close(fd)


def read_at(fd, name):
    try:
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None, None
    try:
        s = os.fstat(f)
        if not stat.S_ISREG(s.st_mode):
            raise ValueError(f'Not a regular metadata file: {name}')
        if s.st_size > 4 * 1024 * 1024:
            raise ValueError('Metadata file exceeds 4 MiB; review manually')
        chunks = []
        while True:
            b = os.read(f, 65536)
            if not b:
                break
            chunks.append(b)
        end = os.fstat(f)
        fingerprint = (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if fingerprint != (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns):
            raise ValueError('Metadata changed while reading')
        return b''.join(chunks), fingerprint
    finally:
        os.close(f)


def read_metadata(path):
    with parent_handle(path) as (fd, name):
        return read_at(fd, name)


def scale_text(row, started, finished, sources):
    def gb(n): return f'{n / 1e9:.3f} GB'
    remote = '；远端数值为挂载层报告占用，不代表云端计费容量' if 'mount_reported' in sources else ''
    return (f'盘点时间 {started} 至 {finished}；总占用 {gb(row["allocated"])}，'
            f'排除环境/缓存 {gb(row["excluded_allocated"])}，业务占用 {gb(row["business_allocated"])}；'
            f'参考逻辑大小 {gb(row["logical"])}。目录内硬链接去重，父子目录及共享硬链接项目不可直接相加{remote}')


def new_registration(project, owner, scale):
    template = ASSET.read_text()
    comment = template[template.index('<!--'):]
    return (f'# 项目：{project.get("title", Path(project["path"]).name)}\n\n'
            f'- 负责人：{owner}\n- 最近清理：无\n'
            f'- 项目概况：{project.get("description", "待确认")}；目录：{project["path"]}\n'
            f'- 数据规模：{scale}\n- 清理情况：未开始（本次仅盘点登记）\n\n' + comment)


def update_scale(old, scale):
    """Only replace one unambiguous scale line; preserve all other original bytes."""
    text = old.decode('utf-8')
    for field in FIELDS:
        if len(re.findall(r'^- ' + re.escape(field) + r'：', text, flags=re.M)) != 1:
            raise ValueError(f'Missing or ambiguous field: {field}')
    match = re.search(r'^- 数据规模：.*(?:\n|$)', text, flags=re.M)
    tail = text[match.end():]
    if tail and tail.splitlines()[0].strip() and not tail.startswith('- '):
        raise ValueError('Multiline scale field needs manual merging')
    newline = '\r\n' if match[0].endswith('\r\n') else ('\n' if match[0].endswith('\n') else '')
    return (text[:match.start()] + '- 数据规模：' + scale + newline + text[match.end():]).encode('utf-8')


def git_context(root):
    if not any((p / '.git').exists() for p in [root, *root.parents]):
        return False, False
    try:
        tracked = subprocess.run(['git', '-C', str(root), 'ls-files', '--error-unmatch', '--', 'PROJECT.md'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except FileNotFoundError:
        raise ValueError('Git metadata exists but git is unavailable; check manually')
    return True, tracked


def plan(run, archives=()):
    run = Path(run).resolve(); db = connect(run)
    try:
        if meta(db, 'aggregation_status') != 'complete':
            raise ValueError('Run scan or report to finish aggregation first')
        c = meta(db, 'config'); started = meta(db, 'started'); finished = meta(db, 'finished') or now()
        identity = uuid.uuid4().hex
        directory = run / 'plans' / identity
        directory.mkdir(mode=0o700, parents=True)
        actions, pending, notes = [], [], []
        roots = [r['path'] for r in c['managed_roots']]
        source_rows = meta(db, 'mounts')

        def action(target, content, operation='write'):
            original, fingerprint = read_metadata(target)
            if original == content and operation == 'write':
                notes.append({'path': str(target), 'reason': 'already up to date'})
                return
            s = Path(target).parent.stat()
            a = {'target': str(target), 'operation': operation,
                 'before_sha256': digest(original) if original is not None else None,
                 'before_fingerprint': list(fingerprint) if fingerprint else None,
                 'original_mode': stat.S_IMODE(os.stat(target, follow_symlinks=False).st_mode) & 0o777 if original is not None else None,
                 'parent_identity': [s.st_dev, s.st_ino],
                 'fstype': mount_for(str(target), source_rows)['fstype']}
            if content is not None:
                draft = directory / (str(len(actions)) + '.draft')
                draft.write_bytes(content)
                a['draft'] = str(draft)
                a['after_sha256'] = digest(content)
            actions.append(a)

        for project in c['projects']:
            root = Path(project['path']); target = root / 'PROJECT.md'
            action_start = len(actions)
            row = db.execute('SELECT * FROM measures WHERE path=?', (str(root),)).fetchone()
            try:
                if row is None or row['errors'] or row['unknown']:
                    raise ValueError('Incomplete scan or unknown allocation; registration pending')
                scanned = db.execute('SELECT dev,ino FROM nodes WHERE path=? AND kind="directory"', (str(root),)).fetchone()
                no_symlink_path(root)
                current = root.stat()
                if not scanned or tuple(scanned) != (current.st_dev, current.st_ino):
                    raise ValueError('Project directory changed since scan')
                if row['business_allocated'] == 0 and db.execute('SELECT excluded FROM nodes WHERE path=?', (str(root),)).fetchone()[0]:
                    notes.append({'path': str(root), 'reason': 'verified system directory; no registration'})
                    continue
                old, _ = read_metadata(target)
                if row['business_allocated'] <= c['threshold_bytes'] and old is None:
                    continue
                prefix = str(root) + '/'
                sources = {r[0] for r in db.execute('SELECT DISTINCT allocation_source FROM nodes WHERE path=? OR substr(path,1,?)=?', (str(root), len(prefix), prefix))}
                scale = scale_text(row, started, finished, sources)
                if old is None:
                    content = new_registration(project, c.get('owner', '待确认'), scale).encode()
                else:
                    try:
                        content = update_scale(old, scale)
                    except (ValueError, UnicodeError) as exc:
                        draft = directory / (digest(str(target).encode())[:16] + '.review.md')
                        draft.write_text(new_registration(project, c.get('owner', '待确认'), scale))
                        pending.append({'path': str(target), 'reason': str(exc), 'suggested_draft': str(draft)})
                        continue
                action(target, content)
                in_git, tracked = git_context(root)
                if tracked:
                    notes.append({'path': str(target), 'reason': 'already tracked by Git; index unchanged'})
                if in_git:
                    ignore = root / '.gitignore'; before, _ = read_metadata(ignore)
                    text = before.decode() if before is not None else ''
                    ignored = subprocess.run(['git', '-C', str(root), 'check-ignore', '--no-index', '-q', '--', 'PROJECT.md'],
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
                    if ignored not in (0, 1):
                        raise ValueError('Git could not evaluate effective ignore rules')
                    if ignored != 0 or ('/PROJECT.md' not in text.splitlines() and 'PROJECT.md' not in text.splitlines()):
                        content = (text + ('' if not text or text.endswith('\n') else '\n') + '/PROJECT.md\n').encode()
                        action(ignore, content)
            except (OSError, ValueError, UnicodeError) as exc:
                del actions[action_start:]
                pending.append({'path': str(root), 'reason': str(exc)})
        project_paths = {p['path'] for p in c['projects']}
        for value in archives:
            target = Path(absolute(value))
            if target.name != 'PROJECT.md' or str(target.parent) in project_paths or not any(within(str(target), r) for r in roots):
                raise ValueError(f'Not a redundant registration within managed scope: {target}')
            original, _ = read_metadata(target)
            if original is None:
                raise ValueError(f'Archive source missing: {target}')
            update_scale(original, 'validation only')
            action(target, None, 'archive_registration')
        result = {'schema_version': 1, 'created': now(), 'run': str(run), 'plan_id': identity,
                  'managed_roots': roots, 'project_roots': sorted(project_paths),
                  'actions': actions, 'pending': pending, 'notes': notes}
        dump(directory / 'manifest.json', result)
        return directory / 'manifest.json'
    finally:
        db.close()


def unchanged(fd, name, action):
    content, fingerprint = read_at(fd, name)
    if (digest(content) if content is not None else None) != action['before_sha256']:
        raise ValueError('File contents changed since planning')
    if (list(fingerprint) if fingerprint else None) != action['before_fingerprint']:
        raise ValueError('File identity or timestamps changed since planning')
    return content


def exclusive_create(fd, name, content, mode=None):
    f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644 if mode is None else mode, dir_fd=fd)
    written = b''
    identity = os.fstat(f)
    try:
        while len(written) < len(content):
            count = os.write(f, content[len(written):])
            if not count:
                raise OSError('Short metadata write')
            written += content[len(written):len(written) + count]
        os.fsync(f)
        if mode is not None and stat.S_IMODE(os.fstat(f).st_mode) & 0o777 != mode:
            try:
                os.fchmod(f, mode)
            except OSError as exc:
                if exc.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                    raise
    except BaseException:
        # Remove only the exact partial file created by this call, not a concurrent replacement.
        current, fingerprint = read_at(fd, name)
        if current == written and fingerprint and tuple(fingerprint[:2]) == (identity.st_dev, identity.st_ino):
            os.unlink(name, dir_fd=fd)
        raise
    finally:
        os.close(f)


def atomic_write(fd, name, content, action):
    temporary = '.data-manager-' + uuid.uuid4().hex
    try:
        exclusive_create(fd, temporary, content, action.get('original_mode'))
        unchanged(fd, name, action)
        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def replace_with_recovery(fd, name, content, action, original):
    """TOS fallback only. Return a clear recovery failure instead of retrying indefinitely."""
    unchanged(fd, name, action)
    if original is not None:
        os.unlink(name, dir_fd=fd)
    try:
        exclusive_create(fd, name, content, action.get('original_mode'))
        if read_at(fd, name)[0] != content:
            raise ValueError('TOS readback mismatch')
    except Exception as exc:
        present, _ = read_at(fd, name)
        if present == content:
            os.unlink(name, dir_fd=fd); present = None
        if present is not None:
            raise RuntimeError('Recovery required: unexpected target remains; use saved backup') from exc
        if original is not None:
            try:
                exclusive_create(fd, name, original, action.get('original_mode'))
                if read_at(fd, name)[0] != original:
                    raise ValueError('Restored content differs')
            except Exception as restore:
                raise RuntimeError('Recovery required: original restoration failed; use saved backup') from restore
        raise RuntimeError('Metadata update failed; original state restored') from exc


def apply(manifest_path, allow_archive=False):
    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('schema_version') != 1:
        raise ValueError('Unsupported manifest')
    db = connect(manifest['run'])
    try:
        config = meta(db, 'config')
    finally:
        db.close()
    roots = [r['path'] for r in config['managed_roots']]
    projects = {p['path'] for p in config['projects']}
    actions = manifest['actions']
    seen = set()
    current_mounts = mounts()
    previous_file = manifest_path.parent / 'results.json'
    previous = json.loads(previous_file.read_text()) if previous_file.exists() else {'results': []}
    verified = {r['target']: r for r in previous['results'] if r['status'] == 'verified'}
    todo = []
    # Preflight the entire batch before modifying any registration.
    for a in actions:
        target = Path(absolute(a['target']))
        if str(target) in seen:
            raise ValueError('Duplicate target in manifest')
        seen.add(str(target))
        if not any(within(str(target), r) for r in roots) or any(within(str(target), r) for r in config['out_of_scope']):
            raise ValueError('Manifest target outside managed scope')
        if a['operation'] == 'write':
            mode = a.get('original_mode')
            if mode is not None and (not isinstance(mode, int) or not 0 <= mode <= 0o777):
                raise ValueError('Invalid metadata mode in manifest')
            if target.name not in {'PROJECT.md', '.gitignore'} or str(target.parent) not in projects:
                raise ValueError('Only project metadata can be written')
            draft = Path(a['draft'])
            no_symlink_path(draft)
            if draft.parent != manifest_path.parent or digest(draft.read_bytes()) != a['after_sha256']:
                raise ValueError('Draft changed or outside plan directory')
        elif a['operation'] == 'archive_registration':
            if not allow_archive or target.name != 'PROJECT.md' or str(target.parent) in projects:
                raise ValueError('Registration archival requires --allow-registration-archive and a non-project root')
        else:
            raise ValueError('Unknown operation')
        with parent_handle(target) as (fd, name):
            s = os.fstat(fd)
            if [s.st_dev, s.st_ino] != a['parent_identity']:
                raise ValueError('Parent directory changed since planning')
            old, _ = read_at(fd, name)
            if str(target) in verified:
                ok = old is None if a['operation'] == 'archive_registration' else old is not None and digest(old) == a['after_sha256']
                if not ok:
                    raise ValueError('Previously verified target has changed; prepare a new plan')
                continue
            unchanged(fd, name, a)
        todo.append(a)
    results = [verified[a['target']] for a in actions if a['target'] in verified]
    execution_id = uuid.uuid4().hex
    backup_dir = manifest_path.parent / 'backups' / execution_id
    backup_dir.mkdir(mode=0o700, parents=True)
    for a in todo:
        target = Path(a['target']); result = {'target': str(target), 'operation': a['operation'], 'time': now()}
        try:
            with parent_handle(target) as (fd, name):
                s = os.fstat(fd)
                if [s.st_dev, s.st_ino] != a['parent_identity']:
                    raise ValueError('Parent changed after preflight')
                old = unchanged(fd, name, a)
                if old is not None:
                    backup = backup_dir / (digest(str(target).encode()) + '.original')
                    backup_fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(backup_fd, 'wb') as f:
                        f.write(old); f.flush(); os.fsync(f.fileno())
                    if backup.read_bytes() != old:
                        raise ValueError('Backup readback mismatch')
                    result['backup'] = str(backup); result['before_sha256'] = digest(old)
                if a['operation'] == 'archive_registration':
                    unchanged(fd, name, a)
                    os.unlink(name, dir_fd=fd)
                    if read_at(fd, name)[0] is not None:
                        raise ValueError('Archive verification failed')
                else:
                    content = Path(a['draft']).read_bytes()
                    if digest(content) != a['after_sha256']:
                        raise ValueError('Draft changed after preflight')
                    try:
                        atomic_write(fd, name, content, a)
                    except OSError as exc:
                        fs = mount_for(str(target), current_mounts)['fstype']
                        if fs != 'fuse.tosutil' or exc.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                            raise
                        replace_with_recovery(fd, name, content, a, old)
                        result['method'] = 'TOS exclusive recreation'
                    if read_at(fd, name)[0] != content:
                        raise ValueError('Metadata readback mismatch')
                    result['after_sha256'] = digest(content)
                result['status'] = 'verified'
        except Exception as exc:
            result['status'] = 'failed'; result['error'] = str(exc)
        results.append(result)
        dump(previous_file, {'plan_id': manifest['plan_id'], 'results': results, 'pending': manifest['pending']})
        if result['status'] != 'verified':
            break  # Preserve evidence and stop rather than widen a failing mutation.
    if not todo:
        dump(previous_file, {'plan_id': manifest['plan_id'], 'results': results, 'pending': manifest['pending']})
    return {'plan_id': manifest['plan_id'], 'results': results, 'pending': manifest['pending']}
