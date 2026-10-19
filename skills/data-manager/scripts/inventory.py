"""Read-only discovery and resumable metadata inventory. Python standard library only."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import sqlite3
import stat
import threading
import time
import tempfile

VIRTUAL = {'proc', 'sysfs', 'devtmpfs', 'tmpfs', 'cgroup', 'cgroup2', 'squashfs',
           'overlay', 'autofs', 'securityfs', 'debugfs', 'tracefs', 'devpts', 'nsfs',
           'hugetlbfs', 'mqueue', 'rpc_pipefs', 'binfmt_misc', 'fusectl', 'configfs', 'bpf', 'efivarfs', 'pstore'}
RELIABLE_INODES = {'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'zfs', 'nfs', 'nfs4', 'tmpfs'}
REMOTE = {'nfs', 'nfs4', 'cifs', 'smb3', 'fuse.tosutil', 'fuse.s3fs', 'fuse.rclone'}
FIELDS = ('负责人', '最近清理', '项目概况', '数据规模', '清理情况')


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def within(path, root):
    return path == root or path.startswith(root.rstrip('/') + '/')


def absolute(value):
    if not isinstance(value, str) or not os.path.isabs(value):
        raise ValueError(f'Expected an absolute path: {value!r}')
    return os.path.normpath(value)


def no_symlink_path(path):
    """Reject aliases and replaced ancestors, including dangling symbolic links."""
    current = Path('/')
    for part in Path(absolute(str(path))).parts[1:]:
        current /= part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ValueError(f'Symbolic link in path: {current}')
        except FileNotFoundError:
            break


def read_config(path=None):
    raw = json.loads(Path(path).read_text()) if path else {
        'schema_version': 1, 'uid': os.getuid(), 'aliases': [Path.home().name],
        'managed_roots': [{'path': str(Path.home()), 'evidence': 'current account home'}],
        'containers': [str(Path.home())], 'projects': []}
    if raw.get('schema_version', 1) != 1:
        raise ValueError('Unsupported profile version')
    c = dict(raw)
    if path:
        c.setdefault('cleanup_registry', absolute(str(Path(path).absolute()) + '.cleanup.json'))
    c['cleanup_registries'] = list(dict.fromkeys([*c.get('cleanup_registries', []),
                                                *([c['cleanup_registry']] if c.get('cleanup_registry') else [])]))
    for key in ('quarantine_roots', 'runtime_paths', 'cleanup_registries'):
        c[key] = [absolute(p) for p in c.get(key, [])]
    if c.get('cleanup_registry'):
        c['cleanup_registry'] = absolute(c['cleanup_registry'])
    c.setdefault('uid', os.getuid())
    c.setdefault('aliases', [])
    c.setdefault('threshold_bytes', 100_000_000_000)
    c.setdefault('local_workers', 4)
    c.setdefault('remote_workers', 8)
    for k in ('local_workers', 'remote_workers'):
        if not isinstance(c[k], int) or not 1 <= c[k] <= 64:
            raise ValueError(f'{k} must be between 1 and 64')
    if not isinstance(c['threshold_bytes'], int) or c['threshold_bytes'] < 0:
        raise ValueError('threshold_bytes must be a nonnegative integer')
    c.setdefault('managed_roots', [])
    for r in c['managed_roots']:
        r['path'] = absolute(r['path'])
        if not r.get('evidence'):
            raise ValueError('Every managed root needs ownership evidence')
        no_symlink_path(r['path'])
    roots = [r['path'] for r in c['managed_roots']]
    for i, r in enumerate(roots):
        if any(within(r, s) or within(s, r) for s in roots[:i]):
            raise ValueError('Managed roots must not overlap; use include_mounts inside one root')
    for key in ('containers', 'out_of_scope', 'include_mounts'):
        c[key] = [absolute(p) for p in c.get(key, [])]
    for key in ('system_paths', 'projects'):
        c.setdefault(key, [])
        for entry in c[key]:
            entry['path'] = absolute(entry['path'])
            if not any(within(entry['path'], r) for r in roots):
                raise ValueError(f'{key} entry outside managed scope: {entry["path"]}')
            if key == 'system_paths' and not entry.get('evidence'):
                raise ValueError('System exclusions require evidence')
            if key == 'projects' and not entry.get('evidence'):
                raise ValueError('Project boundaries require evidence')
    projects = [r['path'] for r in c['projects']]
    for i, r in enumerate(projects):
        if any(within(r, s) or within(s, r) for s in projects[:i]):
            raise ValueError('Project roots must not overlap')
        if r in c['containers'] or any(within(r, p) for p in c['out_of_scope']):
            raise ValueError(f'Project conflicts with a container or exclusion: {r}')
    return c


def mounts():
    def unescape(s):
        return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), s)
    rows = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        a, b = left.split(), right.split()
        rows.append({'id': a[0], 'device': a[2], 'root': unescape(a[3]),
                     'target': unescape(a[4]), 'fstype': b[0], 'source': unescape(b[1])})
    # Later overmounts win for the same target.
    return sorted({r['target']: r for r in rows}.values(), key=lambda r: len(r['target']), reverse=True)


def mount_for(path, rows):
    return next((r for r in rows if within(path, r['target'])),
                {'target': '/', 'root': '/', 'fstype': 'unknown', 'device': '?', 'source': '?'})


def source_key(path, rows):
    m = mount_for(path, rows)
    suffix = os.path.relpath(path, m['target'])
    physical = os.path.normpath(os.path.join(m['root'], suffix))
    return (m['device'], m['fstype'], m['source'], physical)


def dump(path, value):
    p = Path(path)
    no_symlink_path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + p.name + '-', dir=p.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.write('\n')
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


RUNTIME_MARKER = '.data-manager-runtime.json'


def mark_runtime(directory, kind):
    dump(Path(directory) / RUNTIME_MARKER, {'schema_version': 1, 'kind': 'data-manager-runtime',
                                          'directory': absolute(str(Path(directory).absolute())), 'purpose': kind})


def is_runtime(directory):
    marker = Path(directory) / RUNTIME_MARKER
    no_symlink_path(marker)
    if not marker.is_file():
        return False
    if marker.stat().st_size > 4096:
        return False
    try:
        value = json.loads(marker.read_text())
        return (isinstance(value, dict) and value.get('schema_version') == 1 and value.get('kind') == 'data-manager-runtime'
                and value.get('directory') == str(Path(directory).absolute()))
    except (ValueError, UnicodeError):
        return False


def connect(run):
    p = Path(run) / 'inventory.sqlite'
    if not p.is_file():
        raise ValueError(f'No inventory database in {run}')
    no_symlink_path(p)
    db = sqlite3.connect(p)
    db.row_factory = sqlite3.Row
    return db


def meta(db, key, value=None):
    if value is not None:
        db.execute('INSERT OR REPLACE INTO meta VALUES (?, ?)', (key, json.dumps(value, ensure_ascii=False)))
        return value
    row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return json.loads(row[0]) if row else None


def create_db(run, config):
    out = Path(run)
    no_symlink_path(out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    p = out / 'inventory.sqlite'
    if p.exists():
        raise ValueError('Run already exists. Use --resume or choose a fresh output directory.')
    mark_runtime(out, 'inventory')
    db = sqlite3.connect(p)
    db.row_factory = sqlite3.Row
    db.executescript('''
    PRAGMA journal_mode=WAL;
    CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE tasks(path TEXT PRIMARY KEY, state TEXT NOT NULL, excluded INTEGER NOT NULL);
    CREATE TABLE nodes(path TEXT PRIMARY KEY, parent TEXT, kind TEXT, dev INTEGER, ino INTEGER,
      nlink INTEGER, allocated INTEGER, logical INTEGER, mtime_ns INTEGER, ctime_ns INTEGER,
      excluded INTEGER, allocation_source TEXT, identity TEXT);
    CREATE TABLE issues(path TEXT, kind TEXT, message TEXT);
    CREATE TABLE measures(path TEXT PRIMARY KEY, logical INTEGER, files INTEGER,
      allocated INTEGER, excluded_allocated INTEGER, business_allocated INTEGER,
      unknown INTEGER, errors INTEGER);
    ''')
    meta(db, 'config', config)
    meta(db, 'started', now())
    meta(db, 'scan_status', 'new')
    meta(db, 'aggregation_status', 'pending')
    db.commit()
    return db


def node(path, s, excluded, mount_rows):
    kind = 'directory' if stat.S_ISDIR(s.st_mode) else ('symlink' if stat.S_ISLNK(s.st_mode) else 'file')
    fs = mount_for(path, mount_rows)['fstype']
    blocks = getattr(s, 'st_blocks', None)
    allocated = blocks * 512 if blocks is not None and blocks >= 0 else None
    # Bind aliases may expose an inode twice even when its link count is one.
    identity = f'inode:{s.st_dev}:{s.st_ino}' if fs in RELIABLE_INODES and s.st_ino else 'path:' + path
    return (path, str(Path(path).parent), kind, s.st_dev, s.st_ino, s.st_nlink,
            allocated, 0 if kind == 'directory' else s.st_size, s.st_mtime_ns,
            s.st_ctime_ns, int(excluded), 'unknown' if allocated is None else ('mount_reported' if fs in REMOTE or fs.startswith('fuse.') else 'filesystem_reported'), identity)


def inspect_directory(path, inherited, c, mount_rows, output):
    records, children, issues = [], [], []
    excluded = inherited or any(within(path, e['path']) for e in c['system_paths'])
    try:
        no_symlink_path(path)
        before = os.lstat(path)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError('Directory replaced by another file type')
        with os.scandir(path) as it:
            entries = list(it)
        # A directory name alone is not evidence of an environment.
        markers = {e.name: e for e in entries if e.name in {'conda-meta', 'pyvenv.cfg'}}
        conda = markers.get('conda-meta')
        venv = markers.get('pyvenv.cfg')
        marked = bool((conda and conda.is_dir(follow_symlinks=False)) or
                      (venv and venv.is_file(follow_symlinks=False)))
        excluded = bool(excluded or marked)
        if marked:
            issues.append((path, 'environment_marker', 'Verified conda-meta directory or pyvenv.cfg file'))
        if Path(path).name.lower() in {'env', 'envs', 'cache', 'software', '.cache'} and not excluded:
            issues.append((path, 'classification_pending', 'Name suggests an environment/cache; retained as business content'))
        records.append(node(path, before, excluded, mount_rows))
        for e in entries:
            p = e.path
            if within(p, output) or any(within(p, x) for x in c['out_of_scope']):
                issues.append((p, 'excluded_scope', 'Configured exclusion or inventory output'))
                continue
            try:
                s = e.stat(follow_symlinks=False)
                is_dir = stat.S_ISDIR(s.st_mode)
                m = mount_for(p, mount_rows)
                if is_dir and p == m['target'] and m['target'] != mount_for(path, mount_rows)['target']:
                    if m['fstype'] in VIRTUAL:
                        issues.append((p, 'excluded_virtual', m['fstype']))
                        continue
                    if p not in c['include_mounts']:
                        issues.append((p, 'unscanned_mount', 'Nested mount needs an explicit include_mounts entry'))
                        continue
                    if source_key(p, mount_rows) == source_key(path, mount_rows) or any(
                            source_key(p, mount_rows) == source_key(str(a), mount_rows) for a in Path(path).parents):
                        issues.append((p, 'mount_cycle', 'Mount aliases an ancestor; not followed'))
                        continue
                ex = excluded or any(within(p, x['path']) for x in c['system_paths'])
                records.append(node(p, s, ex, mount_rows))
                if is_dir:
                    children.append((p, int(ex)))
            except (OSError, ValueError) as exc:
                issues.append((p, 'read_error', str(exc)))
        after = os.lstat(path)
        if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
            issues.append((path, 'changed_during_scan', 'Directory changed while enumerating'))
    except (OSError, ValueError) as exc:
        issues.append((path, 'read_error', str(exc)))
    return records, children, issues


ERROR_KINDS = {'read_error', 'unscanned_mount', 'mount_cycle', 'changed_during_scan'}


def scan(config, run, resume=False):
    output = absolute(str(run))
    db = connect(run) if resume else create_db(run, config)
    if meta(db, 'config') != config:
        db.close()
        raise ValueError('Resume requires the identical profile; use a fresh run for changed scope')
    mount_rows = mounts()
    if resume and meta(db, 'mounts') != mount_rows:
        db.close()
        raise ValueError('Mount table changed since checkpoint; start a fresh run')
    meta(db, 'mounts', mount_rows)
    if not resume:
        keys, aliases = {}, []
        for r in config['managed_roots']:
            p = r['path']
            if within(p, output) or any(within(p, x) for x in config['out_of_scope']):
                raise ValueError(f'Managed root excluded by output or profile: {p}')
            key = source_key(p, mount_rows)
            if key in keys:
                aliases.append({'path': p, 'canonical': keys[key]})
            else:
                keys[key] = p
                db.execute('INSERT INTO tasks VALUES (?, "pending", 0)', (p,))
        meta(db, 'aliases', aliases)
    else:
        # Interrupted directory reads never commit partial records. Retry error subtrees.
        failed = [(r[0], r[1]) for r in db.execute('SELECT path,excluded FROM tasks WHERE state="error" ORDER BY length(path)')]
        retried = []
        for p, excluded in failed:
            if any(within(p, ancestor) for ancestor in retried):
                continue
            prefix = p.rstrip('/') + '/'
            for table in ('nodes', 'tasks', 'issues'):
                db.execute(f'DELETE FROM {table} WHERE path=? OR substr(path,1,?)=?', (p, len(prefix), prefix))
            db.execute('INSERT OR REPLACE INTO tasks VALUES (?, "pending", ?)', (p, excluded))
            retried.append(p)
        db.execute('UPDATE tasks SET state="pending" WHERE state="running"')
    meta(db, 'scan_status', 'running')
    meta(db, 'aggregation_status', 'pending')
    db.commit()
    incoming, finished = queue.Queue(), queue.Queue()
    max_workers = max(config['local_workers'], config['remote_workers'])
    stopped = threading.Event()

    def worker():
        while not stopped.is_set():
            item = incoming.get()
            if item is None:
                return
            p, ex = item
            try:
                result = inspect_directory(p, ex, config, mount_rows, output)
            except Exception as exc:
                result = ([], [], [(p, 'read_error', f'{type(exc).__name__}: {exc}')])
            finished.put((p, result))

    for _ in range(max_workers):
        threading.Thread(target=worker, daemon=True).start()
    active, per_mount, completed = {}, {}, 0
    last_progress = time.monotonic()
    try:
        while True:
            # Bounded in-flight reads; each directory checkpoint is committed by the coordinator.
            pending = db.execute('SELECT path,excluded FROM tasks WHERE state="pending" ORDER BY path LIMIT 1000').fetchall()
            for row in pending:
                if len(active) >= max_workers:
                    break
                p = row['path']; m = mount_for(p, mount_rows)
                key = m['target']; remote = m['fstype'] in REMOTE or m['fstype'].startswith('fuse.')
                cap = config['remote_workers'] if remote else config['local_workers']
                if per_mount.get(key, 0) >= cap:
                    continue
                active[p] = key; per_mount[key] = per_mount.get(key, 0) + 1
                db.execute('UPDATE tasks SET state="running" WHERE path=?', (p,))
                incoming.put((p, row['excluded']))
            db.commit()
            if not active:
                break
            try:
                p, (records, children, issues) = finished.get(timeout=1)
            except queue.Empty:
                continue
            key = active.pop(p); per_mount[key] -= 1
            db.executemany('INSERT OR REPLACE INTO nodes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', records)
            db.executemany('INSERT OR IGNORE INTO tasks VALUES (?, "pending", ?)', children)
            db.executemany('INSERT INTO issues VALUES (?,?,?)', issues)
            error = any(r[1] in ERROR_KINDS for r in issues)
            db.execute('UPDATE tasks SET state=? WHERE path=?', ('error' if error else 'done', p))
            db.commit(); completed += 1
            if time.monotonic() - last_progress >= 5:
                print(json.dumps({'directories_this_invocation': completed, 'active': len(active), 'current': p}), flush=True)
                last_progress = time.monotonic()
        bad = db.execute('SELECT count(*) FROM tasks WHERE state!="done"').fetchone()[0]
        meta(db, 'scan_status', 'partial' if bad else 'complete')
        meta(db, 'finished', now()); db.commit()
    except KeyboardInterrupt:
        meta(db, 'scan_status', 'interrupted')
        db.execute('UPDATE tasks SET state="pending" WHERE state="running"')
        db.commit()
        raise
    finally:
        stopped.set()
        for _ in range(max_workers):
            incoming.put(None)
        db.close()
    aggregate(run)


def aggregate(run):
    db = connect(run)
    meta(db, 'aggregation_status', 'running'); db.commit()
    db.executescript('''DROP TABLE IF EXISTS contributions;
    CREATE TABLE contributions(scope TEXT, identity TEXT, allocated INTEGER, business INTEGER,
      unknown INTEGER, PRIMARY KEY(scope,identity)) WITHOUT ROWID;
    DELETE FROM measures;''')
    directory_rows = db.execute('SELECT path,parent FROM nodes WHERE kind="directory"').fetchall()
    parents = {r['path']: r['parent'] for r in directory_rows}
    totals = {p: [0, 0, 0] for p in parents}  # logical bytes, file paths, errors

    def scopes(p):
        if p not in parents:
            p = str(Path(p).parent)
        while p in parents:
            yield p
            p = parents[p]

    sql = '''INSERT INTO contributions VALUES (?,?,?,?,?) ON CONFLICT(scope,identity)
             DO UPDATE SET allocated=max(coalesce(allocated,0),coalesce(excluded.allocated,0)),
             business=max(business,excluded.business), unknown=max(unknown,excluded.unknown)'''
    try:
        for r in db.execute('SELECT * FROM nodes ORDER BY path'):
            ancestors = list(scopes(r['path']))
            for p in ancestors:
                totals[p][0] += r['logical']
                totals[p][1] += r['kind'] != 'directory'
            contribution = (r['identity'], r['allocated'], 1 - r['excluded'], int(r['allocated'] is None))
            db.executemany(sql, [(p, *contribution) for p in ancestors + ['@global']])
        for r in db.execute('SELECT path,kind FROM issues'):
            if r['kind'] in ERROR_KINDS:
                for p in scopes(r['path']):
                    totals[p][2] += 1
        for r in db.execute('SELECT path FROM tasks WHERE state!="done"'):
            for p in scopes(r[0]):
                totals[p][2] += 1
        for r in db.execute('''SELECT scope, sum(coalesce(allocated,0)) AS a,
            sum(CASE WHEN business=0 THEN coalesce(allocated,0) ELSE 0 END) AS e,
            sum(CASE WHEN business=1 THEN coalesce(allocated,0) ELSE 0 END) AS b,
            sum(unknown) AS u FROM contributions GROUP BY scope'''):
            p = r['scope']; t = totals.get(p, [0, 0, 0])
            if p == '@global':
                t = [db.execute('SELECT coalesce(sum(logical),0) FROM nodes').fetchone()[0],
                     db.execute('SELECT count(*) FROM nodes WHERE kind!="directory"').fetchone()[0],
                     db.execute('SELECT count(*) FROM tasks WHERE state!="done"').fetchone()[0]]
            db.execute('INSERT INTO measures VALUES (?,?,?,?,?,?,?,?)',
                       (p, t[0], t[1], r['a'], r['e'], r['b'], r['u'], t[2]))
        meta(db, 'aggregation_status', 'complete'); db.commit()
    except BaseException:
        db.rollback(); meta(db, 'aggregation_status', 'interrupted'); db.commit()
        raise
    finally:
        db.close()


def discover(config, output, full=False, max_depth=2):
    """Discovery is separate from ownership confirmation and inventory completion."""
    out = Path(output); no_symlink_path(out); out.mkdir(parents=True, exist_ok=True)
    mark_runtime(out, 'discovery')
    mount_rows = mounts()
    dump(out / 'mounts.json', mount_rows)
    candidates, errors, skipped, coverage = [], [], [], []
    targets, seen = [], set()
    for m in sorted(mount_rows, key=lambda r: len(r['target'])):
        if m['fstype'] in VIRTUAL:
            continue
        k = (m['device'], m['fstype'], m['source'], m['root'])
        if k in seen:
            skipped.append({'path': m['target'], 'reason': 'mount alias'})
            continue
        seen.add(k); targets.append(m['target'])
    boundaries = {m['target'] for m in mount_rows if m['target'] != '/'}
    known = [r['path'] for r in config['managed_roots']]
    complete = True
    try:
        for root in targets:
            stack = [(root, 0)]; count = 0; limited = False
            while stack:
                p, depth = stack.pop()
                if any(within(p, x) for x in known + config['out_of_scope']) or within(p, str(out)):
                    skipped.append({'path': p, 'reason': 'known scope, explicit exclusion, or output'})
                    continue
                try:
                    with os.scandir(p) as entries:
                        for e in entries:
                            if not e.is_dir(follow_symlinks=False) or e.path in boundaries:
                                continue
                            if any(within(e.path, x) for x in known + config['out_of_scope']) or within(e.path, str(out)):
                                skipped.append({'path': e.path, 'reason': 'known scope, explicit exclusion, or output'})
                                continue
                            s = e.stat(follow_symlinks=False)
                            fs = mount_for(e.path, mount_rows)['fstype']
                            uid_trusted = fs in RELIABLE_INODES
                            reasons = []
                            if uid_trusted and s.st_uid == config['uid']:
                                reasons.append('uid_candidate')
                            if e.name in config['aliases']:
                                reasons.append('name_candidate')
                            if reasons:
                                candidates.append({'path': e.path, 'uid': s.st_uid, 'evidence': reasons,
                                                   'ownership': 'unconfirmed'})
                            if full or depth + 1 < max_depth:
                                stack.append((e.path, depth + 1))
                            else:
                                limited = True
                    count += 1
                except OSError as exc:
                    errors.append({'path': p, 'error': str(exc)})
                if count % 1000 == 0:
                    dump(out / 'discovery-progress.json', {'root': root, 'directories': count, 'pending': len(stack), 'time': now()})
            coverage.append({'root': root, 'directories': count, 'depth_limited': limited})
            complete = complete and not limited
    except KeyboardInterrupt:
        complete = False
        skipped.append({'path': root, 'reason': 'interrupted; discovery must be rerun'})
    result = {'time': now(), 'mode': 'full' if full else 'mount_check', 'ownership_complete': False,
              'coverage_complete': complete and not errors, 'candidates': candidates,
              'coverage': coverage, 'errors': errors, 'skipped': skipped}
    dump(out / 'discovery.json', result)
    return result
