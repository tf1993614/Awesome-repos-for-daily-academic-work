"""Reviewed local quarantine, recovery and purge with durable per-file evidence."""
from __future__ import annotations

import contextlib
import csv
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

import content
import inventory as inv
import registration as reg

LOCAL = {'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'zfs', 'tmpfs'}


def load(path):
    with content.regular(path) as (stream, s, _):
        if s.st_size > 128 * 1024 * 1024:
            raise ValueError('Control file too large')
        value = json.load(stream)
        if not isinstance(value, dict):
            raise ValueError('Control JSON must be an object')
        return value


def durable(path, value):
    """Persist both the replacement and directory entry before business mutations."""
    path = Path(path); inv.no_symlink_path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def signature(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def private_directory(path, create=False):
    path = Path(inv.absolute(str(path))); inv.no_symlink_path(path)
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
        sync_directories(path)
    s = path.stat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) & 0o077:
        raise ValueError(f'Private account-owned directory required: {path}')
    return path


def sync_directories(path):
    for directory in [Path(path), *Path(path).parents]:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@contextlib.contextmanager
def locks(paths):
    # Directory locks create no project files; all cooperating operations use them.
    handles = []
    try:
        for path in sorted(set(map(str, paths))):
            inv.no_symlink_path(path)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            handles.append(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        for fd in reversed(handles):
            os.close(fd)


def operation_locks(plan, directory):
    return locks([directory, Path(plan['registry']).parent, *plan['projects'],
                  *(a['quarantine_root'] for a in plan['actions'])])


def local(path, rows):
    m = inv.mount_for(str(path), rows)
    if m['fstype'] not in LOCAL:
        raise ValueError(f'Unsupported local mutation filesystem: {m["fstype"]}: {path}')
    return m


def rename_noreplace(source, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        raise ValueError('Atomic no-replace rename unavailable')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    with reg.parent_handle(source) as (src, name), reg.parent_handle(destination) as (dst, dest):
        if rename(src, os.fsencode(name), dst, os.fsencode(dest), 1) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        os.fsync(src); os.fsync(dst)


def check_scope(path, config):
    path = inv.absolute(path)
    if content.protected(path, config) or not any(inv.within(path, r['path']) for r in config['managed_roots']):
        raise ValueError(f'Protected or unmanaged target: {path}')
    project = next((p['path'] for p in config['projects'] if inv.within(path, p['path'])), None)
    if project is None:
        raise ValueError('Confirm the project boundary before cleanup')
    if path == project:
        raise ValueError('Cannot mutate a project root')
    return project


def existing_parent_identity(path):
    with reg.parent_handle(path) as (fd, _):
        s = os.fstat(fd)
        return [s.st_dev, s.st_ino]


def validate_action(action, config, rows):
    target = action['target']; keeper = action['keeper']
    project = check_scope(target['path'], config)
    if project != action['project'] or target['kind'] != 'file' or target['attributes']['nlink'] != 1:
        raise ValueError('Only independent project regular files may be handled')
    if not action.get('reason') or action.get('role') not in {'redundant_data', 'working_copy', 'backup'}:
        raise ValueError('Each action requires a reason and reviewed role')
    if not action.get('attributes_reviewed'):
        raise ValueError('Attribute restoration limitations must be reviewed')
    local(target['path'], rows); local(keeper['path'], rows)
    if not any(inv.within(keeper['path'], r['path']) for r in config['managed_roots']) or content.protected(keeper['path'], config):
        raise ValueError('Keeper must be an in-scope business file')
    if keeper['path'] == target['path']:
        raise ValueError('A file cannot retain itself')
    if keeper['fingerprint'][:2] == target['fingerprint'][:2]:
        raise ValueError('Retained and handled paths reference the same file object')
    if keeper['kind'] not in {'file', 'member', 'payload'} or (keeper['kind'] != 'file' and not content.archive_type(keeper['path'])):
        raise ValueError('Invalid retained content reference')
    if (target['length'], target['sha256']) != (keeper['length'], keeper['sha256']):
        raise ValueError('Retained content does not match target')
    root = private_directory(action['quarantine_root'])
    if any(inv.within(str(root), p['path']) or inv.within(p['path'], str(root)) for p in config['projects']):
        raise ValueError('Quarantine root must be outside all projects')
    local(root, rows)
    if os.stat(root).st_dev != target['fingerprint'][0] or inv.mount_for(str(root), rows) != target['mount']:
        raise ValueError('Quarantine must use the same mount and filesystem')
    if inv.within(keeper['path'], str(root)):
        raise ValueError('Keeper cannot be in quarantine')
    return root


def validate_dependencies(actions, config, rows):
    targets = set()
    for action in actions:
        validate_action(action, config, rows)
        path = action['target']['path']
        if path in targets:
            raise ValueError('Duplicate cleanup target')
        targets.add(path)
    if any(a['keeper']['path'] in targets for a in actions):
        raise ValueError('A retained dependency is also scheduled for cleanup')
    roots = sorted({a['quarantine_root'] for a in actions})
    if any(inv.within(a, b) for i, a in enumerate(roots) for b in roots[:i]):
        raise ValueError('Quarantine roots must not overlap')


def verify_dependencies(actions, limits, target_paths=None):
    """Batch whole-archive checks, then compare each target before mutation."""
    groups = {}
    for index, action in enumerate(actions):
        keeper = action['keeper']; path = (target_paths or {}).get(index, action['target']['path'])
        if keeper['kind'] == 'file':
            content.verify_file(keeper)
            if path is not None:
                content.compare_files(path, keeper['path'])
        else:
            groups.setdefault(keeper['path'], []).append((keeper, path))
    for archive, items in groups.items():
        comparisons = {}
        for keeper, path in items:
            if path is not None:
                comparisons.setdefault((keeper['kind'], keeper['member']), path)
        actual = {content.key(r): r for r in content.archive_evidence(archive, **limits, comparisons=comparisons)}
        for keeper, path in items:
            if actual.get(content.key(keeper)) != keeper:
                raise ValueError('Retained archive changed')
            if path is not None:
                content.compare_files(path, comparisons[(keeper['kind'], keeper['member'])])


def plan_cleanup(duplicates, selection, output):
    source = Path(inv.absolute(str(duplicates)))
    detected = load(source / 'duplicates.json'); selected = load(selection)
    if detected.get('schema_version') != 1 or selected.get('schema_version') != 1:
        raise ValueError('Unsupported cleanup input version')
    if selected.get('writers_stopped') is not True:
        raise ValueError('Stop writers and acknowledge writers_stopped in the selection')
    actions = []; rows = inv.mounts(); config = detected['config']
    for chosen in selected['actions']:
        candidates = [m for m in detected['matches'] if m['content_equal']
                      and m['target']['path'] == chosen['target']
                      and content.key(m['keeper']) == (chosen['keeper']['kind'], chosen['keeper']['path'], chosen['keeper'].get('member'))]
        if len(candidates) != 1:
            raise ValueError('Selection must refer to exactly one verified detection match')
        match = candidates[0]
        action = dict(match, reason=chosen['reason'], role=chosen['role'],
                      attributes_reviewed=chosen.get('attributes_reviewed', False),
                      project=check_scope(chosen['target'], config),
                      quarantine_root=inv.absolute(chosen['quarantine_root']))
        validate_action(action, config, rows)
        content.verify_file(action['target'])
        actions.append(action)
    if not actions:
        raise ValueError('Selection is empty')
    validate_dependencies(actions, config, rows)
    verify_dependencies(actions, detected['limits'])
    directory = Path(inv.absolute(str(output))); inv.no_symlink_path(directory)
    local(directory, rows)
    if any(inv.within(str(directory), p['path']) for p in config['projects']):
        raise ValueError('Operation output must be outside project roots')
    if any(inv.within(str(directory), a['quarantine_root']) or inv.within(a['quarantine_root'], str(directory))
           for a in actions):
        raise ValueError('Operation output and quarantine roots must be disjoint')
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    inv.mark_runtime(directory, 'cleanup')
    sync_directories(directory)
    identity = uuid.uuid4().hex
    for i, action in enumerate(actions):
        action['quarantine'] = str(Path(action['quarantine_root']) / identity / str(i))
    registry = config.get('cleanup_registry', str(Path(detected['run']) / 'cleanup-registry.json'))
    plan = {'schema_version': 1, 'kind': 'quarantine', 'operation_id': identity, 'created': inv.now(),
            'directory': str(directory), 'source_run': detected['run'], 'registry': registry,
            'duplicates': str(source), 'selection': str(Path(selection).absolute()),
            'config': config, 'limits': detected['limits'], 'writers_stopped': True, 'actions': actions,
            'projects': {p: identity_of(p) for p in sorted({a['project'] for a in actions})}}
    validate_registry(plan)
    durable(directory / 'manifest.json', plan)
    return {'manifest': str(directory / 'manifest.json'), 'actions': len(actions)}


def identity_of(path):
    inv.no_symlink_path(path); s = os.stat(path)
    return [s.st_dev, s.st_ino]


def validate_plan(plan, directory):
    if plan.get('schema_version') != 1 or plan.get('kind') != 'quarantine' or plan.get('writers_stopped') is not True:
        raise ValueError('Invalid quarantine plan')
    if plan['directory'] != str(directory) or not re.fullmatch('[a-f0-9]{32}', plan['operation_id']):
        raise ValueError('Plan directory or operation ID mismatch')
    local(directory, inv.mounts())
    validate_dependencies(plan['actions'], plan['config'], inv.mounts())
    validate_registry(plan)
    for p, identity in plan['projects'].items():
        if identity_of(p) != identity:
            raise ValueError('Project directory changed')
    if set(plan['projects']) != {a['project'] for a in plan['actions']}:
        raise ValueError('Project set mismatch')
    for i, action in enumerate(plan['actions']):
        expected = str(Path(action['quarantine_root']) / plan['operation_id'] / str(i))
        if action['quarantine'] != expected:
            raise ValueError('Quarantine destination escaped the operation directory')


def read_state(directory, plan):
    path = directory / 'state.json'
    if path.exists():
        state = load(path)
        if state['manifest_sha256'] != signature(plan):
            raise ValueError('Manifest changed after execution started')
        if len(state.get('entries', [])) != len(plan['actions']) or not isinstance(state.get('phases'), dict):
            raise ValueError('Invalid operation state shape')
        allowed = {'planned', 'quarantined', 'restored', 'purged', 'quarantine_intent', 'restore_intent', 'purge_intent'}
        for action, entry in zip(plan['actions'], state['entries']):
            if entry.get('status') not in allowed or not isinstance(entry.get('events'), list):
                raise ValueError('Unknown or invalid per-file state; manual recovery required')
            for field in ('quarantined', 'restored'):
                if field not in entry:
                    continue
                ref = entry[field]; target = action['target']
                expected_path = action['quarantine'] if field == 'quarantined' else target['path']
                if (ref['path'] != expected_path or ref['fingerprint'][:4] != target['fingerprint'][:4]
                        or ref['sha256'] != target['sha256'] or ref['length'] != target['length']):
                    raise ValueError('Recorded outcome does not match planned content and identity')
            status = entry['status']
            if status in {'quarantined', 'restored', 'purged'}:
                expected_phase = {'quarantined': 'quarantine', 'restored': 'restore', 'purged': 'purge'}[status]
                verified = [e for e in entry['events'] if e.get('state') == 'verified']
                if not verified or verified[-1].get('phase') != expected_phase or 'quarantined' not in entry:
                    raise ValueError('Missing verified outcome evidence')
                if status == 'restored' and 'restored' not in entry:
                    raise ValueError('Missing restoration evidence')
        if any(phase not in {'quarantine', 'restore', 'purge'} or result.get('data_status') not in {'running', 'partial', 'complete', 'not_started'}
               for phase, result in state['phases'].items()):
            raise ValueError('Unknown phase state')
        for result in state['phases'].values():
            indices = result.get('indices')
            if not isinstance(indices, list) or not indices or len(set(indices)) != len(indices) or any(
                    type(i) is not int or not 0 <= i < len(state['entries']) for i in indices):
                raise ValueError('Invalid recorded phase scope')
        return state
    return {'schema_version': 1, 'operation_id': plan['operation_id'], 'manifest_sha256': signature(plan),
            'entries': [{'status': 'planned', 'events': []} for _ in plan['actions']], 'phases': {}}


def save_state(directory, state):
    durable(directory / 'state.json', state)


def recover_phase_completion(state, phase):
    result = state['phases'][phase]
    if all(any(e['phase'] == phase and e['state'] == 'verified' for e in state['entries'][i]['events'])
           for i in result['indices']):
        result['data_status'] = 'complete'


def event(entry, phase, state, **details):
    entry['events'].append(dict(phase=phase, state=state, time=inv.now(), **details))


def verify_location(action, entry, phase):
    if phase == 'quarantine':
        if os.path.lexists(action['quarantine']):
            raise ValueError('Quarantine destination already exists')
        actual = content.verify_file(action['target'])
    else:
        actual = content.verify_file(entry['quarantined'], action['quarantine'])
        if phase == 'restore' and os.path.lexists(action['target']['path']):
            raise ValueError('Restore destination already exists')
        if phase == 'restore' and existing_parent_identity(action['target']['path']) != action['target']['parent_identity']:
            raise ValueError('Original parent changed; manual recovery required')
    if actual['attributes']['nlink'] != 1:
        raise ValueError('Hardlinked targets are report-only')
    return actual


def validate_registry(plan):
    path = inv.absolute(plan['registry']); inv.no_symlink_path(path)
    local(Path(path).parent, inv.mounts())
    if any(inv.within(path, p['path']) for p in plan['config']['projects']):
        raise ValueError('Cleanup registry must be outside business projects')
    if any(inv.within(path, a['quarantine_root']) for a in plan['actions']):
        raise ValueError('Cleanup registry must be outside quarantine')
    if Path(path).exists():
        value = load(path)
        if value.get('kind') != 'data-manager-cleanup-registry' or value.get('schema_version') != 1:
            raise ValueError('Existing file is not a cleanup registry')
        for field in ('quarantine_roots', 'runtime_paths'):
            if not isinstance(value.get(field), list) or any(not isinstance(p, str) or not os.path.isabs(p) for p in value[field]):
                raise ValueError('Invalid cleanup registry')


def ensure_registry(plan):
    validate_registry(plan)
    path = Path(plan['registry']); inv.no_symlink_path(path)
    previous = load(path) if path.exists() else {'schema_version': 1, 'kind': 'data-manager-cleanup-registry',
                                               'quarantine_roots': [], 'runtime_paths': []}
    previous['quarantine_roots'] = sorted(set(previous['quarantine_roots']) | {a['quarantine_root'] for a in plan['actions']})
    previous['runtime_paths'] = sorted(set(previous['runtime_paths']) |
                                       {plan['directory'], plan['source_run'], plan['duplicates'], plan['selection']})
    durable(path, previous)


def scoped_measure(plan, directory, phase, moment):
    config = plan['config']; roots = sorted(plan['projects'])
    business = dict(config, managed_roots=[{'path': p, 'evidence': 'Reviewed affected project'} for p in roots],
                    projects=[p for p in config['projects'] if p['path'] in roots], containers=[],
                    system_paths=[p for p in config['system_paths'] if any(inv.within(p['path'], r) for r in roots)])
    folder = directory / 'measurements' / (phase + '-' + moment + '-' + uuid.uuid4().hex)
    inv.scan(business, folder)
    db = inv.connect(folder)
    try:
        values = {r['path']: dict(r) for r in db.execute('SELECT * FROM measures')}
        status = inv.meta(db, 'scan_status')
        if any(not values.get(p) or values[p]['unknown'] or values[p]['errors'] for p in roots):
            status = 'partial'
        started = inv.meta(db, 'started'); finished = inv.meta(db, 'finished')
    finally:
        db.close()
    qroots = sorted({a['quarantine_root'] for a in plan['actions']})
    # A separate fresh scan measures quarantine without treating it as a project.
    quarantine = dict(config, managed_roots=[{'path': p, 'evidence': 'Reviewed quarantine'} for p in qroots],
                      projects=[], containers=[], system_paths=[], out_of_scope=[], include_mounts=[])
    qfolder = folder.parent / (folder.name + '-quarantine')
    inv.scan(quarantine, qfolder)
    qdb = inv.connect(qfolder)
    try:
        qvalues = {r['path']: dict(r) for r in qdb.execute('SELECT * FROM measures')}
        qstatus = inv.meta(qdb, 'scan_status')
        if any(not qvalues.get(p) or qvalues[p]['unknown'] or qvalues[p]['errors'] for p in qroots):
            qstatus = 'partial'
    finally:
        qdb.close()
    available = {p: os.statvfs(p).f_bavail * os.statvfs(p).f_frsize for p in qroots}
    return {'run': str(folder), 'quarantine_run': str(qfolder), 'started': started, 'finished': finished,
            'status': 'complete' if status == qstatus == 'complete' else 'partial',
            'projects': {p: values.get(p) for p in roots}, 'quarantine': {p: qvalues.get(p) for p in qroots},
            'available_bytes': available, 'verified_storage_release_bytes': None}


def update_cleanup_text(original, records):
    text = original.decode('utf-8')
    # Reuse the strict five-field validation without changing the scale value.
    match = re.search(r'^- 数据规模：(.*)$', text, re.M)
    if not match:
        raise ValueError('Missing scale field')
    reg.update_scale(original, match[1].rstrip('\r'))
    for record in records:
        marker = '<!-- data-manager-cleanup:' + record['id'] + ' -->'
        if marker in text:
            continue
        newline = '\r\n' if '\r\n' in text else '\n'
        current = re.search(r'^- 最近清理：(\d{4}-\d{2}-\d{2})', text, re.M)
        date = max(record['date'], current[1] if current else record['date'])
        text = re.sub(r'^- 最近清理：[^\r\n]*', '- 最近清理：' + date, text, count=1, flags=re.M)
        description = f'{record["date"]} {record["phase"]}: {record["files"]} files; {record["status"]}; operation {record["id"]}'
        # Append to the existing cleaning field without dropping manual content.
        text = re.sub(r'^- 清理情况：[^\r\n]*', lambda m: m[0] + '; ' + description, text, count=1, flags=re.M)
        text += newline + marker + newline
    return text.encode('utf-8')


def finalize(directory, plan, state, phase):
    result = state['phases'][phase]
    if result.get('registration_changed'):
        raise ValueError('Registration changed after verification; review current metadata before retrying')
    if result.get('finalized'):
        return
    after = scoped_measure(plan, directory, phase, 'after')
    result['after'] = after; save_state(directory, state)
    if after['status'] != 'complete':
        raise ValueError('Fresh measurement incomplete; finalization pending')
    registration = reg.plan(after['run'])
    manifest = load(registration)
    for action in manifest['actions']:
        if Path(action['target']).name != 'PROJECT.md':
            continue
        project = str(Path(action['target']).parent)
        records = []
        for prior_phase, prior in state['phases'].items():
            count = sum(a['project'] == project and any(e['phase'] == prior_phase and e['state'] == 'verified'
                        for e in entry['events']) for a, entry in zip(plan['actions'], state['entries']))
            if count:
                verified_times = [e['time'] for a, entry in zip(plan['actions'], state['entries']) if a['project'] == project
                                  for e in entry['events'] if e['phase'] == prior_phase and e['state'] == 'verified']
                records.append({'id': plan['operation_id'] + ':' + prior_phase + ':' + str(count) + ':' + prior.get('data_status', 'partial'),
                                'date': max(verified_times)[:10], 'phase': prior_phase,
                                'files': count, 'status': prior.get('data_status', 'partial')})
        if records:
            draft = Path(action['draft'])
            updated = update_cleanup_text(draft.read_bytes(), records)
            draft.write_bytes(updated); action['after_sha256'] = inv.digest(updated)
    inv.dump(registration, manifest)
    applied = reg.apply(registration)
    result['registration_manifest'] = str(registration)
    result['registration_results'] = applied
    if manifest['pending'] or any(r['status'] != 'verified' for r in applied['results']):
        save_state(directory, state)
        raise ValueError('Registration requires review; data operations must not be repeated')
    result['finalized'] = True; result.pop('finalization_error', None)
    save_state(directory, state)


def check_registrations(state):
    latest = {}
    for phase, result in state['phases'].items():
        for record in result.get('registration_results', {}).get('results', []):
            if record['status'] == 'verified' and record['operation'] == 'write':
                latest[record['target']] = (phase, record)
    changed = set()
    for target, (phase, record) in latest.items():
        try:
            current, _ = reg.read_metadata(target)
            if current is None or inv.digest(current) != record['after_sha256']:
                changed.add(phase)
        except (OSError, ValueError):
            changed.add(phase)
    for phase, result in state['phases'].items():
        if phase in changed:
            if not result.get('registration_changed'):
                result['registration_was_finalized'] = result.get('finalized', False)
            result.update(registration_changed=True, finalized=False,
                          finalization_error='Registration changed since verification; manual review required')
        elif result.pop('registration_changed', False):
            result['finalized'] = result.pop('registration_was_finalized', False)
            result.pop('finalization_error', None)


def output_report(directory, plan, state):
    check_registrations(state)
    save_state(directory, state)
    report = {'operation_id': plan['operation_id'], 'projects': sorted(plan['projects']),
              'entries': state['entries'], 'phases': state['phases'],
              'status': 'complete' if state['phases'] and all(p.get('finalized') and p.get('data_status') == 'complete'
                        for p in state['phases'].values()) and all(e['status'] in {'quarantined', 'restored', 'purged'}
                        for e in state['entries']) else 'pending',
              'verified_storage_release_bytes': None}
    durable(directory / 'report.json', report)
    lines = ['# 数据清理报告', '', f'操作：{plan["operation_id"]}；状态：{report["status"]}。', '',
             '覆盖仅限本批受影响项目和隔离区，其他历史盘点未刷新。',
             '隔离仍占用存储。文件系统可用空间变化不能直接归因于本操作；已证明实际释放空间：未知。',
             '内容等价不保证权限、属主、ACL、扩展属性或原路径用途可以恢复。', '',
             '| 阶段 | 数据状态 | 登记与测量收尾 |', '|---|---|---|']
    for phase, result in state['phases'].items():
        lines.append(f'| {phase} | {result.get("data_status", "pending")} | {"complete" if result.get("finalized") else "pending"} |')
        before = result.get('before'); after = result.get('after')
        if before and after:
            result['allocation_changes'] = {
                'project_decrease_bytes': {p: before['projects'][p]['allocated'] - after['projects'][p]['allocated']
                                           for p in plan['projects'] if before['projects'].get(p) and after['projects'].get(p)},
                'quarantine_allocated_bytes': {p: v['allocated'] if v else None for p, v in after['quarantine'].items()},
                'available_bytes_change': {p: after['available_bytes'][p] - v for p, v in before['available_bytes'].items()}}
            lines += ['', f'## {phase} 实测容量', '', '| 范围 | 操作前分配字节 | 操作后分配字节 |', '|---|---:|---:|']
            for category in ('projects', 'quarantine'):
                for path, row in after[category].items():
                    old = before[category].get(path)
                    label = path.replace('|', '\\|').replace('\n', '<br>').replace('\r', '')
                    lines.append(f'| {label} | {old["allocated"] if old else "未知"} | {row["allocated"] if row else "未知"} |')
    purged = [e['quarantined'].get('allocated') for e in state['entries'] if e['status'] == 'purged']
    report['purged_content_allocated_bytes'] = sum(purged) if all(n is not None for n in purged) else None
    with (directory / 'files.csv').open('w', newline='') as stream:
        writer = csv.writer(stream); writer.writerow(['original', 'quarantine', 'keeper', 'member', 'status', 'sha256'])
        for action, entry in zip(plan['actions'], state['entries']):
            writer.writerow([action['target']['path'], action['quarantine'], action['keeper']['path'],
                             action['keeper']['member'], entry['status'], action['target']['sha256']])
    durable(directory / 'report.json', report)
    (directory / 'REPORT.md').write_text('\n'.join(lines) + '\n\n逐文件明细：[files.csv](files.csv)；完整测量：[report.json](report.json)；事件与失败：[state.json](state.json)。\n')
    return report


def execute(directory, phase='quarantine', purge_manifest=None):
    if phase not in {'quarantine', 'restore', 'purge'}:
        raise ValueError('Unsupported cleanup phase')
    directory = private_directory(directory)
    plan = load(directory / 'manifest.json'); validate_plan(plan, directory)
    with operation_locks(plan, directory):
        state = read_state(directory, plan)
        check_registrations(state)
        if any(e['status'].endswith('_intent') for e in state['entries']):
            raise ValueError('Uncertain interrupted mutation; inspect state.json before recovery')
        if phase == 'purge':
            if purge_manifest is None:
                raise ValueError('Reviewed purge manifest required')
            expected = purge_manifest
            if (expected.get('kind') != 'purge' or expected.get('schema_version') != 1
                    or expected['operation'] != str(directory) or expected['manifest_sha256'] != signature(plan)):
                raise ValueError('Invalid purge manifest')
            indices = expected['indices']
            if not indices or len(set(indices)) != len(indices) or any(type(i) is not int or i < 0 or i >= len(plan['actions']) for i in indices):
                raise ValueError('Invalid purge selection')
            if expected.get('paths') != [plan['actions'][i]['quarantine'] for i in indices]:
                raise ValueError('Displayed purge paths do not match the reviewed execution set')
            if any(state['entries'][i]['status'] not in {'quarantined', 'purged'} for i in indices):
                raise ValueError('The reviewed quarantine set is no longer eligible for purge')
            bound = signature([state['entries'][i].get('quarantined') for i in indices])
            if expected['quarantined_sha256'] != bound:
                raise ValueError('Reviewed quarantine set changed')
        else:
            indices = list(range(len(plan['actions'])))
        desired = 'planned' if phase == 'quarantine' else 'quarantined'
        remaining = [i for i in indices if state['entries'][i]['status'] == desired]
        resuming = phase in state['phases']
        if resuming:
            # Reapplications verify evidence and finish metadata; no data mutation repeats.
            completed = 'quarantined' if phase == 'quarantine' else ('restored' if phase == 'restore' else 'purged')
            for i in indices:
                entry = state['entries'][i]; action = plan['actions'][i]
                if entry['status'] == 'quarantined':
                    content.verify_file(entry['quarantined'], action['quarantine'])
                elif entry['status'] == 'restored':
                    content.verify_file(entry['restored'], action['target']['path'])
                elif entry['status'] == 'purged' and os.path.lexists(action['quarantine']):
                    raise ValueError('Purged destination unexpectedly reappeared')
                elif entry['status'] not in {completed, 'purged', 'restored', 'planned'}:
                    raise ValueError('Uncertain previous result')
            if not remaining:
                recover_phase_completion(state, phase)
                try:
                    finalize(directory, plan, state, phase)
                except Exception as exc:
                    state['phases'][phase]['finalization_error'] = str(exc); save_state(directory, state)
                return output_report(directory, plan, state)
        indices = remaining
        if not indices:
            raise ValueError('No eligible files for this phase')
        actions = [plan['actions'][i] for i in indices]
        paths = {j: a['target']['path'] if phase == 'quarantine' else a['quarantine'] for j, a in enumerate(actions)}
        for i in indices:
            verify_location(plan['actions'][i], state['entries'][i], phase)
        if phase != 'restore':
            verify_dependencies(actions, plan['limits'], paths)
        ensure_registry(plan)
        if phase == 'quarantine':
            for root in sorted({a['quarantine_root'] for a in actions}):
                child = Path(root) / plan['operation_id']
                private_directory(child, create=not child.exists())
        if not resuming:
            state['phases'][phase] = {'started': inv.now(), 'data_status': 'running', 'finalized': False, 'indices': indices}
        else:
            state['phases'][phase].update(data_status='running', finalized=False)
            state['phases'][phase]['indices'] = sorted(set(state['phases'][phase].get('indices', [])) | set(indices))
        save_state(directory, state)
        before = scoped_measure(plan, directory, phase, 'before')
        state['phases'][phase].setdefault('before', before)
        if before['status'] != 'complete':
            state['phases'][phase]['data_status'] = 'not_started'
            save_state(directory, state)
            return output_report(directory, plan, state)
        save_state(directory, state)
        succeeded = 0
        for i in indices:
            action = plan['actions'][i]; entry = state['entries'][i]
            intent = False
            try:
                verify_location(action, entry, phase)
                # Whole-archive evidence is phase-scoped; reject any later metadata change.
                if phase != 'restore':
                    keeper = action['keeper']
                    with content.regular(keeper['path']) as (_, s, parent):
                        if content.fingerprint(s) != keeper['fingerprint'] or [parent.st_dev, parent.st_ino] != keeper['parent_identity']:
                            raise ValueError('Retained copy changed after phase validation')
                entry['status'] = phase + '_intent'; event(entry, phase, 'intent')
                save_state(directory, state); intent = True
                if phase == 'quarantine':
                    rename_noreplace(action['target']['path'], action['quarantine'])
                    entry['quarantined'] = content.verify_file(action['target'], action['quarantine'], relocated=True)
                    entry['status'] = 'quarantined'
                elif phase == 'restore':
                    rename_noreplace(action['quarantine'], action['target']['path'])
                    entry['restored'] = content.verify_file(entry['quarantined'], action['target']['path'], relocated=True)
                    entry['status'] = 'restored'
                else:
                    with reg.parent_handle(action['quarantine']) as (fd, name):
                        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if content.fingerprint(current) != entry['quarantined']['fingerprint']:
                            raise ValueError('Quarantine changed before unlink')
                        os.unlink(name, dir_fd=fd); os.fsync(fd)
                        if os.path.lexists(action['quarantine']):
                            raise ValueError('Unlink verification failed')
                    entry['status'] = 'purged'
                event(entry, phase, 'verified'); save_state(directory, state); succeeded += 1
            except BaseException as exc:
                if intent:
                    entry['status'] = phase + '_intent'
                event(entry, phase, 'failed', error=str(exc))
                state['phases'][phase]['error'] = str(exc)
                state['phases'][phase]['data_status'] = 'partial'
                save_state(directory, state)
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                break
        else:
            state['phases'][phase]['data_status'] = 'complete'
            state['phases'][phase].pop('error', None)
        save_state(directory, state)
        if succeeded or not any(e['status'].endswith('_intent') for e in state['entries']):
            try:
                finalize(directory, plan, state, phase)
            except Exception as exc:
                state['phases'][phase]['finalization_error'] = str(exc); save_state(directory, state)
        return output_report(directory, plan, state)


def plan_purge(cleanup, output):
    directory = private_directory(cleanup); plan = load(directory / 'manifest.json')
    validate_plan(plan, directory)
    with operation_locks(plan, directory):
        state = read_state(directory, plan)
        if any(e['status'].endswith('_intent') for e in state['entries']):
            raise ValueError('Uncertain operation; purge blocked')
        indices = [i for i, entry in enumerate(state['entries']) if entry['status'] == 'quarantined']
        if not indices:
            raise ValueError('No verified quarantined files')
        for i in indices:
            verify_location(plan['actions'][i], state['entries'][i], 'purge')
        verify_dependencies([plan['actions'][i] for i in indices], plan['limits'],
                            {j: plan['actions'][i]['quarantine'] for j, i in enumerate(indices)})
        output = Path(inv.absolute(str(output))); inv.no_symlink_path(output)
        if any(inv.within(str(output), p['path']) for p in plan['config']['projects']) or any(
                inv.within(str(output), a['quarantine_root']) or inv.within(a['quarantine_root'], str(output)) for a in plan['actions']):
            raise ValueError('Purge output must be outside projects and disjoint from quarantine')
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        inv.mark_runtime(output, 'purge-plan')
        manifest = {'schema_version': 1, 'kind': 'purge', 'created': inv.now(), 'operation': str(directory),
                    'manifest_sha256': signature(plan), 'indices': indices,
                    'quarantined_sha256': signature([state['entries'][i]['quarantined'] for i in indices]),
                    'paths': [plan['actions'][i]['quarantine'] for i in indices]}
        durable(output / 'manifest.json', manifest)
        return {'manifest': str(output / 'manifest.json'), 'files': len(indices)}


def report_cleanup(operation):
    directory = private_directory(operation); plan = load(directory / 'manifest.json')
    validate_plan(plan, directory)
    with operation_locks(plan, directory):
        state = read_state(directory, plan)
        check_registrations(state)
        if any(e['status'].endswith('_intent') for e in state['entries']):
            raise ValueError('Uncertain mutation: inspect state.json; automatic finalization blocked')
        for action, entry in zip(plan['actions'], state['entries']):
            if entry['status'] == 'quarantined':
                content.verify_file(entry['quarantined'], action['quarantine'])
            elif entry['status'] == 'restored':
                content.verify_file(entry['restored'], action['target']['path'])
            elif entry['status'] == 'purged' and os.path.lexists(action['quarantine']):
                raise ValueError('Purged path unexpectedly exists')
        for phase in state['phases']:
            recover_phase_completion(state, phase)
            if not state['phases'][phase].get('finalized'):
                try:
                    finalize(directory, plan, state, phase)
                except Exception as exc:
                    state['phases'][phase]['finalization_error'] = str(exc); save_state(directory, state)
        return output_report(directory, plan, state)
