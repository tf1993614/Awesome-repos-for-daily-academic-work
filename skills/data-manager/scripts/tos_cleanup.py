"""Native TOS inventory, reviewed cleanup, and read-only interruption reconciliation."""
from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor
import csv
import json
import os
from pathlib import Path
import re
import uuid

import cleanup as local
import content
import inventory as inv
import remote_io
from tos_store import TosStore, read_profile


def output_directory(path):
    path = Path(inv.absolute(str(path))); inv.no_symlink_path(path)
    local.local(path.parent, inv.mounts())
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    inv.mark_runtime(path, 'native-tos')
    local.sync_directories(path)
    return path


def controls(config):
    return TosStore(read_profile(config)).controls()


def scan(config, output, store=None):
    profile = read_profile(config) if not isinstance(config, dict) else config
    store = store or TosStore(profile)
    directory = output_directory(output)
    rows = []; issues = []
    for project in profile['projects']:
        try:
            for key in store.keys(project['prefix']):
                if key.endswith('/'):
                    continue
                try:
                    rows.append(dict(store.inspect(key), project=project['prefix']))
                except (ValueError, RuntimeError, OSError) as exc:
                    issues.append({'key': key, 'error': str(exc)})
        except (ValueError, RuntimeError, OSError) as exc:
            issues.append({'prefix': project['prefix'], 'error': str(exc)})
    result = {'schema_version': 1, 'backend': 'tos', 'config': profile, 'created': inv.now(),
              'status': 'partial' if issues else 'complete', 'objects': rows, 'issues': issues,
              'allocated': None, 'allocation_source': 'unknown', 'physical_or_billed_bytes': None}
    local.durable(directory / 'snapshot.json', result)
    return report_inventory(directory)


def report_inventory(run):
    directory = local.private_directory(run)
    result = local.load(directory / 'snapshot.json')
    rows = result['objects']; profile = result['config']; issues = result['issues']
    with (directory / 'projects.csv').open('w', newline='') as f:
        writer = csv.writer(f); writer.writerow(['prefix', 'logical_bytes', 'allocated', 'threshold_decision'])
        for project in profile['projects']:
            writer.writerow([project['prefix'], sum(r['object_length'] for r in rows if r['project'] == project['prefix']),
                             'unknown', 'pending_measurement'])
    (directory / 'REPORT.md').write_text('# TOS 存储盘点\n\n' +
        '范围仅限已确认项目前缀。逻辑大小不是分配占用或计费容量；登记阈值判断待测量。\n\n' +
        f'状态：{result["status"]}；对象：{len(rows)}；问题：{len(issues)}。\n')
    return {'output': str(directory), 'status': result['status'], 'objects': len(rows), 'allocated': None,
            'registration_status': 'pending_measurement', 'snapshot_created': result['created']}


def archive_source(store, ref):
    @contextlib.contextmanager
    def source():
        with store.open(ref) as (stream, _):
            yield stream, {'object': ref, 'path': ref['path']}
    return source


def archive_refs(store, ref, limits, target=None, keeper=None):
    comparisons = {(keeper['kind'], keeper['member']): target} if target is not None else {}
    @contextlib.contextmanager
    def compare_open(value):
        with store.open(value) as (stream, _):
            yield stream, None, None
    return content.archive_evidence(ref['key'], **limits, source=archive_source(store, ref),
                                    comparisons=comparisons, comparison_open=compare_open)


def find_duplicates(run, output, max_expanded=content.MAX_EXPANDED, max_members=content.MAX_MEMBERS, store=None):
    snapshot = local.load(Path(run) / 'snapshot.json')
    profile = snapshot['config']; store = store or TosStore(profile)
    directory = output_directory(output)
    limits = {'max_expanded': max_expanded, 'max_members': max_members}
    if min(limits.values()) < 1:
        raise ValueError('Archive limits must be positive')
    issues = list(snapshot['issues']); files = []; refs = []
    candidates = []
    for obj in snapshot['objects']:
        try:
            store.project(obj['key']); candidates.append(obj)
        except ValueError:
            continue
    def detect(obj):
        ref = store.evidence(obj['key'], obj['version_id'])
        expected = {k: v for k, v in obj.items() if k != 'project'}
        if {k: v for k, v in ref.items() if k not in {'length', 'sha256'}} != expected:
            raise ValueError('TOS inventory object changed')
        store.verify(ref, current=True)
        return ref, archive_refs(store, ref, limits) if content.archive_type(obj['key']) else []
    with ThreadPoolExecutor(max_workers=store.traffic.options['workers']) as pool:
        futures = [(obj, pool.submit(detect, obj)) for obj in candidates]
        for obj, future in futures:
            try:
                ref, archive = future.result(); files.append(ref); refs.extend([ref, *archive])
            except Exception as exc:
                issues.append({'key': obj['key'], 'error': str(exc)})
    groups = {}
    for ref in refs:
        groups.setdefault((ref['length'], ref['sha256']), []).append(ref)
    matches = []
    for target in files:
        for keeper in groups[(target['length'], target['sha256'])]:
            obj = keeper.get('object', keeper)
            if obj['key'] == target['key']:
                continue
            try:
                verify_pair(store, target, keeper, limits)
                matches.append({'target': target, 'keeper': keeper, 'content_equal': True})
            except (ValueError, RuntimeError, OSError, EOFError) as exc:
                issues.append({'key': target['key'], 'error': str(exc)})
    result = {'schema_version': 1, 'backend': 'tos', 'config': profile, 'run': str(Path(run).absolute()),
              'matches': matches, 'limits': limits, 'issues': issues, 'created': inv.now(),
              'status': 'partial' if issues or snapshot['status'] != 'complete' else 'complete'}
    local.durable(directory / 'duplicates.json', result)
    local.durable(directory / 'selection.example.json', {'schema_version': 1, 'writers_stopped': False, 'actions': []})
    with (directory / 'duplicates.csv').open('w', newline='') as f:
        writer = csv.writer(f); writer.writerow(['target', 'keeper', 'kind', 'member', 'length', 'sha256'])
        for match in matches:
            t, k = match['target'], match['keeper']
            writer.writerow([t['key'], k.get('object', k)['key'], k['kind'], k['member'], t['length'], t['sha256']])
    (directory / 'REPORT.md').write_text('# TOS 重复内容\n\n' +
        f'状态：{result["status"]}；已验证关系：{len(matches)}。\n\n内容相等仍须逐项确认业务冗余。\n')
    return {'output': str(directory), 'status': result['status'], 'matches': len(matches)}


def verify_pair(store, target, keeper, limits):
    store.verify(target)
    obj = keeper.get('object', keeper)
    store.project(obj['key']); store.verify(obj, current=True)
    if keeper['kind'] == 'file':
        store.compare(target, keeper)
    else:
        actual = archive_refs(store, obj, limits, target, keeper)
        if keeper not in actual:
            raise ValueError('Retained archive changed or selected member missing')


def probe(config, output, store=None):
    profile = read_profile(config) if not isinstance(config, dict) else config
    store = store or TosStore(profile)
    directory = output_directory(output)
    result = {'schema_version': 1, 'kind': 'tos-capabilities', 'backend': 'tos',
              'checked': inv.now(), 'supported': False, 'endpoint': profile['endpoint'],
              'bucket': profile['bucket'], 'quarantine_prefix': profile['quarantine_prefix'], 'fixtures': []}
    result['controls'] = store.safety()
    local.durable(directory / 'probe.json', result)
    base = profile['quarantine_prefix'] + '.probe-' + uuid.uuid4().hex + '/'
    try:
        for key, data in [(base + 'source', b'NAS/TOS capability source'), (base + 'occupied', b'occupied')]:
            result['fixtures'].append({'key': key, 'status': 'create_intent'})
            local.durable(directory / 'probe.json', result)
            receipt = store.call('put_object', key, content=data, forbid_overwrite=True)
            ref = store.evidence(key, getattr(receipt, 'version_id', None))
            if ref['length'] != len(data):
                raise ValueError('TOS fixture read-back failed')
            result['fixtures'][-1].update(status='created', ref=ref)
            local.durable(directory / 'probe.json', result)
        source, occupied = [r['ref'] for r in result['fixtures']]
        try:
            store.copy(source, occupied['key'], lambda **kw: None)
        except RuntimeError as exc:
            if not any(code in str(exc) for code in ('409/', '412/')):
                raise
        else:
            raise ValueError('TOS did not reject copy into an occupied key')
        store.verify(occupied, current=True)
        destination = base + 'copied'
        result['fixtures'].append({'key': destination, 'status': 'copy_intent'})
        local.durable(directory / 'probe.json', result)
        receipt = store.copy(source, destination, lambda **kw: None)
        ref = store.evidence(destination, receipt.version_id)
        if not same_content(source, ref):
            raise ValueError('TOS positive copy capability check failed')
        result['fixtures'][-1].update(status='created', ref=ref)
        local.durable(directory / 'probe.json', result)
        result['supported'] = True
    except Exception as exc:
        result['error'] = str(exc)
    finally:
        for fixture in result['fixtures']:
            if fixture['status'] != 'created':
                continue
            try:
                fixture['status'] = 'purge_intent'; local.durable(directory / 'probe.json', result)
                fixture['receipt'] = store.delete(fixture['ref'])
                if store.exists(fixture['key'], fixture['ref']['version_id']) is not None:
                    raise ValueError('Probe fixture version remains')
                fixture['status'] = 'purged'
            except Exception as exc:
                fixture['error'] = str(exc); result['supported'] = False
        local.durable(directory / 'probe.json', result)
    return dict(result, output=str(directory), status='complete' if result['supported'] else 'pending')


def capability(store):
    from datetime import datetime, timezone
    report_path = Path(store.profile['capability_report'])
    local.local(report_path.parent, inv.mounts())
    evidence = local.load(report_path)
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(evidence['checked'])).total_seconds()
    if (evidence.get('kind') != 'tos-capabilities' or evidence.get('supported') is not True
            or not 0 <= age <= store.profile.get('capability_max_age_seconds', 86400)
            or evidence['endpoint'] != store.profile['endpoint'] or evidence['bucket'] != store.bucket
            or evidence['quarantine_prefix'] != store.profile['quarantine_prefix']
            or any(f['status'] != 'purged' for f in evidence['fixtures'])
            or evidence['controls'] != store.safety()):
        raise ValueError('TOS capabilities expired, changed, or incomplete; run tos-probe in a test prefix')


def plan_cleanup(duplicates, selection, output, store=None):
    detected = local.load(Path(duplicates) / 'duplicates.json'); chosen = local.load(selection)
    if chosen.get('schema_version') != 1 or chosen.get('writers_stopped') is not True:
        raise ValueError('Version-1 selection and confirmed stopped writers required')
    profile = detected['config']; store = store or TosStore(profile); capability(store)
    actions = []; targets = set(); identity = uuid.uuid4().hex
    for item in chosen['actions']:
        key = item['target']; keeper = item['keeper']; project = store.project(key)
        matches = [m for m in detected['matches'] if m['content_equal'] and m['target']['key'] == key
                   and m['keeper'].get('object', m['keeper'])['key'] == keeper['key']
                   and (m['keeper']['kind'], m['keeper']['member']) == (keeper['kind'], keeper.get('member'))]
        if len(matches) != 1 or key in targets:
            raise ValueError('Selection must bind exactly one verified duplicate relation per target')
        if (not item.get('reason') or item.get('role') not in {'redundant_data', 'working_copy', 'backup'}
                or item.get('attributes_reviewed') is not True):
            raise ValueError('Reviewed role, reason, and attribute acknowledgement required')
        match = matches[0]; store.verify(match['target'], current=True)
        verify_pair(store, match['target'], match['keeper'], detected['limits'])
        actions.append(dict(match, project=project, quarantine=profile['quarantine_prefix'] + identity + '/' + str(len(actions)),
                            role=item['role'], reason=item['reason'], attributes_reviewed=True))
        targets.add(key)
    if not actions or any(a['keeper'].get('object', a['keeper'])['key'] in targets for a in actions):
        raise ValueError('Nonempty actions and keepers outside the entire handling set required')
    directory = output_directory(output)
    plan = {'schema_version': 1, 'backend': 'tos', 'kind': 'quarantine', 'operation_id': identity,
            'created': inv.now(), 'directory': str(directory), 'config': profile, 'writers_stopped': True,
            'actions': actions, 'limits': detected['limits'], 'source_run': detected['run']}
    local.durable(directory / 'manifest.json', plan)
    return {'manifest': str(directory / 'manifest.json'), 'actions': len(actions)}


def read_operation(operation):
    directory = local.private_directory(operation); plan = local.load(directory / 'manifest.json')
    if (plan.get('backend') != 'tos' or plan.get('schema_version') != 1 or plan.get('kind') != 'quarantine'
            or plan.get('writers_stopped') is not True or plan['directory'] != str(directory)
            or not re.fullmatch('[a-f0-9]{32}', plan['operation_id']) or not plan['actions']):
        raise ValueError('Invalid native TOS cleanup manifest')
    local.local(directory, inv.mounts())
    read_profile(plan['config'])
    validator = object.__new__(TosStore); validator.profile = plan['config']; validator.bucket = plan['config']['bucket']
    targets = set()
    for i, action in enumerate(plan['actions']):
        expected = plan['config']['quarantine_prefix'] + plan['operation_id'] + '/' + str(i)
        target = action['target']; keeper = action['keeper']; obj = keeper.get('object', keeper)
        if (action['quarantine'] != expected or action.get('project') != validator.project(target['key'])
                or not action.get('reason') or action.get('role') not in {'redundant_data', 'working_copy', 'backup'}
                or action.get('attributes_reviewed') is not True or target['kind'] != 'file'
                or action.get('content_equal') is not True or target['key'] in targets
                or keeper['kind'] not in {'file', 'member', 'payload'}
                or target['key'] == obj['key'] or target['path'] != validator.uri(target['key'])
                or obj['path'] != validator.uri(obj['key'])
                or (target['length'], target['sha256']) != (keeper['length'], keeper['sha256'])):
            raise ValueError('TOS quarantine mapping escaped the reviewed operation')
        validator.project(obj['key']); targets.add(target['key'])
    if any(a['keeper'].get('object', a['keeper'])['key'] in targets for a in plan['actions']):
        raise ValueError('A retained dependency is also a target')
    path = directory / 'state.json'
    state = local.load(path) if path.exists() else {
        'schema_version': 1, 'manifest_sha256': local.signature(plan),
        'entries': [{'status': 'planned', 'events': []} for _ in plan['actions']],
        'traffic': {'read_bytes': 0, 'copy_attempted_bytes': 0}, 'phases': {}}
    if state['manifest_sha256'] != local.signature(plan) or len(state['entries']) != len(plan['actions']):
        raise ValueError('TOS manifest changed after execution or invalid state shape')
    allowed = {'planned', 'copy_intent', 'copied', 'remove_intent', 'quarantined', 'restore_copy_intent',
               'restore_copied', 'restore_remove_intent', 'restored', 'purge_intent', 'purged'}
    for action, entry in zip(plan['actions'], state['entries']):
        if entry.get('status') not in allowed or not isinstance(entry.get('events'), list):
            raise ValueError('Unknown TOS operation state')
        for field, key in [('quarantined', action['quarantine']), ('restored', action['target']['key'])]:
            if field in entry and (entry[field]['key'] != key or not same_content(entry[field], action['target'])):
                raise ValueError('TOS recorded outcome escaped the planned identity or contents')
        if entry['status'] != 'planned' and entry['status'] != 'copy_intent' and 'quarantined' not in entry:
            raise ValueError('TOS state lacks verified isolation evidence')
        required = {'quarantined': 'remove', 'restored': 'restore_remove', 'purged': 'purge'}.get(entry['status'])
        if required and (not any(e.get('phase') == required and e.get('state') == 'verified' for e in entry['events'])
                         or not entry.get(required + '_receipt')):
            raise ValueError('TOS state lacks bound verified mutation evidence')
    return directory, plan, state


def same_content(left, right):
    return all(left[k] == right[k] for k in ('length', 'sha256', 'attributes'))


def report(directory, plan, state):
    local.durable(directory / 'state.json', state)
    finished = all(e['status'] in {'quarantined', 'restored', 'purged'} for e in state['entries'])
    result = {'operation_id': plan['operation_id'], 'backend': 'tos', 'status': 'pending',
              'data_status': 'complete' if finished else 'pending', 'entries': state['entries'],
              'phases': state['phases'], 'traffic': state['traffic'], 'allocated': None,
              'physical_or_billed_bytes': None, 'verified_storage_release_bytes': None,
              'finalization_status': 'pending_backend_allocation',
              'registration': state.get('registration', {}),
              'source_historical_versions': 'preserved', 'real_backend_validation': 'see capability report'}
    local.durable(directory / 'report.json', result)
    with (directory / 'files.csv').open('w', newline='') as f:
        writer = csv.writer(f); writer.writerow(['original', 'quarantine', 'keeper', 'status', 'isolated_version', 'sha256'])
        for action, entry in zip(plan['actions'], state['entries']):
            writer.writerow([action['target']['path'], action['quarantine'], action['keeper']['path'],
                             entry['status'], entry.get('quarantined', {}).get('version_id'), action['target']['sha256']])
    lines = ['# TOS 清理报告', '', '数据状态：' + result['data_status'] + '；容量收尾：待后端分配占用证据。',
             '隔离仍占存储；源位置历史版本及删除标记保留。实际物理释放和计费容量变化未知。',
             '对象锁依据有时效的人工审核，另核查 HEAD 保留属性；不代表 SDK 能完整查询对象锁配置。',
             '', '逐对象结果：[files.csv](files.csv)；操作日志：[state.json](state.json)。']
    (directory / 'REPORT.md').write_text('\n'.join(lines) + '\n')
    return result


def session(directory, plan, state, store):
    traffic = remote_io.Traffic(plan['config'].get('remote_io'), state['traffic'],
                              lambda: local.durable(directory / 'state.json', state))
    store = store or TosStore(plan['config'], traffic)
    store.traffic = traffic
    return store


def execute(operation, phase='quarantine', purge_manifest=None, store=None):
    directory = local.private_directory(operation)
    with local.locks([directory]):
        directory, plan, state = read_operation(directory)
        store = session(directory, plan, state, store); capability(store)
        if phase not in {'quarantine', 'restore', 'purge'}:
            raise ValueError('Invalid TOS phase')
        if any(e['status'].endswith('_intent') for e in state['entries']):
            raise ValueError('Uncertain TOS mutation: reconcile-cleanup before continuing')
        indices = list(range(len(plan['actions'])))
        if phase == 'purge':
            p = purge_manifest or {}
            indices = p.get('indices', [])
            if (p.get('backend') != 'tos' or p.get('kind') != 'purge' or p.get('schema_version') != 1
                    or p.get('operation') != str(directory) or p.get('manifest_sha256') != local.signature(plan)
                    or not indices or len(indices) != len(set(indices)) or any(type(i) is not int or i < 0 or i >= len(plan['actions']) for i in indices)
                    or p.get('paths') != [plan['actions'][i]['quarantine'] for i in indices]
                    or p.get('versions') != [state['entries'][i]['quarantined']['version_id'] for i in indices]
                    or p.get('quarantined_sha256') != local.signature([state['entries'][i].get('quarantined') for i in indices])
                    or any(state['entries'][i]['status'] not in {'quarantined', 'purged'} for i in indices)):
                raise ValueError('Exact reviewed TOS purge set changed or invalid')
        state['phases'].setdefault(phase, {'started': inv.now(), 'data_status': 'pending'})
        save = lambda: local.durable(directory / 'state.json', state)
        for i in indices:
            action = plan['actions'][i]; entry = state['entries'][i]
            try:
                mutate(store, action, entry, plan['limits'], phase, save)
                save()
            except BaseException as exc:
                local.event(entry, phase, 'failed', error=str(exc)); save()
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                break
        state['phases'][phase]['data_status'] = 'complete' if all(
            e['status'] in ({'quarantined', 'restored', 'purged'} if phase == 'quarantine' else
                             {'restored', 'purged'} if phase == 'restore' else {'purged'}) for e in (state['entries'][i] for i in indices)) else 'pending'
        if not any(e['status'].endswith('_intent') for e in state['entries']):
            finalize_history(store, directory, plan, state)
        return report(directory, plan, state)


def mutate(store, action, entry, limits, phase, save):
    target = action['target']; status = entry['status']
    if status == 'quarantined':
        store.verify(entry['quarantined'], current=True)
    elif status == 'restored':
        store.verify(entry['restored'], current=True); return
    elif status == 'purged':
        if store.exists(action['quarantine'], entry['quarantined']['version_id']) is not None:
            raise ValueError('Purged TOS version reappeared')
        return
    if phase == 'quarantine' and status in {'planned', 'copied'}:
        store.verify(target, current=True); verify_pair(store, target, action['keeper'], limits)
        if status == 'planned':
            copy_stage(store, target, action['quarantine'], entry, 'copy', 'quarantined', save)
            entry['status'] = 'copied'; save()
        isolated = entry['quarantined']; store.verify(isolated, current=True); store.compare(target, isolated)
        verify_pair(store, isolated, action['keeper'], limits)
        remove_stage(store, target, entry, 'remove', 'quarantined', save,
                     hide=bool(target['version_id']))
    elif phase == 'restore' and status in {'quarantined', 'restore_copied'}:
        isolated = entry['quarantined']; store.verify(isolated, current=True)
        if status == 'quarantined':
            copy_stage(store, isolated, target['key'], entry, 'restore_copy', 'restored', save)
            entry['status'] = 'restore_copied'; save()
        restored = entry['restored']; store.verify(restored, current=True); store.compare(isolated, restored)
        remove_stage(store, isolated, entry, 'restore_remove', 'restored', save)
    elif phase == 'purge' and status == 'quarantined':
        isolated = entry['quarantined']
        verify_pair(store, isolated, action['keeper'], limits)
        remove_stage(store, isolated, entry, 'purge', 'purged', save)


def copy_stage(store, source, destination, entry, stage, field, save):
    store.safety()
    if store.exists(destination) is not None:
        raise ValueError('TOS destination occupied; restore never overwrites')
    entry['status'] = stage + '_intent'; local.event(entry, stage, 'intent'); save()
    def journal(**details):
        entry[stage + '_multipart'] = details; save()
    receipt = store.copy(source, destination, journal)
    entry[stage + '_receipt'] = {'request_id': receipt.request_id, 'version_id': receipt.version_id}
    save()
    actual = store.evidence(destination, receipt.version_id)
    if not same_content(source, actual):
        raise ValueError('TOS copied contents or required attributes do not match')
    store.compare(source, actual)
    entry[field] = actual
    local.event(entry, stage, 'verified'); save()


def remove_stage(store, source, entry, stage, completed, save, hide=False):
    store.safety()
    entry['status'] = stage + '_intent'; local.event(entry, stage, 'intent'); save()
    entry[stage + '_receipt'] = store.delete(source, hide=hide); save()
    if store.exists(source['key'], None if hide else source['version_id']) is not None:
        raise ValueError('TOS removal not visible; reconcile before continuing')
    if hide and not entry[stage + '_receipt'].get('delete_marker'):
        raise ValueError('Versioned source removal did not return a delete marker')
    entry['status'] = completed; local.event(entry, stage, 'verified'); save()


def reconcile(operation, store=None):
    directory = local.private_directory(operation)
    with local.locks([directory]):
        directory, plan, state = read_operation(directory)
        store = session(directory, plan, state, store)
        for action, entry in zip(plan['actions'], state['entries']):
            status = entry['status']
            try:
                if status in {'copy_intent', 'restore_copy_intent'}:
                    restoring = status.startswith('restore')
                    source = entry['quarantined'] if restoring else action['target']
                    destination = action['target']['key'] if restoring else action['quarantine']
                    stage = 'restore_copy' if restoring else 'copy'
                    receipt = entry.get(stage + '_receipt')
                    # A transport failure without a bound receipt remains uncertain, even if absent.
                    if not receipt:
                        continue
                    actual = store.evidence(destination, receipt['version_id'])
                    store.verify(source, current=True)
                    if not same_content(source, actual):
                        raise ValueError('Reconciliation found changed copy contents or attributes')
                    store.compare(source, actual)
                    entry['restored' if restoring else 'quarantined'] = actual
                    entry['status'] = 'restore_copied' if restoring else 'copied'
                    local.event(entry, stage, 'verified', evidence='read-only reconciliation')
                elif status in {'remove_intent', 'restore_remove_intent', 'purge_intent'}:
                    stage = status.removesuffix('_intent')
                    source = action['target'] if stage == 'remove' else entry['quarantined']
                    receipt = entry.get(stage + '_receipt')
                    if not receipt:
                        continue
                    if store.exists(source['key'], None if stage == 'remove' else source['version_id']) is not None:
                        raise ValueError('Removal still visible or original location has new data')
                    if stage == 'remove':
                        if action['target']['version_id'] and not receipt.get('delete_marker'):
                            raise ValueError('Versioned source receipt lacks a deletion marker')
                        store.verify(entry['quarantined'], current=True)
                        verify_pair(store, entry['quarantined'], action['keeper'], plan['limits'])
                    elif stage == 'restore_remove':
                        store.verify(entry['restored'], current=True)
                    else:
                        obj = action['keeper'].get('object', action['keeper']); store.verify(obj, current=True)
                    entry['status'] = {'remove': 'quarantined', 'restore_remove': 'restored', 'purge': 'purged'}[stage]
                    local.event(entry, stage, 'verified', evidence='bound receipt and read-only result checks')
            except (ValueError, OSError, RuntimeError) as exc:
                local.event(entry, status, 'unresolved', error=str(exc))
        for phase, result in state['phases'].items():
            stage = {'quarantine': 'remove', 'restore': 'restore_remove', 'purge': 'purge'}[phase]
            if all(any(e['phase'] == stage and e['state'] == 'verified' for e in item['events']) for item in state['entries']):
                result['data_status'] = 'complete'
        result = report(directory, plan, state)
        result['business_mutations'] = 0
        return result


def plan_purge(operation, output, store=None):
    directory = local.private_directory(operation)
    with local.locks([directory]):
        directory, plan, state = read_operation(directory)
        store = session(directory, plan, state, store); capability(store)
        if any(e['status'].endswith('_intent') for e in state['entries']):
            raise ValueError('Uncertain mutation blocks TOS purge planning')
        indices = [i for i, e in enumerate(state['entries']) if e['status'] == 'quarantined']
        if not indices:
            raise ValueError('No verified TOS quarantine set')
        for i in indices:
            entry = state['entries'][i]; action = plan['actions'][i]
            store.verify(entry['quarantined'], current=True)
            verify_pair(store, entry['quarantined'], action['keeper'], plan['limits'])
        output = output_directory(output)
        manifest = {'schema_version': 1, 'backend': 'tos', 'kind': 'purge', 'created': inv.now(),
                    'operation': str(directory), 'manifest_sha256': local.signature(plan), 'indices': indices,
                    'paths': [plan['actions'][i]['quarantine'] for i in indices],
                    'quarantined_sha256': local.signature([state['entries'][i]['quarantined'] for i in indices]),
                    'versions': [state['entries'][i]['quarantined']['version_id'] for i in indices]}
        local.durable(output / 'manifest.json', manifest)
        return {'manifest': str(output / 'manifest.json'), 'files': len(indices)}


def finalize_history(store, directory, plan, state):
    # Unknown backend allocation cannot create a threshold-based registration.
    for project in sorted({a['project'] for a in plan['actions']}):
        key = project + 'PROJECT.md'
        try:
            ref = store.exists(key)
            if ref is None:
                continue
            if ref['object_length'] > 1024 * 1024:
                raise ValueError('Registration too large; review manually')
            with store.open(ref) as (stream, _):
                original = stream.read()
            records = []
            for phase in ('quarantine', 'restore', 'purge'):
                stages = {'quarantine': 'remove', 'restore': 'restore_remove', 'purge': 'purge'}
                events = [e for a, item in zip(plan['actions'], state['entries']) if a['project'] == project
                          for e in item['events'] if e['phase'] == stages[phase] and e['state'] == 'verified']
                if events:
                    records.append({'id': plan['operation_id'] + ':' + phase + ':' + str(len(events)),
                                    'date': max(e['time'] for e in events)[:10], 'phase': phase,
                                    'files': len(events), 'status': state['phases'].get(phase, {}).get('data_status', 'pending')})
            if not records:
                continue
            updated = local.update_cleanup_text(original, records)
            if updated != original:
                attrs = ref['attributes']
                backup = directory / ('registration-' + inv.digest(key.encode()) + '.backup')
                if not backup.exists():
                    with backup.open('xb') as stream:
                        stream.write(original); stream.flush()
                        os.fsync(stream.fileno())
                    local.sync_directories(directory)
                store.call('put_object', key, content=updated, if_match=ref['etag'], **store.write_attributes(attrs))
                after = store.inspect(key)
                if after['attributes'] != attrs:
                    raise ValueError('TOS registration attributes changed; preserve backup and review')
                with store.open(after) as (stream, _):
                    if stream.read() != updated:
                        raise ValueError('TOS registration read-back failed')
            state.setdefault('registration', {})[project] = 'history_verified_allocation_pending'
        except (ValueError, OSError, RuntimeError, UnicodeError) as exc:
            state.setdefault('registration', {})[project] = 'pending: ' + str(exc)


def report_cleanup(operation, store=None):
    directory = local.private_directory(operation)
    with local.locks([directory]):
        directory, plan, state = read_operation(directory)
        store = session(directory, plan, state, store)
        for action, entry in zip(plan['actions'], state['entries']):
            if entry['status'] in {'quarantined', 'restored'}:
                store.verify(entry[entry['status']], current=True)
            elif entry['status'] == 'purged' and store.exists(action['quarantine'], entry['quarantined']['version_id']):
                raise ValueError('Purged TOS object version reappeared')
        if not any(e['status'].endswith('_intent') for e in state['entries']):
            finalize_history(store, directory, plan, state)
        return report(directory, plan, state)
