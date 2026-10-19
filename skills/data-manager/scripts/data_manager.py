#!/usr/bin/env python3
"""Inventory managed storage, register projects, and execute reviewed local cleanup."""
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import sys
import tarfile
import zipfile
import lzma

from inventory import RUNTIME_MARKER, aggregate, connect, discover, dump, is_runtime, meta, no_symlink_path, read_config, scan, within
from registration import apply, plan, read_metadata
import content as contents
import cleanup


def write_csv(path, fields, rows):
    no_symlink_path(path)
    with Path(path).open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader(); w.writerows(rows)


def display(value):
    return str(value).replace('|', '\\|').replace('\n', '<br>').replace('\r', '')


def report(run):
    db = connect(run)
    if meta(db, 'aggregation_status') != 'complete':
        db.close(); aggregate(run); db = connect(run)
    try:
        c = meta(db, 'config'); run = Path(run)
        runtime = contents.runtime_roots(c)
        runtime += [str(Path(r['path']).parent) for r in db.execute('SELECT path FROM nodes WHERE kind="file"')
                    if Path(r['path']).name == RUNTIME_MARKER and is_runtime(Path(r['path']).parent)]
        measures = {r['path']: dict(r) for r in db.execute('SELECT * FROM measures')}
        issues = [dict(r) for r in db.execute('SELECT * FROM issues ORDER BY path,kind')]
        tasks = {r['path']: r['state'] for r in db.execute('SELECT path,state FROM tasks')}
        projects, unassigned = [], []
        project_roots = [p['path'] for p in c['projects']]
        containers = set(c['containers']) | {r['path'] for r in c['managed_roots'] if r['path'] not in project_roots}
        sources = {r['path']: r['allocation_source'] for r in db.execute('SELECT path,allocation_source FROM nodes')}
        for p in c['projects']:
            row = dict(measures.get(p['path'], {'path': p['path'], 'allocated': 0, 'business_allocated': 0,
                         'excluded_allocated': 0, 'logical': 0, 'files': 0, 'unknown': 1, 'errors': 1}))
            row['project_id'] = p.get('project_id', '')
            row['ownership_evidence'] = p['evidence']
            row['allocation_source'] = sources.get(p['path'], 'unknown')
            row['scan_status'] = 'complete' if not row['errors'] and not row['unknown'] else 'partial_or_unknown'
            row['required'] = row['business_allocated'] > c['threshold_bytes'] if row['scan_status'] == 'complete' else None
            try:
                content, _ = read_metadata(Path(p['path']) / 'PROJECT.md')
                row['registration_status'] = 'existing_unverified' if content is not None else ('required_missing' if row['required'] else 'not_required')
            except (OSError, ValueError):
                row['registration_status'] = 'unreadable'
            if row['required'] is None:
                row['registration_status'] = 'pending_measurement'
            projects.append(row)
        # Verify results against current files, not only against historical success flags.
        import hashlib
        result_files = sorted((run / 'plans').glob('*/results.json'), key=lambda f: f.stat().st_mtime_ns) if (run / 'plans').exists() else []
        current_results = {}
        for f in result_files:
            for result in json.loads(f.read_text())['results']:
                current_results[result['target']] = result
        for p in projects:
            target = p['path'] + '/PROJECT.md'; result = current_results.get(target)
            if result and result['status'] == 'verified' and result['operation'] == 'write':
                try:
                    content, _ = read_metadata(target)
                    good = content is not None and hashlib.sha256(content).hexdigest() == result['after_sha256']
                except (OSError, ValueError):
                    good = False
                if p['scan_status'] == 'complete':
                    p['registration_status'] = 'verified' if good else 'changed_since_verification'
        for container in sorted(containers):
            # Direct loose files are never silently assigned to the whole home.
            if any(within(container, r) for r in runtime):
                continue
            files = [f for f in db.execute('SELECT * FROM nodes WHERE parent=? AND kind!="directory"', (container,))
                     if not any(within(f['path'], r) for r in runtime)]
            unique = {}
            for f in files:
                previous = unique.get(f['identity'])
                if previous is None or (previous['excluded'] and not f['excluded']):
                    unique[f['identity']] = f
            business = sum(f['allocated'] or 0 for f in unique.values() if not f['excluded'])
            if files:
                unassigned.append({'path': container, 'kind': 'loose_files', 'files': len(files),
                                   'logical': sum(f['logical'] for f in files), 'business_allocated': business,
                                   'unknown': sum(f['allocated'] is None for f in unique.values()),
                                   'registration_status': 'pending_project_boundary' if business > c['threshold_bytes'] else 'below_threshold_unassigned'})
            for child in db.execute('SELECT path,excluded FROM nodes WHERE parent=? AND kind="directory"', (container,)):
                path = child['path']
                if path in containers or any(within(path, r) for r in project_roots + runtime) or child['excluded']:
                    continue
                row = measures.get(path)
                if row:
                    unassigned.append(dict(row, kind='directory_candidate', registration_status='pending_project_boundary'))
        dump(run / 'projects.json', projects)
        dump(run / 'unassigned.json', unassigned)
        dump(run / 'issues.json', issues)
        common = ['path', 'allocated', 'excluded_allocated', 'business_allocated', 'logical', 'files', 'unknown', 'errors']
        write_csv(run / 'all_directories.csv', common, [r for p, r in sorted(measures.items()) if p != '@global'])
        write_csv(run / 'projects.csv', common + ['project_id', 'ownership_evidence', 'allocation_source', 'scan_status', 'required', 'registration_status'], projects)
        global_row = measures.get('@global', {})
        unresolved = bool(unassigned and any(u.get('business_allocated', 0) > c['threshold_bytes'] or u.get('unknown', 0) for u in unassigned))
        bad_registration = any(p['registration_status'] in {'required_missing', 'pending_measurement', 'unreadable', 'changed_since_verification', 'existing_unverified'} or
                               (p['required'] and p['registration_status'] != 'verified') for p in projects)
        summary = {'scope': 'confirmed_managed_roots', 'scan_status': meta(db, 'scan_status'),
                   'discovery_coverage': 'not_implied_by_inventory', 'registration_status': 'pending' if unresolved or bad_registration else 'complete',
                   'started': meta(db, 'started'), 'finished': meta(db, 'finished'),
                   'threshold_bytes': c['threshold_bytes'], 'global': global_row,
                   'managed_roots': c['managed_roots'], 'mount_aliases': meta(db, 'aliases'),
                   'project_count': len(projects), 'required_count': sum(p['required'] is True for p in projects),
                   'verified_count': sum(p['registration_status'] == 'verified' for p in projects),
                   'unassigned_count': len(unassigned)}
        summary['cleanup_runtime_roots'] = runtime
        if summary['scan_status'] != 'complete':
            summary['registration_status'] = 'pending'
        dump(run / 'summary.json', summary)
        lines = ['# 存储盘点报告', '', f'统计状态：{summary["scan_status"]}；登记状态：{summary["registration_status"]}。',
                 f'采集时间：{summary["started"]} 至 {summary["finished"] or "尚未完成"}。这是动态快照，不是冻结文件系统。', '',
                 '## 口径', '', '阈值依据：业务占用严格超过 ' + str(c['threshold_bytes']) + ' 字节。GB 使用十进制。',
                 '逻辑大小按路径统计；分配占用在目录内去重可靠 inode 的硬链接。整体去重总量另算，项目及父子目录不能直接相加。',
                 '远端数据使用挂载报告占用，不等于后端实际物理空间或云端计费容量；未知值不以逻辑大小替代。',
                 '环境/缓存只有经证据确认才扣除；盘点不执行清理，不刷新最近清理日期。',
                 '管理范围中的隔离内容仍计入整体占用，隔离根与清理运行目录不列为待归属项目；清理报告单列隔离占用。', '',
                 '## 管理范围', '', '| 目录 | 归属证据 | 总占用 GB | 业务占用 GB | 统计状态 |', '|---|---|---:|---:|---|']
        for r in c['managed_roots']:
            row = measures.get(r['path'])
            alias = next((a for a in (meta(db, 'aliases') or []) if a['path'] == r['path']), None)
            if alias:
                lines.append(f'| {display(r["path"])} | 挂载别名，见 {display(alias["canonical"])} | — | — | 不重复累计 |')
            else:
                status = 'complete' if row and not row['errors'] and not row['unknown'] else 'partial_or_unknown'
                a = f'{row["allocated"]/1e9:.3f}' if row else '未知'
                b = f'{row["business_allocated"]/1e9:.3f}' if row else '未知'
                lines.append(f'| {display(r["path"])} | {display(r["evidence"])} | {a} | {b} | {status} |')
        if global_row:
            lines += ['', f'已观察内容的整体去重总占用：{global_row["allocated"]/1e9:.3f} GB；业务占用：{global_row["business_allocated"]/1e9:.3f} GB。未读取内容不计作零大小。']
        lines += ['', '## 项目存储副本', '', '| 目录 | 总占用 GB | 排除 GB | 业务 GB | 逻辑 GB | 登记状态 |', '|---|---:|---:|---:|---:|---|']
        for p in sorted(projects, key=lambda p: p['business_allocated'], reverse=True):
            nums = ' | '.join(f'{p[k]/1e9:.3f}' for k in ('allocated', 'excluded_allocated', 'business_allocated', 'logical'))
            lines.append(f'| {display(p["path"])} | {nums} | {p["registration_status"]} |')
        lines += ['', '## 待归入项目的内容', '', '| 路径 | 类型 | 已观察业务占用 GB | 状态 |', '|---|---|---:|---|']
        for u in unassigned:
            lines.append(f'| {display(u["path"])} | {u["kind"]} | {u.get("business_allocated",0)/1e9:.3f} | {u["registration_status"]} |')
        lines += ['', '## 覆盖与限制', '',
                  '本报告只证明已配置管理范围的统计情况，不证明所有磁盘的未知归属目录已排查。发现覆盖、归属证据与统计完成分别记录。',
                  f'本次记录 {len(issues)} 条分类、排除或读取事件；详见 issues.json。未知分类保留在业务占用中。',
                  '中断恢复沿用已完成检查点，可能跨越较长采集时间；需要全新快照时使用新的输出目录。', '',
                  '项目明细：projects.csv；全层级大小：all_directories.csv；运行摘要：summary.json；未归属内容：unassigned.json。',
                  '登记草稿、备份和执行证据位于 plans/。仅存在 PROJECT.md 不代表本次已成功核验。']
        destination = run / 'REPORT.md'; no_symlink_path(destination)
        destination.write_text('\n'.join(lines) + '\n')
        return summary
    finally:
        db.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('discover', help='Inspect mounted storage and collect unconfirmed ownership candidates')
    p.add_argument('--config'); p.add_argument('--output', required=True)
    p.add_argument('--full', action='store_true', help='Search all accessible directories outside known/excluded scopes')
    p.add_argument('--max-depth', type=int, default=2, help='Mount-check depth; ignored with --full')
    p = sub.add_parser('scan', help='Read metadata in confirmed managed roots; never clean business data')
    p.add_argument('--config', required=True); p.add_argument('--output', required=True); p.add_argument('--resume', action='store_true')
    p = sub.add_parser('plan-register', help='Prepare drafts and expected-original fingerprints')
    p.add_argument('--run', required=True)
    p.add_argument('--archive-registration', action='append', default=[], metavar='PROJECT_MD', help='Explicit redundant metadata path to back up and remove; never a business file')
    p = sub.add_parser('apply-register', help='Apply an authorized, reviewed metadata manifest')
    p.add_argument('--manifest', required=True); p.add_argument('--allow-registration-archive', action='store_true')
    p = sub.add_parser('report', help='Regenerate reports and read back previously verified registrations')
    p.add_argument('--run', required=True)
    p = sub.add_parser('find-duplicates', help='Read-only whole-content and archive-member verification')
    p.add_argument('--run', required=True); p.add_argument('--output', required=True)
    p.add_argument('--max-expanded', type=int, default=contents.MAX_EXPANDED)
    p.add_argument('--max-members', type=int, default=contents.MAX_MEMBERS)
    p = sub.add_parser('plan-cleanup', help='Prepare exact reviewed quarantine actions')
    p.add_argument('--duplicates', required=True); p.add_argument('--selection', required=True); p.add_argument('--output', required=True)
    p = sub.add_parser('apply-cleanup', help='Quarantine an authorized manifest; stop all related writers first')
    p.add_argument('--manifest', required=True)
    p = sub.add_parser('restore-cleanup', help='Restore verified isolated files without overwriting; stop writers first')
    p.add_argument('--operation', required=True)
    p = sub.add_parser('plan-purge', help='Prepare a separately reviewed permanent purge set')
    p.add_argument('--cleanup', required=True); p.add_argument('--output', required=True)
    p = sub.add_parser('purge', help='Permanently delete only the explicitly authorized quarantine set; stop writers first')
    p.add_argument('--manifest', required=True)
    p = sub.add_parser('report-cleanup', help='Verify current cleanup results and retry only measurement/registration finalization')
    p.add_argument('--operation', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'discover':
            if args.max_depth < 1:
                raise ValueError('--max-depth must be positive')
            result = discover(read_config(args.config), os.path.abspath(args.output), args.full, args.max_depth)
        elif args.command == 'scan':
            scan(read_config(args.config), args.output, args.resume)
            result = report(args.output)
        elif args.command == 'plan-register':
            result = {'manifest': str(plan(args.run, args.archive_registration))}
        elif args.command == 'apply-register':
            result = apply(args.manifest, args.allow_registration_archive)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 1 if any(r['status'] != 'verified' for r in result['results']) else 0
        elif args.command == 'find-duplicates':
            if args.max_expanded < 1 or args.max_members < 1:
                raise ValueError('Archive limits must be positive')
            result = contents.find_duplicates(args.run, args.output, args.max_expanded, args.max_members)
        elif args.command == 'plan-cleanup':
            result = cleanup.plan_cleanup(args.duplicates, args.selection, args.output)
        elif args.command == 'apply-cleanup':
            manifest = Path(args.manifest).absolute()
            if manifest.name != 'manifest.json':
                raise ValueError('Expected the operation manifest.json')
            result = cleanup.execute(manifest.parent)
        elif args.command == 'restore-cleanup':
            result = cleanup.execute(args.operation, 'restore')
        elif args.command == 'plan-purge':
            result = cleanup.plan_purge(args.cleanup, args.output)
        elif args.command == 'purge':
            manifest = cleanup.load(args.manifest)
            result = cleanup.execute(manifest['operation'], 'purge', manifest)
        elif args.command == 'report-cleanup':
            result = cleanup.report_cleanup(args.operation)
        else:
            result = report(args.run)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.command in {'scan', 'report'} and result['scan_status'] != 'complete':
            return 2
        if args.command == 'find-duplicates' and result['status'] != 'complete':
            return 2
        if args.command in {'apply-cleanup', 'restore-cleanup', 'purge', 'report-cleanup'} and result['status'] != 'complete':
            return 2
        return 0
    except KeyboardInterrupt:
        if args.command in {'apply-cleanup', 'restore-cleanup', 'purge', 'report-cleanup'}:
            print('Interrupted. Inspect the preserved operation state; uncertain mutation intentions require manual recovery.', file=sys.stderr)
        else:
            print('Interrupted. Capacity scan checkpoints may be resumed with the identical profile; detection uses a fresh output directory.', file=sys.stderr)
        return 130
    except (ValueError, OSError, KeyError, TypeError, EOFError, RuntimeError, tarfile.TarError, zipfile.BadZipFile, lzma.LZMAError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
