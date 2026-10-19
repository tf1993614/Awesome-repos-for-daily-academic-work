import bz2
import gzip
import io
import json
import lzma
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import cleanup
import content
import data_manager as cli
import inventory as inv
import registration as reg


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='data-manager-cleanup-')
        self.base = Path(self.temp.name)
        self.root = self.base / 'managed'; self.root.mkdir()
        self.project = self.root / 'project'; self.project.mkdir()
        self.q = self.root / 'quarantine'; self.q.mkdir(mode=0o700)
        self.profile = self.base / 'profile.json'
        self.profile.write_text(json.dumps({'schema_version': 1, 'owner': 'test',
            'managed_roots': [{'path': str(self.root), 'evidence': 'test'}],
            'projects': [{'path': str(self.project), 'evidence': 'test'}],
            'containers': [str(self.root)], 'threshold_bytes': 10 ** 12}))
        self.config = inv.read_config(self.profile)
        self.serial = 0
        # These fixtures are non-Git even when /tmp has unrelated Git metadata.
        git = patch.object(reg, 'git_context', return_value=(False, False))
        git.start(); self.addCleanup(git.stop)

    def tearDown(self):
        self.temp.cleanup()

    def path(self, name):
        self.serial += 1
        return self.base / (name + '-' + str(self.serial))

    def write(self, name, data=b'biological data\n' * 4096):
        path = self.project / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data); return path

    def detect(self):
        run = self.path('scan'); inv.scan(self.config, run)
        output = self.path('duplicates'); content.find_duplicates(run, output)
        return output

    def selection(self, output, pairs):
        data = cleanup.load(output / 'duplicates.json')
        actions = []
        for target, keeper, member in pairs:
            match = next(m for m in data['matches'] if m['target']['path'] == str(target)
                         and m['keeper']['path'] == str(keeper) and m['keeper'].get('member') == member)
            actions.append({'target': str(target), 'keeper': {k: match['keeper'][k] for k in ('kind', 'path', 'member')},
                            'quarantine_root': str(self.q), 'reason': 'Reviewed redundant data',
                            'role': 'redundant_data', 'attributes_reviewed': True})
        result = self.path('selection').with_suffix('.json')
        result.write_text(json.dumps({'schema_version': 1, 'writers_stopped': True, 'actions': actions}))
        return result

    def plan(self, target, keeper, member=None):
        output = self.detect(); selected = self.selection(output, [(target, keeper, member)])
        directory = self.path('operation')
        cleanup.plan_cleanup(output, selected, directory)
        return directory

    def test_plain_quarantine_restore_and_idempotency(self):
        target = self.write('working.bin'); keeper = self.write('retained.bin')
        original = target.read_bytes(); op = self.plan(target, keeper)
        report = cleanup.execute(op)
        self.assertEqual(report['status'], 'complete', report)
        self.assertFalse(target.exists()); self.assertEqual(keeper.read_bytes(), original)
        quarantine = Path(cleanup.load(op / 'manifest.json')['actions'][0]['quarantine'])
        self.assertEqual(quarantine.read_bytes(), original)
        identity = quarantine.stat().st_ino
        self.assertEqual(cleanup.execute(op)['status'], 'complete')
        self.assertEqual(quarantine.stat().st_ino, identity)
        self.assertEqual(cleanup.execute(op, 'restore')['status'], 'complete')
        self.assertEqual(target.read_bytes(), original); self.assertFalse(quarantine.exists())
        self.assertEqual(cleanup.execute(op, 'restore')['status'], 'complete')
        self.assertIsNone(report['verified_storage_release_bytes'])
        self.assertFalse((self.project / 'PROJECT.md').exists())

    def test_compressed_quarantine_and_separately_bound_purge(self):
        target = self.write('sample.fastq'); keeper = self.write('sample.fastq.gz', gzip.compress(target.read_bytes()))
        op = self.plan(target, keeper)
        self.assertEqual(cleanup.execute(op)['status'], 'complete')
        purge_dir = self.path('purge'); cleanup.plan_purge(op, purge_dir)
        manifest = cleanup.load(purge_dir / 'manifest.json')
        self.assertEqual(cleanup.execute(op, 'purge', manifest)['status'], 'complete')
        self.assertTrue(keeper.exists())
        self.assertFalse(Path(manifest['paths'][0]).exists())
        self.assertEqual(cleanup.execute(op, 'purge', manifest)['status'], 'complete')

    def test_purge_manifest_displayed_paths_must_match_execution(self):
        a = self.write('a'); b = self.write('b'); op = self.plan(a, b); cleanup.execute(op)
        purge = self.path('purge'); cleanup.plan_purge(op, purge)
        manifest = cleanup.load(purge / 'manifest.json')
        manifest['paths'] = [str(self.base / 'unrelated')]
        with self.assertRaises(ValueError):
            cleanup.execute(op, 'purge', manifest)
        q = cleanup.load(op / 'manifest.json')['actions'][0]['quarantine']
        self.assertTrue(Path(q).exists())

    def test_all_standard_archive_formats(self):
        data = b'ACGT' * 1000
        for suffix, compress in [('gz', gzip.compress), ('bz2', bz2.compress), ('xz', lzma.compress)]:
            with self.subTest(suffix=suffix):
                path = self.write('single.' + suffix, compress(data))
                ref = content.archive_evidence(path)[0]
                self.assertEqual(ref['length'], len(data)); self.assertEqual(ref['sha256'], inv.digest(data))
        for suffix, mode in [('tar', 'w'), ('tar.gz', 'w:gz'), ('tar.bz2', 'w:bz2'), ('tar.xz', 'w:xz')]:
            with self.subTest(suffix=suffix):
                path = self.project / ('bundle.' + suffix)
                with tarfile.open(path, mode) as archive:
                    info = tarfile.TarInfo('nested/sample.bin'); info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                refs = content.archive_evidence(path)
                ref = next(r for r in refs if r['kind'] == 'member')
                self.assertEqual(ref['sha256'], inv.digest(data))
                if suffix != 'tar':
                    self.assertTrue(any(r['kind'] == 'payload' for r in refs))
        path = self.project / 'bundle.zip'
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('nested/sample.bin', data)
        self.assertEqual(content.archive_evidence(path)[0]['sha256'], inv.digest(data))

    def test_tar_payload_matches_uncompressed_tar(self):
        raw = self.project / 'bundle.tar'
        with tarfile.open(raw, 'w') as archive:
            info = tarfile.TarInfo('data'); info.size = 4; archive.addfile(info, io.BytesIO(b'ACGT'))
        compressed = self.write('bundle.tar.gz', gzip.compress(raw.read_bytes()))
        output = self.detect(); matches = cleanup.load(output / 'duplicates.json')['matches']
        self.assertTrue(any(m['target']['path'] == str(raw) and m['keeper']['path'] == str(compressed)
                            and m['keeper']['kind'] == 'payload' for m in matches))

    def test_tar_dot_root_is_valid(self):
        data = self.project / 'extracted'; data.mkdir()
        (data / 'data').write_bytes(b'ACGT')
        path = self.project / 'dot-root.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            archive.add(data, arcname='.')
        refs = content.archive_evidence(path)
        self.assertEqual(next(r for r in refs if r['kind'] == 'member')['member'], 'data')
        self.detect()

    def test_member_partial_match_leaves_modified_and_new_files(self):
        target = self.write('extracted/matching', b'AAA'); modified = self.write('extracted/changed', b'new')
        added = self.write('extracted/added', b'CCC')
        keeper = self.project / 'archive.zip'
        with zipfile.ZipFile(keeper, 'w') as archive:
            archive.writestr('matching', b'AAA'); archive.writestr('changed', b'old')
        op = self.plan(target, keeper, 'matching')
        self.assertEqual(cleanup.execute(op)['status'], 'complete')
        self.assertTrue(modified.exists()); self.assertTrue(added.exists()); self.assertFalse(target.exists())

    def test_equal_lengths_different_contents_and_hardlinks(self):
        a = self.write('a', b'AAAA'); b = self.write('b', b'BBBB')
        linked = self.project / 'link'; os.link(a, linked)
        output = self.detect(); result = cleanup.load(output / 'duplicates.json')
        self.assertEqual(len(result['hardlinks']), 2)
        self.assertFalse(any(m['target']['path'] in {str(a), str(linked)} for m in result['matches']))
        self.assertFalse(any(m['keeper']['path'] == str(b) for m in result['matches']))

    def test_fifo_and_symlink_never_read(self):
        fifo = self.project / 'pipe'; os.mkfifo(fifo)
        target = self.write('target'); (self.project / 'symlink').symlink_to(target)
        with self.assertRaises(ValueError):
            content.file_evidence(fifo)
        output = self.detect(); result = cleanup.load(output / 'duplicates.json')
        self.assertTrue(any(i['path'] == str(fifo) for i in result['issues']))

    def test_archive_limits_unsafe_duplicate_and_corrupt_members(self):
        keeper = self.write('big.gz', gzip.compress(b'x' * 1024))
        with self.assertRaises(ValueError):
            content.archive_evidence(keeper, max_expanded=512)
        for name in ['../escape', '/absolute', 'a\\b']:
            path = self.project / 'unsafe.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr(name, b'x')
            with self.assertRaises(ValueError):
                content.archive_evidence(path)
        path = self.project / 'members.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('one', b'x'); archive.writestr('two', b'y')
        with self.assertRaises(ValueError):
            content.archive_evidence(path, max_members=1)
        # Corrupt an unrelated member: the selected valid member is insufficient.
        raw = path.read_bytes().replace(b'y', b'z', 1); path.write_bytes(raw)
        with self.assertRaises((zipfile.BadZipFile, ValueError)):
            content.archive_evidence(path)
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('encrypted', b'ACGT')
        raw = bytearray(path.read_bytes())
        central = raw.index(b'PK\x01\x02'); raw[central + 8] |= 1
        path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'Encrypted'):
            content.archive_evidence(path)
        with zipfile.ZipFile(path, 'w') as archive:
            link = zipfile.ZipInfo('link'); link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, 'target')
        with self.assertRaisesRegex(ValueError, 'Non-regular'):
            content.archive_evidence(path)

    def test_preflight_changed_target_or_keeper_prevents_mutation(self):
        for changed in ['target', 'keeper']:
            with self.subTest(changed=changed):
                target = self.write('target-' + changed); keeper = self.write('keeper-' + changed)
                op = self.plan(target, keeper)
                (target if changed == 'target' else keeper).write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    cleanup.execute(op)
                self.assertTrue(target.exists())

    def test_restore_conflict_and_missing_keeper_prevent_mutation(self):
        target = self.write('target'); keeper = self.write('keeper'); op = self.plan(target, keeper)
        cleanup.execute(op); target.write_bytes(b'new file')
        with self.assertRaises(ValueError):
            cleanup.execute(op, 'restore')
        self.assertEqual(target.read_bytes(), b'new file')
        keeper.unlink()
        with self.assertRaises(OSError):
            cleanup.plan_purge(op, self.path('purge'))

    def test_restore_rescues_quarantine_when_keeper_is_missing(self):
        target = self.write('target'); keeper = self.write('keeper')
        original = target.read_bytes(); op = self.plan(target, keeper)
        cleanup.execute(op); keeper.unlink()
        self.assertEqual(cleanup.execute(op, 'restore')['status'], 'complete')
        self.assertEqual(target.read_bytes(), original)

    def test_registry_rejects_business_json_and_wrong_kind(self):
        target = self.write('target'); keeper = self.write('keeper'); op = self.plan(target, keeper)
        plan = cleanup.load(op / 'manifest.json')
        business = self.write('business.json', b'{"quarantine_roots": [], "runtime_paths": [], "data": 17}')
        original = business.read_bytes(); plan['registry'] = str(business)
        with self.assertRaises(ValueError):
            cleanup.validate_registry(plan)
        self.assertEqual(business.read_bytes(), original)
        outside = self.base / 'unrelated.json'; outside.write_bytes(original)
        plan['registry'] = str(outside)
        with self.assertRaises(ValueError):
            cleanup.validate_registry(plan)
        self.assertEqual(outside.read_bytes(), original)

    def test_known_unstarted_entries_resume_without_repeating_verified_moves(self):
        first = self.write('first'); second = self.write('second'); keeper = self.write('keeper')
        output = self.detect(); selected = self.selection(output, [(first, keeper, None), (second, keeper, None)])
        op = self.path('operation'); cleanup.plan_cleanup(output, selected, op)
        actual = cleanup.verify_location
        calls = 0
        def transient(action, entry, phase):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError('temporary pre-mutation error')
            return actual(action, entry, phase)
        with patch.object(cleanup, 'verify_location', side_effect=transient):
            report = cleanup.execute(op)
        self.assertEqual(report['status'], 'pending')
        self.assertFalse(first.exists()); self.assertTrue(second.exists())
        moved = cleanup.load(op / 'state.json')['entries'][0]['quarantined']['fingerprint']
        self.assertEqual(cleanup.execute(op)['status'], 'complete')
        self.assertEqual(cleanup.load(op / 'state.json')['entries'][0]['quarantined']['fingerprint'], moved)
        self.assertFalse(second.exists())

    def test_remote_and_cross_mount_rejected(self):
        target = self.write('target'); keeper = self.write('keeper')
        output = self.detect(); selected = self.selection(output, [(target, keeper, None)])
        original = inv.mounts()
        remote = dict(inv.mount_for(str(keeper), original), target=str(keeper), fstype='nfs')
        with patch.object(inv, 'mounts', return_value=[remote, *original]):
            with self.assertRaises(ValueError):
                cleanup.plan_cleanup(output, selected, self.path('remote'))
        other = dict(inv.mount_for(str(self.q), original), target=str(self.q), source='other')
        with patch.object(inv, 'mounts', return_value=[other, *original]):
            with self.assertRaises(ValueError):
                cleanup.plan_cleanup(output, selected, self.path('cross-mount'))

    def test_retained_dependency_cannot_also_be_target(self):
        a = self.write('a'); b = self.write('b'); c = self.write('c')
        output = self.detect(); selection = self.selection(output, [(a, b, None), (b, c, None)])
        with self.assertRaises(ValueError):
            cleanup.plan_cleanup(output, selection, self.path('cycle'))
        self.assertTrue(a.exists()); self.assertTrue(b.exists())

    def test_unassigned_and_missing_writer_ack_rejected(self):
        a = self.write('a'); b = self.write('b'); output = self.detect()
        selected = self.selection(output, [(a, b, None)])
        value = cleanup.load(selected); value['writers_stopped'] = False; selected.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            cleanup.plan_cleanup(output, selected, self.path('no-ack'))
        with self.assertRaises(ValueError):
            cleanup.check_scope(str(self.root / 'loose'), self.config)

    def test_registration_history_preserved_once_per_phase(self):
        target = self.write('target'); keeper = self.write('keeper')
        metadata = self.project / 'PROJECT.md'
        text = reg.new_registration({'path': str(self.project)}, 'old owner', 'old scale')
        metadata.write_text(text.replace('未开始（本次仅盘点登记）', 'old cleaning event') + '\nManual text.\n')
        op = self.plan(target, keeper); report = cleanup.execute(op)
        self.assertEqual(report['status'], 'complete', report)
        content_before = metadata.read_text()
        self.assertIn('old cleaning event', content_before); self.assertIn('Manual text.', content_before)
        self.assertEqual(content_before.count('<!-- data-manager-cleanup:'), 1)
        cleanup.execute(op)
        self.assertEqual(metadata.read_text(), content_before)
        cleanup.execute(op, 'restore')
        self.assertEqual(metadata.read_text().count('<!-- data-manager-cleanup:'), 2)

    def test_finalization_failure_retries_without_repeating_mutation(self):
        a = self.write('a'); b = self.write('b'); op = self.plan(a, b)
        with patch.object(cleanup, 'finalize', side_effect=OSError('measurement unavailable')):
            report = cleanup.execute(op)
        self.assertEqual(report['status'], 'pending'); self.assertFalse(a.exists())
        with patch.object(cleanup, 'rename_noreplace', side_effect=AssertionError('repeated move')):
            self.assertEqual(cleanup.report_cleanup(op)['status'], 'complete')

    def test_uncertain_mutation_stops_and_keeps_intent(self):
        a = self.write('a'); b = self.write('b'); op = self.plan(a, b)
        actual = cleanup.rename_noreplace
        def interrupted(source, destination):
            actual(source, destination)
            raise KeyboardInterrupt()
        with patch.object(cleanup, 'rename_noreplace', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                cleanup.execute(op)
        state = cleanup.load(op / 'state.json')
        self.assertEqual(state['entries'][0]['status'], 'quarantine_intent')
        with self.assertRaises(ValueError):
            cleanup.execute(op)
        with self.assertRaises(ValueError):
            cleanup.plan_purge(op, self.path('purge'))

    def test_verified_files_recover_missing_batch_completion_marker(self):
        a = self.write('a'); b = self.write('b'); op = self.plan(a, b)
        save = cleanup.save_state
        def crash_after_files(directory, state):
            if state['phases'].get('quarantine', {}).get('data_status') == 'complete':
                raise KeyboardInterrupt()
            save(directory, state)
        with patch.object(cleanup, 'save_state', side_effect=crash_after_files):
            with self.assertRaises(KeyboardInterrupt):
                cleanup.execute(op)
        self.assertEqual(cleanup.load(op / 'state.json')['entries'][0]['status'], 'quarantined')
        with patch.object(cleanup, 'rename_noreplace', side_effect=AssertionError('duplicate move')):
            self.assertEqual(cleanup.report_cleanup(op)['status'], 'complete')
            self.assertEqual(cleanup.execute(op)['status'], 'complete')

    def test_manifest_tampering_after_execution_is_rejected(self):
        a = self.write('a'); b = self.write('b'); op = self.plan(a, b)
        cleanup.execute(op)
        path = op / 'manifest.json'; value = cleanup.load(path)
        value['actions'][0]['reason'] = 'changed'; path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            cleanup.execute(op)

    def test_unknown_state_is_rejected_in_report_and_execution(self):
        a = self.write('a'); b = self.write('b'); op = self.plan(a, b); cleanup.execute(op)
        path = op / 'state.json'; state = cleanup.load(path)
        state['entries'][0]['status'] = 'unknown_result'; path.write_text(json.dumps(state))
        for call in (lambda: cleanup.report_cleanup(op), lambda: cleanup.execute(op),
                     lambda: cleanup.plan_purge(op, self.path('purge'))):
            with self.assertRaises(ValueError):
                call()

    def test_report_detects_changed_registration_without_overwriting(self):
        a = self.write('a'); b = self.write('b')
        metadata = self.project / 'PROJECT.md'
        metadata.write_text(reg.new_registration({'path': str(self.project)}, 'test', 'old'))
        op = self.plan(a, b)
        self.assertEqual(cleanup.execute(op)['status'], 'complete')
        original = metadata.read_bytes()
        metadata.write_text('Manual replacement.\n')
        report = cleanup.report_cleanup(op)
        self.assertEqual(report['status'], 'pending')
        self.assertEqual(metadata.read_text(), 'Manual replacement.\n')
        metadata.write_bytes(original)
        self.assertEqual(cleanup.report_cleanup(op)['status'], 'complete')

    def test_quarantine_registry_excludes_future_detection_and_unassigned_candidates(self):
        a = self.write('a'); b = self.write('b'); op = self.plan(a, b); cleanup.execute(op)
        self.assertTrue(Path(self.config['cleanup_registry']).exists())
        output = self.detect(); result = cleanup.load(output / 'duplicates.json')
        self.assertFalse(any(inv.within(m['target']['path'], str(self.q)) for m in result['matches']))
        run = self.path('new-scan'); inv.scan(self.config, run); cli.report(run)
        unassigned = json.loads((run / 'unassigned.json').read_text())
        self.assertFalse(any(r['path'] == str(self.q) for r in unassigned))

    def test_historical_runtime_directory_is_not_a_duplicate_or_project_candidate(self):
        historical = self.root / 'historical-inventory'
        inv.scan(self.config, historical)
        first = historical / 'business-looking-file'; first.write_bytes(b'artifact')
        second = self.write('same-bytes', b'artifact')
        output = self.detect(); result = cleanup.load(output / 'duplicates.json')
        self.assertFalse(any(m['target']['path'] == str(second) and m['keeper']['path'] == str(first) for m in result['matches']))
        scan = self.path('report-scan'); inv.scan(self.config, scan); cli.report(scan)
        self.assertFalse(any(r['path'] == str(historical) for r in json.loads((scan / 'unassigned.json').read_text())))

    def test_sparse_file_purge_does_not_report_logical_length_as_allocation(self):
        sparse = self.project / 'sparse'
        with sparse.open('wb') as stream:
            stream.truncate(1024 * 1024)
        keeper = self.write('dense', b'\0' * (1024 * 1024))
        allocated = sparse.stat().st_blocks * 512
        op = self.plan(sparse, keeper); cleanup.execute(op)
        purge = self.path('purge'); cleanup.plan_purge(op, purge)
        report = cleanup.execute(op, 'purge', cleanup.load(purge / 'manifest.json'))
        self.assertEqual(report['purged_content_allocated_bytes'], allocated)
        self.assertIsNone(report['verified_storage_release_bytes'])

    def test_cli_compressed_lifecycle(self):
        target = self.write('reads.fastq'); keeper = self.write('reads.fastq.gz', gzip.compress(target.read_bytes()))
        script = Path(cli.__file__)
        def command(*args):
            result = subprocess.run([sys.executable, '-B', str(script), *map(str, args)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            return json.loads(result.stdout)
        for phase in ['restore', 'purge']:
            run = self.path('cli-scan'); duplicates = self.path('cli-detect'); operation = self.path('cli-operation')
            command('scan', '--config', self.profile, '--output', run)
            command('find-duplicates', '--run', run, '--output', duplicates)
            selection = self.selection(duplicates, [(target, keeper, None)])
            command('plan-cleanup', '--duplicates', duplicates, '--selection', selection, '--output', operation)
            self.assertEqual(command('apply-cleanup', '--manifest', operation / 'manifest.json')['status'], 'complete')
            self.assertEqual(command('report-cleanup', '--operation', operation)['status'], 'complete')
            if phase == 'restore':
                command('restore-cleanup', '--operation', operation)
                self.assertTrue(target.exists())
            else:
                purge = self.path('cli-purge')
                command('plan-purge', '--cleanup', operation, '--output', purge)
                command('purge', '--manifest', purge / 'manifest.json')
                self.assertFalse(target.exists()); self.assertTrue(keeper.exists())

    def test_above_threshold_new_registration_and_malformed_metadata(self):
        self.config['threshold_bytes'] = 0
        a = self.write('a'); b = self.write('b'); op = self.plan(a, b)
        self.assertEqual(cleanup.execute(op)['status'], 'complete')
        metadata = self.project / 'PROJECT.md'
        self.assertIn('data-manager-cleanup:', metadata.read_text())
        self.assertIn('quarantine:', metadata.read_text())
        metadata.write_text('Unrecognized manual metadata.\n')
        c = self.write('c'); op2 = self.plan(c, b)
        report = cleanup.execute(op2)
        self.assertEqual(report['status'], 'pending')
        self.assertFalse(c.exists())
        self.assertEqual(metadata.read_text(), 'Unrecognized manual metadata.\n')
        with patch.object(cleanup, 'rename_noreplace', side_effect=AssertionError('duplicate move')):
            self.assertEqual(cleanup.report_cleanup(op2)['status'], 'pending')


if __name__ == '__main__':
    unittest.main()
