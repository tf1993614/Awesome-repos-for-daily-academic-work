import errno
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import inventory as inv
import registration as reg
import data_manager as cli


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='data-manager-test-')
        self.base = Path(self.temp.name)
        self.root = self.base / 'managed'
        self.root.mkdir()
        self.a = self.root / 'A'; self.a.mkdir()
        self.profile = self.base / 'profile.json'
        self.config = self.configure()
        self.serial = 0

    def tearDown(self):
        self.temp.cleanup()

    def configure(self, projects=None, threshold=32768, **extra):
        raw = {'schema_version': 1, 'owner': 'test-owner', 'uid': os.getuid(),
               'managed_roots': [{'path': str(self.root), 'evidence': 'test ownership'}],
               'containers': [str(self.root)],
               'projects': [{'path': str(p), 'evidence': 'test boundary'} for p in (projects if projects is not None else [self.a])],
               'threshold_bytes': threshold, 'local_workers': 4, 'remote_workers': 4, **extra}
        self.profile.write_text(json.dumps(raw))
        return inv.read_config(self.profile)

    def data(self, path, size=65536):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'x' * size)
        return path

    def run_scan(self, config=None):
        self.serial += 1
        run = self.base / f'run-{self.serial}'
        inv.scan(config or self.config, run)
        cli.report(run)
        return run

    def measures(self, run, path):
        db = inv.connect(run)
        try:
            return dict(db.execute('SELECT * FROM measures WHERE path=?', (str(path),)).fetchone())
        finally:
            db.close()

    def old_registration(self, path):
        text = reg.new_registration({'path': str(path.parent), 'description': 'keep my description'}, 'original-owner', 'old capacity')
        text = text.replace('- 最近清理：无', '- 最近清理：2025-03-04').replace('- 清理情况：未开始（本次仅盘点登记）', '- 清理情况：previous cleanup preserved')
        path.write_text(text + '\nCustom paragraph.\n')
        return path.read_bytes()

    def test_project_root_preserves_history_and_idempotency(self):
        self.data(self.a / 'B' / '数据 file\nname.bin')
        original = self.old_registration(self.a / 'PROJECT.md')
        run = self.run_scan()
        manifest = reg.plan(run)
        result = reg.apply(manifest)
        self.assertTrue(all(r['status'] == 'verified' for r in result['results']))
        updated = (self.a / 'PROJECT.md').read_bytes()
        self.assertIn('2025-03-04'.encode(), updated)
        self.assertIn(b'previous cleanup preserved', updated)
        self.assertIn(b'Custom paragraph.', updated)
        self.assertEqual(original.split('- 数据规模：'.encode())[0], updated.split('- 数据规模：'.encode())[0])
        self.assertFalse((self.root / 'PROJECT.md').exists())
        self.assertFalse((self.a / 'B' / 'PROJECT.md').exists())
        mtime = (self.a / 'PROJECT.md').stat().st_mtime_ns
        reg.apply(manifest)
        self.assertEqual(mtime, (self.a / 'PROJECT.md').stat().st_mtime_ns)
        summary = cli.report(run)
        self.assertEqual(summary['verified_count'], 1)
        manifest2 = reg.plan(run)
        self.assertEqual(json.loads(manifest2.read_text())['actions'], [])

    def test_embedded_environment_excluded_and_name_only_retained(self):
        env = self.a / 'env'; (env / 'conda-meta').mkdir(parents=True)
        self.data(env / 'large', 100000)
        self.data(self.a / 'business', 20000)
        self.data(self.a / 'cache' / 'research-data', 10000)
        c = self.configure(threshold=80000)
        run = self.run_scan(c); row = self.measures(run, self.a)
        self.assertGreater(row['allocated'], 80000)
        self.assertLess(row['business_allocated'], 80000)
        self.assertGreater(row['excluded_allocated'], 100000)
        self.assertEqual(row['allocated'], row['business_allocated'] + row['excluded_allocated'])
        self.assertEqual(json.loads(reg.plan(run).read_text())['actions'], [])
        self.assertTrue(any(r['kind'] == 'classification_pending' for r in json.loads((run / 'issues.json').read_text())))

    def test_hardlinks_are_independent_and_order_invariant(self):
        b = self.root / 'B'; b.mkdir()
        shared = self.data(self.a / 'one')
        os.link(shared, b / 'two')
        c1 = self.configure(projects=[self.a, b], local_workers=1, remote_workers=1)
        r1 = self.run_scan(c1)
        c2 = self.configure(projects=[self.a, b], local_workers=4, remote_workers=4)
        r2 = self.run_scan(c2)
        for path in [self.a, b, self.root, '@global']:
            self.assertEqual(self.measures(r1, path), self.measures(r2, path))
        self.assertGreaterEqual(self.measures(r1, self.a)['allocated'], shared.stat().st_blocks * 512)
        self.assertGreaterEqual(self.measures(r1, b)['allocated'], shared.stat().st_blocks * 512)
        self.assertEqual(self.measures(r1, self.root)['logical'], 2 * shared.stat().st_size)
        self.assertLess(self.measures(r1, self.root)['allocated'], self.measures(r1, self.a)['allocated'] + self.measures(r1, b)['allocated'])

    def test_environment_hardlink_does_not_hide_business(self):
        env = self.a / 'env'; (env / 'conda-meta').mkdir(parents=True)
        f = self.data(env / 'shared')
        os.link(f, self.a / 'business')
        run = self.run_scan(); row = self.measures(run, self.a)
        self.assertGreaterEqual(row['business_allocated'], f.stat().st_blocks * 512)
        self.assertLess(row['excluded_allocated'], f.stat().st_blocks * 512)

    def test_sparse_file_does_not_trigger_logical_threshold(self):
        f = self.a / 'sparse'
        with f.open('wb') as stream:
            stream.truncate(1_000_000_000_000)
        c = self.configure(threshold=100_000_000_000)
        run = self.run_scan(c)
        self.assertGreater(self.measures(run, self.a)['logical'], c['threshold_bytes'])
        self.assertEqual(json.loads(reg.plan(run).read_text())['actions'], [])

    def test_strict_threshold_and_below_threshold_existing_record(self):
        self.data(self.a / 'business')
        run = self.run_scan(); exact = self.measures(run, self.a)['business_allocated']
        equal = self.run_scan(self.configure(threshold=exact))
        self.assertEqual(json.loads(reg.plan(equal).read_text())['actions'], [])
        self.old_registration(self.a / 'PROJECT.md')
        below = self.run_scan(self.configure(threshold=10**12))
        actions = json.loads(reg.plan(below).read_text())['actions']
        self.assertEqual([a['target'] for a in actions], [str(self.a / 'PROJECT.md')])

    def test_loose_files_and_unconfirmed_boundary(self):
        self.data(self.root / 'loose')
        self.data(self.root / 'projects' / 'new-project' / 'data')
        run = self.run_scan(self.configure(projects=[]))
        self.assertEqual(cli.report(run)['registration_status'], 'pending')
        items = json.loads((run / 'unassigned.json').read_text())
        self.assertEqual({r['kind'] for r in items}, {'loose_files', 'directory_candidate'})
        self.assertEqual(json.loads(reg.plan(run).read_text())['actions'], [])
        self.assertFalse((self.root / 'PROJECT.md').exists())

    def test_unknown_allocation_blocks_registration(self):
        self.data(self.a / 'data'); run = self.run_scan()
        db = inv.connect(run)
        db.execute('UPDATE nodes SET allocated=NULL,allocation_source="unknown" WHERE path=?', (str(self.a / 'data'),))
        db.commit(); db.close(); inv.aggregate(run)
        summary = cli.report(run)
        self.assertEqual(summary['registration_status'], 'pending')
        manifest = json.loads(reg.plan(run).read_text())
        self.assertEqual(manifest['actions'], [])
        self.assertTrue(manifest['pending'])

    def test_partial_read_and_resume(self):
        self.data(self.a / 'data')
        real = inv.inspect_directory
        def denied(p, *args):
            if p == str(self.a):
                return [], [], [(p, 'read_error', 'permission denied fixture')]
            return real(p, *args)
        with patch.object(inv, 'inspect_directory', side_effect=denied):
            run = self.run_scan()
        self.assertEqual(cli.report(run)['scan_status'], 'partial')
        self.assertEqual(json.loads(reg.plan(run).read_text())['actions'], [])
        inv.scan(self.config, run, resume=True)
        self.assertEqual(cli.report(run)['scan_status'], 'complete')
        self.assertTrue(json.loads(reg.plan(run).read_text())['actions'])

    def test_symlink_not_followed_and_metadata_redirect_rejected(self):
        outside = self.data(self.base / 'outside' / 'data', 131072)
        (self.a / 'linked').symlink_to(outside.parent, target_is_directory=True)
        self.data(self.a / 'own')
        run = self.run_scan()
        self.assertLess(self.measures(run, self.a)['logical'], outside.stat().st_size)
        manifest = reg.plan(run)
        victim = self.base / 'victim'; victim.write_text('do not change')
        (self.a / 'PROJECT.md').symlink_to(victim)
        with self.assertRaises((OSError, ValueError)):
            reg.apply(manifest)
        self.assertEqual(victim.read_text(), 'do not change')

    def test_conflicts_are_preflighted_before_any_write(self):
        b = self.root / 'B'; b.mkdir()
        self.data(self.a / 'data'); self.data(b / 'data')
        run = self.run_scan(self.configure(projects=[self.a, b]))
        manifest = reg.plan(run)
        (b / 'PROJECT.md').write_text('concurrent author')
        with self.assertRaises(ValueError):
            reg.apply(manifest)
        self.assertFalse((self.a / 'PROJECT.md').exists())
        self.assertEqual((b / 'PROJECT.md').read_text(), 'concurrent author')

    def test_unknown_metadata_is_preserved(self):
        self.data(self.a / 'data')
        p = self.a / 'PROJECT.md'; p.write_text('Manual notes, custom unknown format.')
        run = self.run_scan(); manifest = json.loads(reg.plan(run).read_text())
        self.assertEqual(manifest['actions'], [])
        self.assertEqual(len(manifest['pending']), 1)
        self.assertEqual(p.read_text(), 'Manual notes, custom unknown format.')

    def test_archive_is_explicit_and_backed_up(self):
        self.data(self.a / 'data')
        misplaced = self.root / 'PROJECT.md'; original = self.old_registration(misplaced)
        run = self.run_scan(); manifest = reg.plan(run, [str(misplaced)])
        with self.assertRaises(ValueError):
            reg.apply(manifest)
        self.assertTrue(misplaced.exists()); self.assertFalse((self.a / 'PROJECT.md').exists())
        result = reg.apply(manifest, allow_archive=True)
        archive = next(r for r in result['results'] if r['operation'] == 'archive_registration')
        self.assertFalse(misplaced.exists())
        self.assertEqual(Path(archive['backup']).read_bytes(), original)
        self.assertTrue((self.a / 'data').exists())
        with self.assertRaises(ValueError):
            reg.plan(run, [str(self.a / 'data')])

    @unittest.skipUnless(shutil.which('git'), 'git unavailable')
    def test_git_ignore_preserves_existing_rules(self):
        subprocess.run(['git', 'init', '-q', str(self.a)], check=True)
        (self.a / '.gitignore').write_text('important-original-rule\n')
        self.data(self.a / 'data'); run = self.run_scan()
        reg.apply(reg.plan(run))
        self.assertEqual((self.a / '.gitignore').read_text(), 'important-original-rule\n/PROJECT.md\n')
        self.assertEqual(subprocess.run(['git', '-C', str(self.a), 'check-ignore', '-q', 'PROJECT.md']).returncode, 0)

    @unittest.skipUnless(shutil.which('git'), 'git unavailable')
    def test_git_negation_is_overridden_by_final_rule(self):
        subprocess.run(['git', 'init', '-q', str(self.a)], check=True)
        (self.a / '.gitignore').write_text('/PROJECT.md\n!PROJECT.md\n')
        self.data(self.a / 'data'); run = self.run_scan()
        reg.apply(reg.plan(run))
        self.assertEqual((self.a / '.gitignore').read_text(), '/PROJECT.md\n!PROJECT.md\n/PROJECT.md\n')
        self.assertEqual(subprocess.run(['git', '-C', str(self.a), 'check-ignore', '-q', 'PROJECT.md']).returncode, 0)
        self.assertEqual(json.loads(reg.plan(run).read_text())['actions'], [])

    def test_private_metadata_and_backups_remain_private(self):
        self.data(self.a / 'data')
        target = self.a / 'PROJECT.md'; original = self.old_registration(target)
        target.chmod(0o600)
        run = self.run_scan(); result = reg.apply(reg.plan(run))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        backup = Path(result['results'][0]['backup'])
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(backup.parent.stat().st_mode), 0o700)
        self.assertEqual(backup.read_bytes(), original)

    def test_malformed_below_threshold_registration_stays_pending(self):
        (self.a / 'PROJECT.md').write_text('manual format')
        run = self.run_scan(self.configure(threshold=10**12))
        self.assertEqual(cli.report(run)['registration_status'], 'pending')
        self.assertTrue(json.loads(reg.plan(run).read_text())['pending'])

    def test_tos_recreation_and_original_restoration(self):
        self.data(self.a / 'data')
        original = self.old_registration(self.a / 'PROJECT.md')
        run = self.run_scan(); manifest = reg.plan(run)
        fake_mounts = [{'target': str(self.root), 'fstype': 'fuse.tosutil', 'root': '/', 'device': '1', 'source': 'fixture'}]
        with patch.object(reg, 'mounts', return_value=fake_mounts), patch.object(reg, 'atomic_write', side_effect=OSError(errno.EINVAL, 'unsupported')):
            result = reg.apply(manifest)
        self.assertEqual(result['results'][0]['status'], 'verified')
        self.assertEqual(result['results'][0]['method'], 'TOS exclusive recreation')
        self.assertNotEqual((self.a / 'PROJECT.md').read_bytes(), original)
        # A later failed recreation restores the previous original.
        old, fp = reg.read_metadata(self.a / 'PROJECT.md')
        action = {'before_sha256': inv.digest(old), 'before_fingerprint': list(fp)}
        real = reg.exclusive_create; calls = []
        def fail_first(fd, name, content, *args):
            calls.append(content)
            if len(calls) == 1:
                raise OSError('simulated write failure')
            return real(fd, name, content, *args)
        with reg.parent_handle(self.a / 'PROJECT.md') as (fd, name), patch.object(reg, 'exclusive_create', side_effect=fail_first):
            with self.assertRaisesRegex(RuntimeError, 'original state restored'):
                reg.replace_with_recovery(fd, name, b'new', action, old)
        self.assertEqual((self.a / 'PROJECT.md').read_bytes(), old)

    def test_tos_restore_failure_is_explicit(self):
        p = self.a / 'PROJECT.md'; p.write_bytes(b'original')
        old, fp = reg.read_metadata(p)
        action = {'before_sha256': inv.digest(old), 'before_fingerprint': list(fp)}
        with reg.parent_handle(p) as (fd, name), patch.object(reg, 'exclusive_create', side_effect=OSError('backend unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'original restoration failed'):
                reg.replace_with_recovery(fd, name, b'new', action, old)

    def test_discovery_does_not_confirm_candidates_or_coverage(self):
        (self.root / 'person' / 'nested' / 'deep').mkdir(parents=True)
        fake = [{'target': str(self.root), 'root': '/', 'fstype': 'ext4', 'device': 'fixture', 'source': 'fixture'}]
        c = self.configure(projects=[]); c['managed_roots'] = []; c['aliases'] = ['person']
        with patch.object(inv, 'mounts', return_value=fake):
            result = inv.discover(c, self.base / 'discovery', max_depth=1)
        self.assertFalse(result['coverage_complete'])
        self.assertFalse(result['ownership_complete'])
        self.assertTrue(result['candidates'])
        self.assertTrue(all(r['ownership'] == 'unconfirmed' for r in result['candidates']))

    def test_mount_alias_roots_are_not_counted_twice(self):
        self.data(self.a / 'data')
        alias = self.base / 'alias'; alias.mkdir()
        c = self.configure(); c['managed_roots'].append({'path': str(alias), 'evidence': 'test alias'})
        original_mounts = inv.mounts()
        m = inv.mount_for(str(self.root), original_mounts)
        key = inv.source_key(str(self.root), original_mounts)
        fake = [{'target': str(alias), 'root': key[3], 'fstype': m['fstype'], 'device': m['device'], 'source': m['source']}, *original_mounts]
        fake.sort(key=lambda r: len(r['target']), reverse=True)
        with patch.object(inv, 'mounts', return_value=fake):
            run = self.run_scan(c)
        summary = cli.report(run)
        self.assertEqual(len(summary['mount_aliases']), 1)
        self.assertEqual(summary['global']['allocated'], self.measures(run, self.root)['allocated'])

    def test_single_link_inode_has_same_identity_through_bind_alias(self):
        f = self.data(self.a / 'one')
        s = f.stat()
        self.assertEqual(s.st_nlink, 1)
        fake = [{'target': '/', 'fstype': 'ext4', 'root': '/', 'device': 'fixture', 'source': 'fixture'}]
        first = inv.node(str(f), s, False, fake)
        alias = inv.node(str(self.base / 'bind-alias' / 'one'), s, False, fake)
        self.assertEqual(first[-1], alias[-1])

    def test_cli_interrupt_is_resumable(self):
        for i in range(30):
            self.data(self.a / str(i) / 'data', 512)
        run = self.base / 'interrupted'
        program = "import sys,time;sys.path.insert(0,sys.argv[1]);import inventory as i;real=i.inspect_directory\ndef slow(*a):\n time.sleep(0.15)\n return real(*a)\ni.inspect_directory=slow\ntry:i.scan(i.read_config(sys.argv[2]),sys.argv[3])\nexcept KeyboardInterrupt:sys.exit(130)\n"
        proc = subprocess.Popen([sys.executable, '-c', program, str(SCRIPTS), str(self.profile), str(run)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not (run / 'inventory.sqlite').exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            time.sleep(0.1)
            proc.send_signal(signal.SIGINT)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 130)
            inv.scan(self.config, run, resume=True)
            self.assertEqual(cli.report(run)['scan_status'], 'complete')
        finally:
            if proc.poll() is None:
                proc.kill(); proc.communicate()


if __name__ == '__main__':
    unittest.main()
