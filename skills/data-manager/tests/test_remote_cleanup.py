import copy
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import cleanup
import content
import inventory as inv
import nas
import remote_io
import registration
import tos_cleanup as tc
from tos_store import TosStore, read_profile


class ServiceError(Exception):
    def __init__(self, status, code):
        self.status_code = status; self.code = code


class FakeClient:
    """Stateful SDK-shaped service: old versions survive current-key deletion."""
    def __init__(self, versioned=False):
        self.versioned = versioned; self.data = {}; self.current = {}; self.sequence = 0
        self.calls = []; self.rules = []; self.policy = {}; self.fail = None
        self.max_retry_count = 3

    def acl(self):
        return NS(owner=NS(id='owner'), grants=[NS(grantee=NS(id='owner', type='CanonicalUser', canned=None), permission='FULL_CONTROL')])

    def get_bucket_acl(self, **kw):
        return self.acl()

    def get_bucket_version(self, **kw):
        return NS(status='Enabled' if self.versioned else None)

    def head_bucket(self, **kw):
        return NS(bucket_type='fns', region='test')

    def get_object_tagging(self, **kw):
        return NS(tag_set=[])

    def get_bucket_policy(self, **kw):
        return NS(policy=json.dumps(self.policy))

    def get_bucket_lifecycle(self, **kw):
        return NS(rules=self.rules)

    def get_object_acl(self, **kw):
        self._get(kw['key'], kw.get('version_id')); return self.acl()

    def _get(self, key, version=None):
        version = version if version is not None else self.current.get(key)
        value = self.data.get((key, version))
        if value is None or value.get('marker'):
            raise ServiceError(404, 'NoSuchKey' if version is None else 'NoSuchVersion')
        return value

    def put_object(self, bucket, key, content, forbid_overwrite=False, if_match=None, **kw):
        if forbid_overwrite and key in self.current and not self.data[(key, self.current[key])].get('marker'):
            raise ServiceError(409, 'ObjectAlreadyExists')
        if if_match is not None and self._get(key)['etag'] != if_match:
            raise ServiceError(412, 'PreconditionFailed')
        self.sequence += 1; version = str(self.sequence) if self.versioned else None
        raw = bytes(content)
        self.data[(key, version)] = {'raw': raw, 'etag': hashlib.md5(raw).hexdigest(),
                                    'version': version, 'modified': str(self.sequence), 'kwargs': copy.deepcopy(kw)}
        self.current[key] = version
        self.calls.append(('put', key, version))
        return NS(request_id='put-' + str(self.sequence), version_id=version)

    def head_object(self, bucket, key, version_id=None, **kw):
        value = self._get(key, version_id); settings = value['kwargs']
        return NS(header={'x-tos-server-side-encryption': settings['server_side_encryption']} if settings.get('server_side_encryption') else {},
            etag=value['etag'], version_id=value['version'], content_length=len(value['raw']),
            last_modified=value['modified'], object_type='Normal', is_directory=False, delete_marker=False,
            sse_algorithm=None, tagging_count=0, website_redirect_location=None, expiration=None,
            storage_class='STANDARD', meta=settings.get('meta', {}), expires=settings.get('expires'),
            content_type=settings.get('content_type', 'application/octet-stream'), content_encoding=settings.get('content_encoding'),
            content_language=settings.get('content_language'), content_disposition=settings.get('content_disposition', ''),
            cache_control=settings.get('cache_control'))

    def get_object(self, bucket, key, version_id=None, if_match=None, range_start=0, **kw):
        value = self._get(key, version_id)
        if if_match is not None and if_match != value['etag']:
            raise ServiceError(412, 'PreconditionFailed')
        stream = io.BytesIO(value['raw'][range_start:])
        return NS(content=NS(data=stream), read=stream.read, resp=NS(resp=NS(close=stream.close)))

    def copy_object(self, bucket, key, src_bucket, src_key, src_version_id=None, copy_source_if_match=None, **kw):
        self.calls.append(('copy', key, src_key))
        source = self._get(src_key, src_version_id)
        if source['etag'] != copy_source_if_match:
            raise ServiceError(412, 'PreconditionFailed')
        kw.pop('metadata_directive', None)
        return self.put_object(bucket, key, source['raw'], **kw)

    def delete_object(self, bucket, key, version_id=None, **kw):
        self.calls.append(('delete', key, version_id))
        if self.fail == 'delete':
            raise TimeoutError('a signed authorization header must not be logged')
        self.sequence += 1
        if self.versioned and version_id is None:
            marker = str(self.sequence)
            self.data[(key, marker)] = {'marker': True}; self.current[key] = marker
            return NS(request_id='delete', version_id=marker, delete_marker=True)
        self.data.pop((key, version_id), None)
        if self.current.get(key) == version_id:
            self.current.pop(key, None)
        return NS(request_id='delete', version_id=version_id, delete_marker=False)

    def list_objects_type2(self, bucket, prefix, **kw):
        keys = [k for k, v in self.current.items() if k.startswith(prefix) and not self.data[(k, v)].get('marker')]
        return NS(contents=[NS(key=k) for k in sorted(keys)], is_truncated=False)


class NativeTosTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='data-manager-remote-')
        self.addCleanup(self.temp.cleanup); self.base = Path(self.temp.name); self.serial = 0
        self.profile = {'schema_version': 1, 'backend': 'tos', 'endpoint': 'https://tos.example.test',
            'region': 'test', 'bucket': 'test-bucket',
            'managed_prefixes': [{'prefix': 'managed/', 'evidence': 'test account'}],
            'projects': [{'prefix': 'managed/project/', 'evidence': 'test project'}],
            'quarantine_prefix': 'quarantine/', 'remote_io': {'workers': 4, 'read_bytes_per_second': 10 ** 9},
            'security_review': {'evidence': 'test-only policy and retention review', 'object_lock': 'disabled',
                'policy_sha256': cleanup.signature({}), 'expires': '2999-01-01T00:00:00+00:00'}}
        self.client = FakeClient(); self.store = TosStore(self.profile, client=self.client)
        sdk = NS(ACLType=NS(ACL_Private='private'), MetadataDirectiveType=NS(Metadata_Directive_Replace='REPLACE'),
                 models2=NS(UploadedPart=lambda **kw: NS(**kw)))
        mock = patch.dict(sys.modules, {'tos': sdk}); mock.start(); self.addCleanup(mock.stop)
        self.target = 'managed/project/target'; self.keeper = 'managed/project/keeper'

    def path(self, prefix):
        self.serial += 1; return self.base / (prefix + str(self.serial))

    def seed(self, key, raw=b'preserved biological data\n'):
        return self.client.put_object('test-bucket', key, raw)

    def prepare(self, versioned=False, compressed=False):
        self.client.versioned = versioned
        self.seed(self.target)
        raw = self.client._get(self.target)['raw']
        if compressed:
            self.keeper += '.gz'; self.seed(self.keeper, gzip.compress(raw))
        else:
            self.seed(self.keeper, raw)
        probe = self.path('probe'); result = tc.probe(self.profile, probe, self.store)
        self.assertEqual(result['status'], 'complete', result)
        self.profile['capability_report'] = str(probe / 'probe.json')
        run = self.path('scan'); tc.scan(self.profile, run, self.store)
        duplicate = self.path('duplicate'); tc.find_duplicates(run, duplicate, store=self.store)
        selected = self.path('selection.json')
        selected.write_text(json.dumps({'schema_version': 1, 'writers_stopped': True, 'actions': [{
            'target': self.target, 'keeper': {'key': self.keeper, 'kind': 'payload' if compressed else 'file', 'member': None},
            'reason': 'test-only reviewed redundancy', 'role': 'redundant_data', 'attributes_reviewed': True}]}))
        op = self.path('operation'); tc.plan_cleanup(duplicate, selected, op, self.store)
        return op

    def test_versioned_isolation_restore_preserves_old_source_and_no_overwrite(self):
        op = self.prepare(versioned=True)
        original = self.store.evidence(self.target)
        result = tc.execute(op, store=self.store)
        self.assertEqual(result['data_status'], 'complete', result)
        self.assertEqual(result['status'], 'pending')
        self.assertIsNone(result['verified_storage_release_bytes'])
        self.assertIsNone(self.store.exists(self.target))
        self.assertEqual(self.store.evidence(self.target, original['version_id']), original)
        q = result['entries'][0]['quarantined']; self.assertIsNotNone(self.store.exists(q['key'], q['version_id']))
        mutations = len(self.client.calls); tc.execute(op, store=self.store)
        self.assertEqual(len(self.client.calls), mutations)
        self.seed(self.target, b'new unrelated data')
        result = tc.execute(op, 'restore', store=self.store)
        self.assertEqual(result['entries'][0]['status'], 'quarantined')
        self.assertEqual(self.client._get(self.target)['raw'], b'new unrelated data')

    def test_compressed_keeper_restore_and_bound_purge(self):
        for phase in ('restore', 'purge'):
            with self.subTest(phase=phase):
                op = self.prepare(compressed=True)
                result = tc.execute(op, store=self.store)
                self.assertEqual(result['entries'][0]['status'], 'quarantined', result)
                if phase == 'restore':
                    # Recovery does not require the surviving keeper.
                    self.client.delete_object('test-bucket', self.keeper)
                    result = tc.execute(op, 'restore', store=self.store)
                    self.assertEqual(result['entries'][0]['status'], 'restored', result)
                else:
                    with self.assertRaises(ValueError):
                        tc.execute(op, 'purge', store=self.store)
                    p = self.path('purge'); tc.plan_purge(op, p, self.store)
                    manifest = cleanup.load(p / 'manifest.json')
                    changed = dict(manifest, paths=['quarantine/unreviewed'])
                    with self.assertRaises(ValueError):
                        tc.execute(op, 'purge', changed, self.store)
                    with self.assertRaises(ValueError):
                        tc.execute(op, 'purge', dict(manifest, versions=['unreviewed-version']), self.store)
                    result = tc.execute(op, 'purge', manifest, self.store)
                    self.assertEqual(result['entries'][0]['status'], 'purged', result)
                self.keeper = 'managed/project/keeper'

    def test_changed_keeper_blocks_purge(self):
        op = self.prepare(); tc.execute(op, store=self.store)
        p = self.path('purge'); tc.plan_purge(op, p, self.store)
        self.seed(self.keeper, b'changed keeper')
        before = len([c for c in self.client.calls if c[0] == 'delete'])
        result = tc.execute(op, 'purge', cleanup.load(p / 'manifest.json'), self.store)
        self.assertEqual(result['entries'][0]['status'], 'quarantined')
        self.assertEqual(len([c for c in self.client.calls if c[0] == 'delete']), before)

    def test_copy_receipt_survives_interruption_and_reconciles_without_mutation(self):
        op = self.prepare()
        real = self.store.evidence
        def interrupt(key, version=None):
            if key.startswith('quarantine/'):
                raise KeyboardInterrupt()
            return real(key, version)
        with patch.object(self.store, 'evidence', side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                tc.execute(op, store=self.store)
        state = cleanup.load(op / 'state.json')
        self.assertEqual(state['entries'][0]['status'], 'copy_intent')
        before = len(self.client.calls)
        tc.reconcile(op, self.store)
        self.assertEqual(len(self.client.calls), before)
        self.assertEqual(cleanup.load(op / 'state.json')['entries'][0]['status'], 'copied')
        self.assertEqual(tc.execute(op, store=self.store)['entries'][0]['status'], 'quarantined')

    def test_unknown_delete_never_retries_and_does_not_log_signed_details(self):
        op = self.prepare(); self.client.fail = 'delete'
        result = tc.execute(op, store=self.store)
        self.assertEqual(result['entries'][0]['status'], 'remove_intent')
        before = len(self.client.calls)
        tc.reconcile(op, self.store)
        self.assertEqual(len(self.client.calls), before)
        with self.assertRaises(ValueError):
            tc.execute(op, store=self.store)
        self.assertNotIn('authorization header', (op / 'state.json').read_text())

    def test_lifecycle_policy_and_unknown_allocation_are_not_silently_accepted(self):
        self.client.rules = [{'status': 'Enabled', 'prefix': '', 'expiration': {'days': 1}}]
        with self.assertRaises(ValueError):
            self.store.safety()
        self.client.rules = []; self.client.policy = {'Statement': ['changed']}
        with self.assertRaises(ValueError):
            self.store.safety()
        self.client.policy = {}; self.profile['security_review']['expires'] = '2000-01-01T00:00:00+00:00'
        with self.assertRaises(ValueError):
            self.store.safety()

    def test_native_profile_rejects_cross_project_quarantine_and_embedded_secrets(self):
        profile = copy.deepcopy(self.profile); profile['quarantine_prefix'] = 'managed/project/quarantine/'
        with self.assertRaises(ValueError):
            read_profile(profile)
        profile = dict(self.profile, secret_key='do not persist')
        with self.assertRaises(ValueError):
            read_profile(profile)

    def test_unlimited_transfer_totals_survive_resume(self):
        op = self.prepare(); tc.execute(op, store=self.store)
        state = cleanup.load(op / 'state.json')
        state['traffic']['read_bytes'] = 10 ** 15; state['traffic']['copy_attempted_bytes'] = 10 ** 15
        cleanup.durable(op / 'state.json', state)
        result = tc.execute(op, 'restore', store=self.store)
        self.assertEqual(result['entries'][0]['status'], 'restored')
        self.assertGreater(result['traffic']['copy_attempted_bytes'], 10 ** 15)

    def test_registration_history_preserves_attributes_and_manual_content(self):
        key = 'managed/project/PROJECT.md'
        original = registration.new_registration({'path': 'managed/project/'}, 'fixture owner', 'unknown allocation') + '\nManual notes.\n'
        self.client.put_object('test-bucket', key, original.encode(), content_type='text/markdown',
            content_encoding='identity', content_language='zh-CN', content_disposition='inline',
            cache_control='private, max-age=0', meta={'purpose': 'research'}, server_side_encryption='AES256')
        attrs = self.store.inspect(key)['attributes']
        op = self.prepare()
        result = tc.execute(op, store=self.store)
        self.assertEqual(result['registration']['managed/project/'], 'history_verified_allocation_pending')
        self.assertEqual(self.store.inspect(key)['attributes'], attrs)
        raw = self.client._get(key)['raw']
        self.assertIn(b'Manual notes.', raw)
        self.assertIn(b'data-manager-cleanup:', raw)
        self.assertEqual(len(list(op.glob('registration-*.backup'))), 1)
        tc.report_cleanup(op, self.store)
        self.assertEqual(self.client._get(key)['raw'], raw)

    def test_multipart_copy_uses_bound_ranges_and_no_replace_completion(self):
        self.seed(self.target)
        source = self.store.evidence(self.target)
        source['object_length'] = 6 * 1024 ** 3
        calls = []; records = []
        def create(**kwargs):
            calls.append(('create', kwargs)); return NS(upload_id='fixture-upload')
        def part(**kwargs):
            calls.append(('part', kwargs)); return NS(etag='part-' + str(kwargs['part_number']))
        def complete(**kwargs):
            calls.append(('complete', kwargs)); return NS(version_id='copied-version')
        with patch.object(self.client, 'create_multipart_upload', side_effect=create, create=True), \
                patch.object(self.client, 'upload_part_copy', side_effect=part, create=True), \
                patch.object(self.client, 'complete_multipart_upload', side_effect=complete, create=True):
            self.store.copy(source, 'quarantine/test/multipart', lambda **details: records.append(details))
        parts = [kw for kind, kw in calls if kind == 'part']
        self.assertEqual(parts[0]['copy_source_range_start'], 0)
        self.assertEqual(parts[-1]['copy_source_range_end'], source['object_length'] - 1)
        self.assertEqual(sum(p['copy_source_range_end'] - p['copy_source_range_start'] + 1 for p in parts), source['object_length'])
        self.assertTrue(all(p['src_version_id'] == source['version_id'] and p['copy_source_if_match'] == source['etag'] for p in parts))
        self.assertTrue(calls[-1][1]['forbid_overwrite'])
        self.assertEqual(records[0]['upload_id'], 'fixture-upload')

    def test_transport_failure_after_copy_does_not_guess_completion(self):
        op = self.prepare(); original = self.client.copy_object
        def timeout(**kwargs):
            original(**kwargs); raise TimeoutError('server result unavailable')
        with patch.object(self.client, 'copy_object', side_effect=timeout):
            result = tc.execute(op, store=self.store)
        self.assertEqual(result['entries'][0]['status'], 'copy_intent')
        mutations = len(self.client.calls)
        result = tc.reconcile(op, self.store)
        self.assertEqual(result['entries'][0]['status'], 'copy_intent')
        self.assertEqual(len(self.client.calls), mutations)
        self.assertIsNotNone(self.store.exists(self.target))

    def test_tags_and_nonflat_bucket_are_rejected(self):
        self.seed(self.target)
        with patch.object(self.client, 'get_object_tagging', return_value=NS(tag_set=[{'key': 'tag', 'value': 'retention'}])):
            with self.assertRaises(ValueError):
                self.store.inspect(self.target)
        with patch.object(self.client, 'head_bucket', return_value=NS(bucket_type='hns', region='test')):
            with self.assertRaises(ValueError):
                self.store.controls()

    def test_sdk_wrapped_stream_seek_closes_underlying_response(self):
        self.seed(self.target, b'0123456789')
        ref = self.store.inspect(self.target)
        original = self.client.get_object; handles = []
        def wrapped(**kwargs):
            result = original(**kwargs)
            close = unittest.mock.Mock(wraps=result.resp.resp.close)
            result.resp.resp.close = close; handles.append(close)
            return result
        with patch.object(self.client, 'get_object', side_effect=wrapped), self.store.open(ref) as (stream, _):
            self.assertEqual(stream.read(2), b'01')
            stream.seek(-2, 2)
            self.assertEqual(stream.read(), b'89')
        self.assertEqual([c.call_count for c in handles], [1, 1])


class NasTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='data-manager-nas-'); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.root = self.base / 'nas'; self.root.mkdir(mode=0o700)
        self.q = self.root / 'quarantine'; self.q.mkdir(mode=0o700)
        self.project = self.root / 'project'; self.project.mkdir()
        rows = inv.mounts()
        self.mount = dict(inv.mount_for(str(self.root), rows), target=str(self.root), source='test:/export', fstype='nfs')
        mock = patch.object(inv, 'mounts', return_value=[self.mount, *rows]); mock.start(); self.addCleanup(mock.stop)
        mock = patch.object(content, 'mounts', return_value=[self.mount, *rows]); mock.start(); self.addCleanup(mock.stop)
        self.profile = self.base / 'profile.json'
        self.profile.write_text(json.dumps({'schema_version': 1,
            'managed_roots': [{'path': str(self.root), 'evidence': 'test'}],
            'projects': [{'path': str(self.project), 'evidence': 'test'}], 'containers': [],
            'nas_capabilities': [str(self.base / 'nas.json')], 'threshold_bytes': 10 ** 12,
            'remote_io': {'read_bytes_per_second': 10 ** 9}}))
        self.config = inv.read_config(self.profile)
        mock = patch.object(registration, 'git_context', return_value=(False, False))
        mock.start(); self.addCleanup(mock.stop)

    def test_capability_probe_rejects_missing_noreplace_and_expires(self):
        with patch.object(cleanup, 'rename_noreplace', side_effect=OSError('unsupported')):
            evidence = nas.probe(self.q, self.base / 'failed.json', 'test ACL reviewed')
        self.assertFalse(evidence['supported'])
        self.assertFalse(list(self.q.iterdir()))
        evidence = nas.probe(self.q, self.base / 'nas.json', 'test ACL reviewed')
        self.assertTrue(evidence['supported'])
        nas.validate(self.project, self.config, inv.mounts())
        evidence['checked'] = '2000-01-01T00:00:00+00:00'; cleanup.durable(self.base / 'nas.json', evidence)
        with self.assertRaises(ValueError):
            nas.validate(self.project, self.config, inv.mounts())

    def test_nas_quarantine_reconcile_restore_and_purge(self):
        nas.probe(self.q, self.base / 'nas.json', 'test-only server-side ACL evidence')
        target = self.project / 'target'; keeper = self.project / 'keeper'
        target.write_bytes(b'NAS biology'); keeper.write_bytes(target.read_bytes())
        run = self.base / 'run'; inv.scan(self.config, run)
        duplicate = self.base / 'duplicates'; content.find_duplicates(run, duplicate)
        selection = self.base / 'selection.json'
        selection.write_text(json.dumps({'schema_version': 1, 'writers_stopped': True, 'actions': [{
            'target': str(target), 'keeper': {'path': str(keeper), 'kind': 'file', 'member': None},
            'quarantine_root': str(self.q), 'role': 'redundant_data', 'reason': 'test', 'attributes_reviewed': True}]}))
        op = self.base / 'op'; cleanup.plan_cleanup(duplicate, selection, op)
        real = cleanup.rename_noreplace
        def interrupt(source, destination):
            real(source, destination)
            if str(destination).startswith(str(self.q / cleanup.load(op / 'manifest.json')['operation_id'])):
                raise KeyboardInterrupt()
        with patch.object(cleanup, 'rename_noreplace', side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                cleanup.execute(op)
        result = cleanup.reconcile_cleanup(op)
        self.assertEqual(result['business_mutations'], 0)
        self.assertEqual(result['entries'][0]['status'], 'quarantined')
        self.assertEqual(cleanup.report_cleanup(op)['status'], 'complete')
        self.assertEqual(cleanup.execute(op, 'restore')['status'], 'complete')
        self.assertEqual(target.read_bytes(), b'NAS biology')
        # A fresh operation exercises separately authorized NAS purge.
        run2 = self.base / 'run2'; inv.scan(self.config, run2)
        duplicate2 = self.base / 'duplicates2'; content.find_duplicates(run2, duplicate2)
        op2 = self.base / 'op2'; cleanup.plan_cleanup(duplicate2, selection, op2); cleanup.execute(op2)
        purge = self.base / 'purge'; cleanup.plan_purge(op2, purge)
        self.assertEqual(cleanup.execute(op2, 'purge', cleanup.load(purge / 'manifest.json'))['status'], 'complete')


class TrafficTests(unittest.TestCase):
    def test_large_reads_are_exact_and_totals_are_unbounded(self):
        totals = {'read_bytes': 10 ** 15, 'copy_attempted_bytes': 10 ** 15}
        traffic = remote_io.Traffic({'read_bytes_per_second': 10 ** 12}, totals)
        raw = b'x' * (2 * 1024 ** 2 + 17)
        stream = remote_io.Reader(io.BytesIO(raw), traffic)
        self.assertEqual(stream.read(len(raw)), raw)
        traffic.copy(1024 ** 5)
        self.assertEqual(totals['read_bytes'], 10 ** 15 + len(raw))
        self.assertEqual(totals['copy_attempted_bytes'], 10 ** 15 + 1024 ** 5)


if __name__ == '__main__':
    unittest.main()
