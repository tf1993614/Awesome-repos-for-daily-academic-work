"""Version-bound TOS I/O using the optional official SDK, with retries disabled."""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
from urllib.parse import quote, urlparse

import cleanup
import content
import remote_io


def plain(value):
    if hasattr(value, 'value'):
        return value.value
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return {k: plain(v) for k, v in vars(value).items() if not k.startswith('_')}


def prefix(value):
    if (not isinstance(value, str) or not value or value.startswith('/') or not value.endswith('/')
            or any(p in {'.', '..', ''} for p in value[:-1].split('/')) or '\\' in value or '\x00' in value):
        raise ValueError('TOS prefixes must be nonempty canonical relative keys ending in /')
    return value


def read_profile(path):
    value = path if isinstance(path, dict) else cleanup.load(path)
    if value.get('schema_version') != 1 or value.get('backend') != 'tos':
        raise ValueError('Expected a version-1 native TOS profile')
    endpoint = urlparse(value['endpoint'])
    if (endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password
            or endpoint.path not in {'', '/'} or endpoint.query or endpoint.fragment):
        raise ValueError('TOS endpoint must be an HTTPS origin without credentials')
    if not value.get('region') or not value.get('bucket') or '/' in value['bucket']:
        raise ValueError('TOS region and bucket required')
    if any(k in value for k in ('ak', 'sk', 'access_key', 'secret_key', 'security_token')):
        raise ValueError('Store credentials in the environment, never in the profile')
    roots = [prefix(p['prefix']) for p in value['managed_prefixes'] if p.get('evidence')]
    projects = [prefix(p['prefix']) for p in value['projects'] if p.get('evidence')]
    if not roots or len(roots) != len(value['managed_prefixes']) or not projects or len(projects) != len(value['projects']):
        raise ValueError('Confirmed ownership and project evidence required')
    for group in (roots, projects):
        if any(a.startswith(b) or b.startswith(a) for i, a in enumerate(group) for b in group[:i]):
            raise ValueError('TOS managed/project prefixes must not overlap')
    if any(not any(p.startswith(r) for r in roots) for p in projects):
        raise ValueError('TOS project outside confirmed managed prefixes')
    q = prefix(value['quarantine_prefix'])
    if any(q.startswith(p) or p.startswith(q) for p in projects):
        raise ValueError('TOS quarantine must be outside every project prefix')
    remote_io.Traffic(value.get('remote_io'))
    return value


def missing(exc):
    # A missing bucket or an access denial is never a missing object.
    return getattr(exc, 'status_code', None) == 404 and getattr(exc, 'code', None) in {
        'NoSuchKey', 'NoSuchVersion'}


class ObjectReader(io.RawIOBase):
    def __init__(self, store, ref):
        self.store = store; self.ref = ref; self.position = 0
        self.response = None

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def _close_response(self):
        if self.response is not None:
            # GetObjectOutput.content may be a CRC adapter with no close method.
            self.response.resp.resp.close()
            self.response = None

    def seek(self, offset, whence=0):
        new = offset + (self.position if whence == 1 else self.ref['object_length'] if whence == 2 else 0)
        if new < 0 or whence not in (0, 1, 2):
            raise ValueError('Invalid remote seek')
        if new != self.position:
            self._close_response(); self.position = new
        return new

    def read(self, size=-1):
        remaining = max(0, self.ref['object_length'] - self.position)
        size = remaining if size is None or size < 0 else min(size, remaining)
        if not size:
            return b''
        if self.response is None:
            self.response = self.store.call('get_object', self.ref['key'],
                version_id=self.ref['version_id'], if_match=self.ref['etag'], range_start=self.position)
        blocks = []
        while size:
            try:
                block = self.response.read(min(size, content.CHUNK))
            except Exception as exc:
                raise RuntimeError('TOS object stream failed: ' + type(exc).__name__) from None
            if not block:
                raise ValueError('Truncated TOS response')
            self.store.traffic.read(len(block))
            self.position += len(block); size -= len(block); blocks.append(block)
        return b''.join(blocks)

    def close(self):
        self._close_response()
        super().close()


class TosStore:
    def __init__(self, profile, traffic=None, client=None):
        self.profile = read_profile(profile); self.bucket = profile['bucket']
        self.traffic = traffic or remote_io.Traffic(profile.get('remote_io'))
        if client is None:
            try:
                import tos
            except ImportError as exc:
                raise ValueError('Native TOS requires the optional official tos SDK (requirements-tos.txt)') from exc
            try:
                client = tos.TosClientV2(os.environ['TOS_ACCESS_KEY'], os.environ['TOS_SECRET_KEY'],
                    endpoint=profile['endpoint'], region=profile['region'],
                    security_token=os.environ.get('TOS_SECURITY_TOKEN'), max_retry_count=0,
                    connection_time=15, socket_timeout=60)
            except KeyError as exc:
                raise ValueError('Set TOS_ACCESS_KEY and TOS_SECRET_KEY in the environment') from exc
        self.client = client
        self.client.max_retry_count = 0

    def call(self, method, key=None, **kwargs):
        try:
            if key is not None:
                kwargs['key'] = key
            return getattr(self.client, method)(bucket=self.bucket, **kwargs)
        except Exception as exc:
            if missing(exc):
                raise FileNotFoundError(key) from exc
            # SDK exceptions may contain signed headers; persist only their classification.
            raise RuntimeError('TOS %s failed: %s/%s' % (method,
                getattr(exc, 'status_code', 'transport'), getattr(exc, 'code', type(exc).__name__))) from None

    def optional(self, method, absent_code):
        try:
            return getattr(self.client, method)(bucket=self.bucket)
        except Exception as exc:
            if getattr(exc, 'status_code', None) == 404 and getattr(exc, 'code', None) == absent_code:
                return None
            raise RuntimeError('Cannot verify TOS bucket configuration: ' + method) from None

    def controls(self):
        bucket = self.call('head_bucket')
        if bucket.bucket_type != 'fns' or bucket.region != self.profile['region']:
            raise ValueError('Only a confirmed flat-namespace bucket in the configured region is supported')
        version = plain(self.call('get_bucket_version').status)
        if version not in (None, '', 'Enabled'):
            raise ValueError('Suspended or unknown TOS versioning remains pending')
        acl = self.call('get_bucket_acl')
        owner, grants = self.acl(acl)
        policy = self.optional('get_bucket_policy', 'NoSuchBucketPolicy')
        policy_value = json.loads(policy.policy) if policy is not None else {}
        lifecycle = self.optional('get_bucket_lifecycle', 'NoSuchLifecycleConfiguration')
        rules = plain(lifecycle.rules) if lifecycle is not None else []
        return {'versioning': 'Enabled' if version == 'Enabled' else 'Disabled',
                'owner': owner, 'grants': grants, 'policy_sha256': cleanup.signature(policy_value), 'lifecycle': rules}

    @staticmethod
    def acl(output):
        owner = output.owner.id
        grants = [{'id': g.grantee.id, 'type': plain(g.grantee.type),
                   'canned': plain(g.grantee.canned), 'permission': plain(g.permission)} for g in output.grants]
        if not owner or not grants or any(g['id'] != owner or g['canned'] for g in grants):
            raise ValueError('Only verified owner-private TOS ACLs are supported')
        return owner, sorted(grants, key=lambda g: str(g))

    def safety(self):
        controls = self.controls()
        review = self.profile.get('security_review', {})
        try:
            expiry = dt.datetime.fromisoformat(review['expires'])
            valid = expiry > dt.datetime.now(dt.timezone.utc)
        except (KeyError, ValueError, TypeError):
            valid = False
        if (not valid or not review.get('evidence') or review.get('object_lock') != 'disabled'
                or review.get('policy_sha256') != controls['policy_sha256']):
            raise ValueError('A current policy-bound access/object-lock review is required; use tos-controls')
        prefixes = [self.profile['quarantine_prefix'], *(p['prefix'] for p in self.profile['projects'])]
        for rule in controls['lifecycle']:
            if rule.get('status') == 'Disabled':
                continue
            if rule.get('status') != 'Enabled':
                raise ValueError('Unknown lifecycle rule status')
            rule_prefix = rule.get('prefix') or ''
            # Tag/size filters do not prove nonapplication: object tags can change.
            if rule.get('filter'):
                raise ValueError('Filtered lifecycle rules require explicit exclusion before cleanup')
            if any(p.startswith(rule_prefix) or rule_prefix.startswith(p) for p in prefixes):
                raise ValueError('Lifecycle rules overlap projects or quarantine')
        return controls

    def uri(self, key):
        return 'tos://' + self.bucket + '/' + quote(key, safe='/')

    def project(self, key):
        if not isinstance(key, str) or not key or key.endswith('/') or '\x00' in key:
            raise ValueError('An individual TOS object key is required')
        if key.split('/')[-1] in content.PROTECTED or '.git' in key.split('/'):
            raise ValueError('Protected TOS metadata is not a cleanup target')
        for entry in self.profile['projects']:
            if key.startswith(entry['prefix']):
                return entry['prefix']
        raise ValueError('TOS object outside confirmed projects')

    def inspect(self, key, version=None):
        h = self.call('head_object', key, version_id=version)
        headers = {k.lower(): v for k, v in h.header.items()}
        if (h.object_type != 'Normal' or h.is_directory or h.delete_marker or h.sse_algorithm
                or h.tagging_count or h.website_redirect_location or h.expiration
                or any('object-lock' in k or 'retention' in k or 'legal-hold' in k for k in headers)):
            raise ValueError('Unsupported TOS object attributes, tags, expiry, or retention')
        if self.call('get_object_tagging', key, version_id=h.version_id).tag_set:
            raise ValueError('Tagged TOS objects remain pending')
        storage = plain(h.storage_class) or 'STANDARD'
        encryption = headers.get('x-tos-server-side-encryption')
        if storage != 'STANDARD' or encryption not in (None, 'AES256'):
            raise ValueError('Cold storage or unsupported encryption remains pending')
        owner, grants = self.acl(self.call('get_object_acl', key, version_id=h.version_id))
        attrs = {'owner': owner, 'grants': grants, 'meta': h.meta, 'storage_class': storage,
                 'encryption': encryption, 'content_type': h.content_type,
                 'content_encoding': h.content_encoding, 'content_language': h.content_language,
                 'content_disposition': h.content_disposition, 'cache_control': h.cache_control,
                 'expires': plain(h.expires)}
        return {'kind': 'file', 'path': self.uri(key), 'key': key, 'member': None,
                'version_id': h.version_id, 'etag': h.etag, 'object_length': h.content_length,
                'modified': plain(h.last_modified), 'attributes': attrs, 'allocated': None}

    def exists(self, key, version=None):
        try:
            return self.inspect(key, version)
        except FileNotFoundError:
            return None

    @contextlib.contextmanager
    def open(self, ref):
        if self.inspect(ref['key'], ref['version_id']) != {k: v for k, v in ref.items() if k not in {'length', 'sha256'}}:
            raise ValueError('TOS object identity or metadata changed')
        with ObjectReader(self, ref) as stream:
            yield stream, ref
        expected = {k: v for k, v in ref.items() if k not in {'length', 'sha256'}}
        if self.inspect(ref['key'], ref['version_id']) != expected:
            raise ValueError('TOS object changed while reading')

    def evidence(self, key, version=None):
        ref = self.inspect(key, version)
        with self.open(ref) as (stream, _):
            length, digest = content.read_hash(stream)
        return dict(ref, length=length, sha256=digest)

    def verify(self, ref, current=False):
        actual = self.evidence(ref['key'], ref['version_id'])
        if actual != ref:
            raise ValueError('TOS retained object changed')
        if current and self.inspect(ref['key']) != {k: v for k, v in ref.items() if k not in {'length', 'sha256'}}:
            raise ValueError('TOS current version changed')
        return actual

    def compare(self, left, right):
        with self.open(left) as (a, _), self.open(right) as (b, _):
            content.read_hash(a, compare=b)

    def keys(self, prefix_value):
        token = None; seen = set()
        while True:
            out = self.call('list_objects_type2', prefix=prefix_value, continuation_token=token, list_only_once=True)
            for item in out.contents:
                if not item.key.startswith(prefix_value):
                    raise ValueError('TOS listing escaped prefix')
                yield item.key
            if not out.is_truncated:
                return
            token = out.next_continuation_token
            if not token or token in seen:
                raise ValueError('Invalid TOS pagination')
            seen.add(token)

    def copy(self, source, destination, journal):
        import tos
        self.traffic.copy(source['object_length'])
        attrs = source['attributes']
        kwargs = self.write_attributes(attrs)
        kwargs['acl'] = tos.ACLType.ACL_Private
        if source['object_length'] <= 5 * 1024 ** 3:
            return self.call('copy_object', destination, src_bucket=self.bucket, src_key=source['key'],
                src_version_id=source['version_id'], copy_source_if_match=source['etag'],
                forbid_overwrite=True, metadata_directive=tos.MetadataDirectiveType.Metadata_Directive_Replace,
                **kwargs)
        # Multipart copy is also no-replace. Journal upload identity before sending parts.
        started = self.call('create_multipart_upload', destination, **kwargs)
        upload_id = started.upload_id
        journal(upload_id=upload_id, destination=destination)
        parts = []
        part_size = max(64 * 1024 ** 2, (source['object_length'] + 9998) // 9999)
        for number, start in enumerate(range(0, source['object_length'], part_size), 1):
            out = self.call('upload_part_copy', destination, upload_id=upload_id, part_number=number,
                src_bucket=self.bucket, src_key=source['key'], src_version_id=source['version_id'],
                copy_source_if_match=source['etag'], copy_source_range_start=start,
                copy_source_range_end=min(start + part_size, source['object_length']) - 1)
            parts.append(tos.models2.UploadedPart(part_number=number, etag=out.etag))
            journal(upload_id=upload_id, destination=destination, completed_parts=number)
        return self.call('complete_multipart_upload', destination, upload_id=upload_id, parts=parts,
                         forbid_overwrite=True)

    @staticmethod
    def write_attributes(attrs):
        kwargs = {k: attrs[k] for k in ('content_type', 'content_encoding', 'content_language',
                                      'content_disposition', 'cache_control') if attrs[k]}
        kwargs.update(meta=attrs['meta'], server_side_encryption=attrs['encryption'])
        if attrs['expires']:
            kwargs['expires'] = dt.datetime.fromisoformat(attrs['expires'])
        return kwargs

    def delete(self, ref, hide=False):
        self.verify(ref, current=True)
        out = self.call('delete_object', ref['key'], version_id=None if hide else ref['version_id'])
        return {'request_id': out.request_id, 'version_id': getattr(out, 'version_id', None),
                'delete_marker': getattr(out, 'delete_marker', False)}
