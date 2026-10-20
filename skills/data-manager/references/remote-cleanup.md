# NAS and native TOS cleanup

Use the existing exact selection, quarantine, restore, and separately authorized purge workflow. This reference extends [cleanup-future.md](cleanup-future.md); it does not authorize live-data operations. Reports are Chinese by default.

## Scope and prerequisites

- NAS supports NFS/NFS4 and SMB/CIFS only after a successful dedicated-root capability probe and server-side access review. Targets, keepers, and quarantine must use the same reviewed mount. Other FUSE backends remain report-only for cleanup.
- Native TOS uses a separate bucket/prefix profile and the optional official SDK in `scripts/requirements-tos.txt`. Credentials come from `TOS_ACCESS_KEY`, `TOS_SECRET_KEY`, and optional `TOS_SECURITY_TOKEN`; never put credentials in profiles, command arguments, manifests, or reports. Existing mounted profiles do not prove native bucket/key mappings: confirm these explicitly in the native profile.
- Stop writes to targets and keepers across clients throughout execution. Reconfirm before later restore or purge. Locks coordinate this tool only. Backend configuration, object identity, content, and required attributes are rechecked; changed or uncertain prerequisites leave work pending.
- Keep operation logs and capability reports on supported local storage outside projects and quarantine. Keep those logs while any quarantine or incomplete multipart upload remains. Quarantine remains occupied storage and is excluded from future business-duplicate selections.
- `remote_io.workers` defaults to 4; `remote_io.read_bytes_per_second` defaults to 67108864 (64 MiB/s across client readers). Native object detection uses the bounded worker pool; mutations execute sequentially. **There is no cumulative read or copy byte ceiling.** Counters include rereads and copy attempts, persist through cleanup resumes, and are observations rather than billed traffic. Server-side copy speed is not controlled by the client read limiter. Archive expansion/member limits are separate content-validation limits, not transfer quotas.

## NAS capability evidence

Create/review a dedicated, account-owned mode-0700 quarantine directory outside all projects. Inspect server ACLs/export permissions; synthetic mount UID/mode values alone do not prove privacy. The probe creates and removes only uniquely named fixtures inside this directory. It checks no-replace collision handling, atomic moves, stable file identity, directory fsync, and tool locks; it does not claim to stop other clients or simulate server power failure.

```bash
python3 scripts/data_manager.py probe-nas --root /nas/.quarantine --output /local/runtime/nas-capabilities.json --access-evidence 'Reviewed export and server ACL evidence'
```

Add the resulting local report path to the mounted profile's `nas_capabilities` list. It binds mount, quarantine root identity, access-review evidence, and time. Evidence expires after 86400 seconds by default (`nas_capability_max_age_seconds`); execution also repeats fixture capability checks before touching selected files. Failed probes remain explicit failed evidence. Never fall back to NAS copy-delete.

Then use ordinary mounted `scan`, `find-duplicates`, `plan-cleanup`, `apply-cleanup`, `restore-cleanup`, `plan-purge`, `purge`, and `report-cleanup`. Existing local cleanup and hardlink exclusions still apply. Independent backups on other NAS mounts cannot support this first remote cleanup version.

## Native TOS profile and controls

Start from [example-tos-profile.json](../assets/example-tos-profile.json). Confirm the endpoint, region, bucket, management evidence, and project prefixes. Prefixes end in `/`; the dedicated quarantine prefix cannot overlap any project. Profiles containing credentials are rejected.

```bash
python3 scripts/data_manager.py tos-controls --config TOS_PROFILE.json
```

Review current bucket policy/access, lifecycle, object lock, and retention. Fill `security_review.evidence`, an explicit timezone-aware `expires`, the returned `policy_sha256`, and `object_lock: "disabled"` only after actual review. The SDK does not expose a complete object-lock configuration reader: the latter is an operator attestation, not an automated proof. HEAD retention indicators are additionally rejected. Missing or expired review, unreadable controls, changed policy, nonprivate ACLs, overlapping lifecycle rules, and unknown filters block mutations. The tool never rewrites bucket policies or lifecycle rules.

Supported objects are ordinary, owner-private, standard-storage objects with supported metadata and either no explicit encryption or TOS AES256 encryption. Tagged objects, cold storage, SSE-C/unsupported encryption, symlinks, explicit expiry/retention, and unsupported attributes remain pending. This preserves required attributes rather than silently stripping them. Suspended versioning remains pending; disabled and enabled versioning have separate deletion semantics.

```bash
python3 scripts/data_manager.py tos-probe --config TOS_PROFILE.json --output /local/runtime/tos-probe
```

The probe creates only unique fixture keys under the dedicated quarantine prefix, verifies collision rejection and copied contents/attributes, then deletes only its own bound fixture versions. It logs intentions before requests. Record its `probe.json` as `capability_report` in the native profile. Uncertain requests or incomplete fixture removal leave the probe pending; preserve its log and handle only those fixture identities after review. No successful probe is fabricated from mocked tests. Capability evidence expires after 86400 seconds by default (`capability_max_age_seconds`) and is bound to current controls.

## Native detection and exact selection

```bash
python3 scripts/data_manager.py scan --config TOS_PROFILE.json --output TOS_RUN
python3 scripts/data_manager.py find-duplicates --run TOS_RUN --output TOS_DUPLICATES
```

Native scans enumerate only confirmed project prefixes. They report logical lengths, object identity and version, and unknown backend allocation/billing. They do not replace allocation with logical size or make automatic registration-threshold decisions. Native inventory uses fresh snapshots; it does not support mounted `scan --resume`. Mounted and native evidence are separate inputs.

Detection streams complete content with SHA-256 and final byte comparisons; ETags are identity/precondition hints, never sufficient duplicate evidence. Native archive validation uses the same complete-archive checks, member/path restrictions, checksums, and expansion limits as local detection. ZIP seeks use version-bound range reads; nested archives are not recursively expanded.

Review `duplicates.json`, `duplicates.csv`, and `REPORT.md`. Native selections use exact **keys** rather than mounted paths:

```json
{
  "schema_version": 1,
  "writers_stopped": true,
  "actions": [{
    "target": "managed/example/reads.fastq",
    "keeper": {"key": "managed/example/reads.fastq.gz", "kind": "payload", "member": null},
    "role": "redundant_data",
    "reason": "Reviewed extracted copy is unnecessary for current work",
    "attributes_reviewed": true
  }]
}
```

Keepers must be in confirmed projects in the **same bucket**, cannot be targets elsewhere in the batch, and cannot be quarantined data. This version does not enable cross-bucket, remote-to-local, or cross-NAS cleanup. Compression preserves byte evidence; restoration does not promise the old inode, VersionId, or timestamp.

## Isolation, recovery, and purge

Use the existing commands; manifests dispatch to their recorded backend:

```bash
python3 scripts/data_manager.py plan-cleanup --duplicates TOS_DUPLICATES --selection SELECTION.json --output OPERATION
python3 scripts/data_manager.py apply-cleanup --manifest OPERATION/manifest.json
python3 scripts/data_manager.py restore-cleanup --operation OPERATION
python3 scripts/data_manager.py plan-purge --cleanup OPERATION --output PURGE_PLAN
python3 scripts/data_manager.py purge --manifest PURGE_PLAN/manifest.json
```

Review exact originals, keepers, isolation keys, versions, attributes, and reasons. Isolation copies to a unique same-bucket key without overwriting, verifies full bytes and required attributes, then removes the original location. Objects exceeding the single-copy limit use SDK multipart copy with no-replace completion; upload IDs and progress are journaled. Failed or uncertain multipart requests remain pending, without automatic abort or deletion; inspect their operation records. Transfer totals are unlimited even for multipart objects.

With enabled versioning, original-location removal creates a delete marker and preserves original data versions. With disabled versioning, it removes the verified original only after a verified quarantine copy exists. Permanent purge removes only the exact isolated version in the reviewed purge manifest, never original historical versions or unrelated delete markers. Source history may therefore continue occupying storage after successful purge. There is no recursive prefix deletion.

Recovery verifies quarantine and copies to an unoccupied original key, verifies contents and required attributes, and only then removes the isolated version. An occupied original blocks recovery. A missing keeper does not prevent rescuing intact quarantine; purge still requires its retained dependency. Owner-private attributes and supported encryption/metadata must match. No automatic expiry, retention countdown, or automatic purge is installed.

## Interruption, reports, and acceptance

```bash
python3 scripts/data_manager.py reconcile-cleanup --operation OPERATION
python3 scripts/data_manager.py report-cleanup --operation OPERATION
```

Every mutation follows a durable intent. TOS SDK automatic retries are disabled. Read-only reconciliation may record a fully verified result from bound receipts and current content/identity, but does not repeat requests or remove business data. Missing receipts, transport ambiguity, conflicting paths, or changed versions remain pending; absence alone never fabricates success. Run `report-cleanup` after successful reconciliation to recover phase completion and retry metadata finalization; it does not repeat data actions. A pending operation never silently authorizes new paths.

Native reports distinguish `data_status` from capacity finalization. Backend allocated bytes, physical release, and billing remain unknown; capacity finalization stays pending rather than asserting success from logical lengths. Existing recognized PROJECT.md history is updated only for verified data actions; absent registrations cannot be created from an unknown allocation threshold. Manual/unrecognized content remains pending for review. Historical source versions stay explicitly visible as preserved, not claimed released.

Automated tests use temporary NAS filesystem fixtures and an SDK-shaped in-memory TOS service. They cover capability failures, old versions, compressed keepers, no-overwrite recovery, changed dependencies, exact purge scope, interrupted copies, unknown deletion results, lifecycle controls, and unbounded transfer counters. They are **not real NAS/TOS acceptance**. Run explicit probes and full lifecycle tests only in user-authorized dedicated test directories/prefixes before declaring a particular backend validated. Developing or installing this skill never authorizes live-data cleanup.

Official API contract used by the adapter: [TOS Python SDK client](https://github.com/volcengine/ve-tos-python-sdk/blob/master/tos/clientv2.py) and [response models](https://github.com/volcengine/ve-tos-python-sdk/blob/master/tos/models2.py). The optional SDK is loaded only for native TOS operations.
