# Duplicate content, quarantine, recovery, and purge

This reference describes implemented commands, not permission to handle live data. Resolve scripts relative to the skill; `--help` is the flag reference. Reports and registrations remain Chinese by default.

## Detect and review

Start with a capacity scan. Use fresh output directories outside projects and quarantine:

```bash
python3 scripts/data_manager.py find-duplicates --run RUN --output DUPLICATES
```

Equal lengths and complete SHA-256 narrow candidates; final byte comparisons establish content equality. Special files are rejected even when an older inventory called them `file`. Symbolic links are not followed. Hardlinks are listed separately. Names, project IDs, and equal contents do not establish redundant business uses.

Supported formats: gzip, bzip2, xz, ZIP, tar, tar.gz, tar.bz2, tar.xz, tgz, tbz2, txz. Compressed tar matches both an uncompressed `.tar` and individual members. Members match disk contents regardless of names; new or changed extracted files remain untouched. No files are extracted and nested archives are not recursively expanded.

Every stage validates the whole relied-on archive, including unrelated members and compression checksums. Evidence is shared across members within a stage and invalidated by changes. Hashing and final byte comparisons may require multiple full passes. Unsafe or duplicate paths, links, sparse tar entries, encryption, corruption, and unsupported formats remain pending. Default limits are 1 TiB of expanded content and 1,000,000 members per archive; change `--max-expanded` and `--max-members` explicitly. Partial detection exits 2; its verified matches remain individually reviewable.

Review `duplicates.json`, `duplicates.csv`, `REPORT.md`, and hardlink records. Only confirmed project files with one hardlink may be handled through this mounted workflow. Local keepers must be local in-scope business files; remote-only retained copies cannot support local cleanup. NAS requires same-mount keepers and successful capability evidence. Read [remote-cleanup.md](remote-cleanup.md) before NAS mutations or native TOS work; its object-copy and version rules are separate from mounted-file identity rules.

## Select exact paths

Use paths and keeper references from verified detection matches. `member` is null for a whole file or decoded payload; use the exact member name for `kind: member`.

```json
{
  "schema_version": 1,
  "writers_stopped": true,
  "actions": [{
    "target": "/data/project/sample.fastq",
    "keeper": {"kind": "payload", "path": "/data/project/sample.fastq.gz", "member": null},
    "quarantine_root": "/data/.quarantine",
    "role": "redundant_data",
    "reason": "Verified extracted data no longer needed for analysis",
    "attributes_reviewed": true
  }]
}
```

`role` is `redundant_data`, `working_copy`, or `backup`, and every action requires a reason. Selecting a working copy or backup explicitly acknowledges that its current use is unnecessary. `attributes_reviewed` acknowledges byte-level preservation only: inspect modes, uid/gid, xattr names and unknown ACL restoration. Compressed data need not preserve file attributes or the original path.

Stop writers to targets and keepers before planning and throughout execution. Checks detect changes; directory locks only coordinate this tool. Set `writers_stopped` only when this prerequisite is met, and reconfirm before later recovery or purge.

Provide an existing dedicated account-owned mode-0700 quarantine root outside all projects, on the same mount/filesystem as targets. An explicitly reviewed root may be outside managed scope without expanding responsibility. Roots must not overlap; operation outputs must be local, outside projects, and disjoint from quarantine roots. Unsupported semantics stop execution rather than trigger copy-and-delete.

```bash
python3 scripts/data_manager.py plan-cleanup --duplicates DUPLICATES --selection SELECTION.json --output OPERATION
python3 scripts/data_manager.py apply-cleanup --manifest OPERATION/manifest.json
```

Review the manifest and applicable local AGENTS.md before applying. The CLI does not prompt; the agent applies only within actual authorization for exact paths and keepers. A keeper cannot also be a handling target. Quarantine moves individual files while preserving their file objects; empty project directories are retained.

## Recover or permanently purge

```bash
python3 scripts/data_manager.py restore-cleanup --operation OPERATION
python3 scripts/data_manager.py plan-purge --cleanup OPERATION --output PURGE_PLAN
python3 scripts/data_manager.py purge --manifest PURGE_PLAN/manifest.json
```

Recovery verifies isolated contents and restores all still-quarantined entries. Occupied original paths or changed original parents block it. Already restored or purged entries are not moved. Recovery can rescue an intact isolated file even if its keeper has since disappeared; purge still requires the keeper.

Purge planning deletes nothing. Review its exact `paths` and obtain explicit authorization for that set before invoking purge. Quarantine authority does not authorize permanent deletion. The purge manifest binds operation identity and verified quarantined fingerprints. Changed files, missing keepers, unsupported storage, or uncertain mutation results block execution. There is no direct business-file deletion or recursive directory-removal command.

## Evidence, interruption, and completion

Private operation directories contain `manifest.json` for scope and `state.json` for durable intentions, verified outcomes, measurements, and finalization. Each operation has a unique ID and exact original/quarantine mappings. Mutations use anchored directory handles and atomic no-replace moves, never overwriting rename or copy-delete fallback.

A per-profile sidecar defaults to `PROFILE.json.cleanup.json`; its exact `registry` path is in the manifest. It persists quarantine roots and runtime paths before mutations. Keep it on supported local storage outside projects and quarantine; a remotely stored profile needs an explicit local `cleanup_registry`. Existing files must be recognized tool registries, never arbitrary business JSON. Optional profile fields `quarantine_roots`, `runtime_paths`, `cleanup_registry`, and `cleanup_registries` support explicit roots and additional registry discovery. Missing optional registries are tolerated; malformed or unreadable existing registries fail rather than silently drop protection. Preserve registries while any quarantine sets remain.

Registered quarantine/runtime paths are excluded from duplicate handling and unassigned-project suggestions. New runtime directories also carry a `.data-manager-runtime.json` marker, so historical outputs remain recognizable before any cleanup consumes them. List older unmarked outputs in profile `runtime_paths`. In-scope quarantine remains counted in global allocated/business bytes; it is not an environment exclusion or released space. Cleanup reports measure it separately.

Verified completed entries are checked and skipped on reapplication; known unstarted entries may continue. A surviving `*_intent` status means an interrupted mutation is uncertain: automatic execution, recovery, and purge stop. Use `reconcile-cleanup --operation OPERATION` to inspect interrupted moves without business-file mutations. Exact content/object identity and both locations can establish completed or unstarted moves; missing/conflicting identities and uncertain purge results stay pending. Preserve the log; do not erase intentions or fabricate verification evidence to force retries.

```bash
python3 scripts/data_manager.py report-cleanup --operation OPERATION
```

This verifies current known results and retries failed measurement/registration finalization only. Fresh before/after scans cover affected projects and dedicated quarantine roots; older global scans remain historical. Unknown allocation or incomplete measurement leaves finalization pending.

`files.csv`, `report.json`, and `REPORT.md` show exact file outcomes, project allocation decrease, quarantine allocation, and observed filesystem available-space change. Attributable physical release remains unknown: open file handles, shared extents, snapshots, and backend accounting can retain space. Never substitute logical lengths or estimated savings for measurements. Reports read back the most recent verified registration contents; later manual changes leave registration pending and are not overwritten automatically.

Existing PROJECT.md files preserve manual text and history, appending operation-keyed quarantine/recovery/purge events and partial results. New registrations still follow the business-allocation threshold; unregistered smaller projects retain history in the operation log. Only verified actions advance cleaning history; inventory does not. Malformed metadata leaves review drafts and pending finalization. Metadata retries never repeat successful data operations.

Exit codes: 0 complete, 2 partial detection or pending cleanup/finalization, 1 validation/execution failure, 130 interruption. Successful data operations with failed finalization remain incomplete. Test only temporary fixtures.
