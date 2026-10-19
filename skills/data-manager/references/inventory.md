# Profiles, accounting, and coverage

Profiles use JSON schema version 1. Copy the bundled example into a working area; keep runtime state outside the skill package.

| Field | Meaning |
|---|---|
| `owner` | Display name for new registrations |
| `uid`, `aliases` | Discovery hints; aliases match exactly |
| `managed_roots` | Non-overlapping absolute roots, each with `path` and ownership `evidence` |
| `containers` | Confirmed grouping directories, whose direct files remain unassigned |
| `projects` | Non-overlapping roots, each with `path` and boundary `evidence`; optional `project_id`, `title`, `description` |
| `system_paths` | Environment/cache paths inside managed scope, each with `path` and `evidence` |
| `out_of_scope` | Explicit excluded subtrees |
| `include_mounts` | Explicitly included nested mount targets |
| `threshold_bytes` | Strict business-allocation threshold; default 100000000000 |
| `local_workers`, `remote_workers` | Concurrent directory reads; defaults 4 and 8, maximum 64 |

Managed/project roots use absolute paths without symbolic-link ancestors. Overlapping managed roots are rejected; use a single root with explicit nested mounts or separate non-overlapping scopes. Project roots cannot overlap or also be containers. Association labels are not content comparisons.

Automatic environment evidence is restricted to a `conda-meta` directory or `pyvenv.cfg` file. Confirm other environments and caches through `system_paths`. Name-only suspects remain business content with a classification-pending issue. Hidden business projects and Git data are not automatically excluded.

## Discovery

Default discovery checks mount roots to depth two. `--full` searches accessible directory trees outside known scope and explicit exclusions. Symbolic links and virtual filesystems are not followed. Source/device/root metadata identifies exact mount aliases. UID hits are used only on supported reliable filesystems; all hints remain unconfirmed candidates.

Discovery never edits the profile. Review candidates and record confirmations separately. Bounded checks, unreadable regions, and interruption remain partial coverage; a user's answer about a few candidates cannot prove global discovery complete. Discovery restarts after interruption; resumable checkpoints apply to capacity scans. Never claim unmounted or unavailable disks were inspected.

## Measurement

Workers read metadata only; the coordinator commits each directory into SQLite. Ctrl-C preserves completed checkpoints and unfinished tasks. Resume requires the same profile and mount table and retries failed subtrees. A resumed run spans an observation interval, not a frozen snapshot. Use a fresh output directory for a fresh scan.

Read failures, changed directories, and unexpected nested mounts mark affected scopes partial. Follow nested mounts only when included explicitly; ancestor aliases are cycles. Explicit exclusions, virtual mounts, and the output directory are excluded.

Logical length and file counts are by path; directory entry lengths are not file content. Symlink metadata is counted without reading its target. Allocation uses `st_blocks * 512`; stable device/inode identities deduplicate within each directory and separately in the global union. Unsupported identities remain path-specific. Reflinks, snapshots, compression, and backend deduplication cannot be inferred from these metadata.

An object with any business reference is business allocation; exclusively excluded references are excluded allocation. Directory allocation is included. Project totals may overlap and cannot be summed as a global total. Remote allocation is mount-reported, not guaranteed reclaimable or billable bytes. Unknown allocation blocks threshold decisions; unreadable content is not zero-sized.

## Evidence and output

The database retains scope, mount snapshot, directory tasks, metadata, issues, and computed measures. CSV size columns are bytes; reports display decimal GB. Reports distinguish scope discovery, scan completion, and registration state. `unassigned.json` includes loose files and proposed project roots. Existing metadata is unverified until checked against execution evidence.

Scan exit code 2 indicates partial coverage, 130 interruption, and 1 an input/execution error. Successful measurement may still have registration pending. Review issues and unassigned content before claiming completion. Tests use temporary fixtures, not another real full-disk scan.
