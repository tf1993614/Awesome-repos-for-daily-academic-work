# Registration preservation and recovery

Keep the bundled Chinese template field names. English skill instructions do not change the default report/registration language.

## Planning

Planning generates a unique directory of drafts and a manifest containing original hashes, identities/timestamps, and parent identities. Read applicable local AGENTS.md instructions before application; scripts cannot interpret natural-language instructions.

Complete above-threshold projects require registration. Existing below-threshold registrations are refreshed too. Unknown allocation and incomplete scans remain pending. Verified standalone environments are not business projects.

New metadata uses supplied descriptions or pending values. Existing metadata must contain exactly one instance of each template field. Update only the unambiguous single capacity line, preserving all other UTF-8 content and cleaning history. Missing/ambiguous fields or wrapped capacity descriptions produce manual-review drafts. Inventory does not establish that cleaning occurred.

Git projects receive a local `/PROJECT.md` ignore rule while existing rules are preserved. Report already tracked metadata without modifying the index. Inventory does not commit or publish files.

## Application

Apply only within actual authorization. The CLI does not prompt; the agent distinguishes read-only inventory from a request to register/update. Preflight the entire manifest: restrict writes to confirmed project metadata, validate drafts and original fingerprints, and reject symlink ancestors/targets. Preserve originals under unique execution IDs and read them back before mutation.

Record each result separately and stop on the first failed action. Reapplication verifies and skips completed actions. If interruption left a changed file without verification evidence, inspect it and make a new plan rather than bypassing conflicts. Normal writes stage in the target directory and rename into place. Preserve existing permission bits where the filesystem supports them; new files respect the process umask. Backups use mode 0600 inside a private execution directory. Evaluate effective Git ignore behavior, including negations, rather than treating a matching line as proof that the file is ignored.

Only `fuse.tosutil` receives an unsupported-operation fallback: verify the original and backup, exclusively recreate the metadata, and read it back. Restore original bytes on failure when safe. Unexpected content or restoration failure stops with a recovery-required error and backup reference. This workaround never applies to business data and does not retry indefinitely.

After application, regenerate the report: verification compares current file contents with recorded results, not just old success flags. Capacity text identifies the acquisition interval.

## Placement repair

Pass exact redundant paths with repeated `plan-register --archive-registration PATH` options. Sources must be recognizable PROJECT.md files outside active project roots. Application also requires `--allow-registration-archive`. Use these flags only for an authorized placement repair, not simply because old registrations exist.

Copy originals into versioned backups, verify them, then remove the misplaced metadata. Placement repair never handles business data or recursively deletes directories.

Business cleanup is a separate workflow: read [cleanup-future.md](cleanup-future.md) before handling its events. Its durable operation log is authoritative; registration and fresh measurement are independently retryable finalization. Ordinary inventory plans still change capacity only and never advance cleaning dates.
