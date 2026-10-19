# Future cleanup — specification only

Version 1 does not implement duplicate search, quarantine, purge, or business-file deletion. This document defines extension requirements, not an executable workflow or permission to act.

1. Group regular-file candidates by length; confirm full contents with strong full-file hashing and final byte comparison where storage consistency requires it. Names, equal lengths, and sampled hashes do not prove duplication. Revalidate identity, length, timestamps, and retained-copy integrity before actions.
2. Separate hardlinks, working copies, and deliberate backups. A shared project ID or equal contents does not establish redundancy. Obtain authorization for exact handled paths and retained copies; reuse existing authorization only within its scope.
3. Default to quarantine on the same filesystem, preserving original/quarantine paths and content identity. Unsupported remote semantics require a separate choice; do not silently replace this with cross-filesystem copy-and-delete.
4. Quarantine still occupies storage. Permanent purge requires an explicit instruction for the reviewed quarantine set. Stop on changed files, missing retained copies, scope violations, or uncertain mutations, preserving the operation log.
5. Remeasure affected storage copies and quarantine. Distinguish project allocation decrease, quarantine allocation, and verified storage release; hardlinks, snapshots, and object versions may retain space.
6. Update each affected registration from actual results, accurately distinguishing quarantine and purge. Preserve cleanup events and history, record partial failures, and never substitute estimated reclaimed bytes for measurements. Inventory alone never refreshes cleaning dates.
