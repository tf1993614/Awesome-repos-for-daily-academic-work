---
name: data-manager
description: Inventory user-managed storage, maintain project PROJECT.md registrations, and detect duplicate files or compressed/uncompressed equivalents. Use for storage inventories, ownership discovery, reviewed local quarantine, recovery, and separately authorized purge. Remote storage supports inventory and duplicate detection only.
---

# Data Manager

Inventory by **management responsibility**, register each **storage copy**, and keep ownership evidence separate from coverage evidence. Read [GLOSSARY.md](GLOSSARY.md) when interpreting these terms.

## Establish scope and boundaries

1. Inspect mounts and the existing profile. For routine inventories, use confirmed managed roots and check for mount changes. Expand discovery only for a requested full search or to establish a new profile.
2. UID and exact directory-name matches identify candidates, not confirmed responsibility. CIFS and object-storage mounts often assign one UID to everyone. Inspect evidence, ask about material ambiguity, and preserve previous user confirmations.
3. Distinguish containers from projects. Propose project roots, resolve ambiguous boundaries, and persist the evidence. Register `home/A/B` at A when A is the project, even when B contains most data. Backup machine names and fixed nesting depth do not establish boundaries.
4. Start new profiles from [assets/example-profile.json](assets/example-profile.json). Reuse a host-specific profile only for its recorded account and host after verifying its paths and mount sources. Personal ownership claims are not portable; keep host-specific profiles outside the skill package.

Read [references/inventory.md](references/inventory.md) before first execution, modifying a profile, interpreting shared hardlinks, or resuming a scan.

## Inventory

Use `scripts/data_manager.py`; subcommand `--help` is the authoritative flag reference. Resolve the script relative to this skill. Keep each run in a fresh output directory, preferably outside business projects.

```bash
python3 scripts/data_manager.py discover --config PROFILE.json --output DISCOVERY_DIR
python3 scripts/data_manager.py scan --config PROFILE.json --output RUN_DIR
python3 scripts/data_manager.py report --run RUN_DIR
```

Use `discover --full` for an explicit full search. Resume an interrupted scan with `scan --resume`, the identical profile, and unchanged mounts. Report unreadable locations and bounded search coverage explicitly.

- Require registration when **business allocated bytes strictly exceed 100,000,000,000** by default. Logical size is reference information, not the threshold.
- Report total, excluded, business allocation, and logical bytes. Deduct verified environments/caches even inside projects. Names such as `env`, `cache`, or `software`, and hidden attributes alone, are not evidence.
- Label remote values as mount-reported, not backend physical consumption or billing. Unknown allocation stays unknown and blocks automatic threshold decisions.
- Deduplicate reliable hardlinks independently per directory and in a separate global union. Project totals may overlap. Distinct storage backups count separately; symbolic links are not followed.
- Keep unassigned direct files and ambiguous project candidates visible. Large loose files remain pending: leave them in place and do not register the entire home as a substitute project.

## Registrations

Read [references/registration.md](references/registration.md) before planning/applying registrations, repairing placement, handling unusual metadata, or writing to TOS.

```bash
python3 scripts/data_manager.py plan-register --run RUN_DIR
python3 scripts/data_manager.py apply-register --manifest MANIFEST.json
python3 scripts/data_manager.py report --run RUN_DIR
```

Review drafts, pending items, and applicable local instructions before applying. An existing request to create/update registrations already authorizes that metadata work; avoid redundant confirmation. A read-only inventory request does not authorize writes. Resolve actual runtime permission restrictions when encountered.

Preserve manual content and cleaning history. Inventory refreshes capacity, not the last-cleaned date. Keep existing registrations below the threshold. Unrecognized formats receive review drafts rather than whole-file rewrites. Associate storage copies only when supported by evidence; association does not prove duplicate contents or redundancy.

Placement repair is an explicit metadata operation: list exact redundant PROJECT.md paths, back them up, and remove them only within authorized repair scope. Business files are never repair inputs.

## Completion evidence

Report management scope/exclusions, discovery coverage, measurement status/unknowns, and registration verification separately. Success in one phase does not establish another. Link the Markdown report, project CSV, and full directory CSV. State the scope of completion, observed totals, backup-copy accounting, and unresolved items. Read back resulting metadata; historical success flags alone are insufficient.

## Duplicate detection and cleanup

Read [references/cleanup-future.md](references/cleanup-future.md) before duplicate detection, preparing cleanup selections, isolation, recovery, purge, or resolving interrupted operations. Content equivalence is evidence, not proof of business redundancy. Keep compressed copies when verified against extracted contents. Review exact handled paths, retained dependencies, and attribute restoration limits.

Only independent regular files in confirmed local projects can be handled. Stop related writers. Quarantine requires a private dedicated root outside all projects on the same mount; it still occupies storage. Restore rejects existing original paths. Purge requires an explicit instruction for the exact reviewed quarantine set; quarantine authorization does not authorize purge. Remote-only retained copies cannot support local cleanup. Hardlinks remain report-only.

Use operation logs as mutation evidence. Fresh scans cover affected projects and quarantine, not all managed storage. Retry failed measurement/registration finalization without repeating data actions. Inventory alone never updates cleaning dates. Installing, developing, or testing the skill does not authorize operations on live datasets.

## Maintenance

Run `python3 -m unittest discover -s tests -v` from the skill directory and the installed skill-creator validator after changes. Consult the relevant decision in `docs/adr/` before changing ownership, registration-unit, or accounting semantics.
