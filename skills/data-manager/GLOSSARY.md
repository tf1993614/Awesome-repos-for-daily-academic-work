# Managed Storage

This context describes responsibility for stored data, capacity, and project registration. Inventory is not cleanup.

## Language

**Managed scope**:
Confirmed directories for which the user accepts management responsibility, including their in-scope contents regardless of individual file ownership.
_Avoid_: UID-owned data, every accessed directory

**Ownership candidate**:
A location with evidence suggesting management responsibility that has not been confirmed.
_Avoid_: confirmed owner

**Container**:
A directory organizing users, machines, backups, or projects without itself representing a project.
_Avoid_: large project by default

**Project**:
Data and work with a common business or research purpose, potentially present at multiple locations.
_Avoid_: physical directory

**Storage copy**:
A project's contents at one storage location, with its own capacity and registration history. Copies need not be identical.
_Avoid_: verified duplicate, redundant copy

**Project root**:
The outermost directory defining one registered storage copy, below containers and above internal data directories.
_Avoid_: largest directory, deepest oversized directory

**Total allocation**:
Reported allocation for a scope, counting reliably identified shared objects once within that scope. Mount reports need not equal backend consumption or billing.
_Avoid_: reclaimable space, additive project size

**Excluded allocation**:
Allocation referenced exclusively by verified environments or caches. Content also referenced by business paths remains business allocation.
_Avoid_: all hidden data

**Business allocation**:
Total allocation after excluded allocation is removed; this determines the registration threshold.
_Avoid_: logical size

**Logical size**:
File lengths summed by path, including each hardlink path separately, rather than allocated space.
_Avoid_: physical consumption

**Unassigned content**:
Business content without an established project boundary, including loose files under containers.
_Avoid_: ignored data, implicit home project

**Registration**:
A storage copy's capacity and management record, including its cleaning history.
_Avoid_: cleanup history reset on every scan
