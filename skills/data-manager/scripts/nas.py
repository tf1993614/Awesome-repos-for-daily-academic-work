"""Capability evidence for NAS; probes only mutate their own temporary fixtures."""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import tempfile

import inventory as inv

FILESYSTEMS = {'nfs', 'nfs4', 'cifs', 'smb3'}


def probe(root, output, access_evidence):
    import cleanup
    root = cleanup.private_directory(root)
    if output is not None:
        output = Path(inv.absolute(str(output))); inv.no_symlink_path(output)
        cleanup.local(output.parent, inv.mounts())
        if inv.within(str(output), str(root)) or output.exists():
            raise ValueError('Capability output must be a new local file outside quarantine')
    mount = inv.mount_for(str(root), inv.mounts())
    if mount['fstype'] not in FILESYSTEMS or not access_evidence.strip():
        raise ValueError('NAS mount and explicit server-side access review evidence required')
    result = {'schema_version': 1, 'kind': 'nas-capabilities', 'root': str(root),
              'mount': mount, 'root_identity': cleanup.identity_of(root),
              'access_evidence': access_evidence, 'checked': inv.now(), 'supported': False}
    # TemporaryDirectory only removes this newly created fixture, never user data.
    try:
        with tempfile.TemporaryDirectory(prefix='.data-manager-probe-', dir=root) as name:
            folder = Path(name); source = folder / 'source'; dest = folder / 'dest'
            source.write_bytes(b'data-manager NAS capability fixture\n')
            dest.write_bytes(b'occupied\n')
            with source.open('rb') as stream:
                os.fsync(stream.fileno())
            original = source.stat()
            with cleanup.locks([folder]):
                try:
                    cleanup.rename_noreplace(source, dest)
                except FileExistsError:
                    pass
                else:
                    raise ValueError('NAS rename overwrote an occupied destination')
                if dest.read_bytes() != b'occupied\n' or source.stat().st_ino != original.st_ino:
                    raise ValueError('NAS no-replace probe changed file identity or content')
                dest.unlink()
                cleanup.rename_noreplace(source, dest)
                moved = dest.stat()
                if (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns) != (
                        moved.st_dev, moved.st_ino, moved.st_size, moved.st_mtime_ns):
                    raise ValueError('NAS does not preserve file identity across rename')
                cleanup.rename_noreplace(dest, source)
                source.unlink(); cleanup.sync_directories(folder)
        cleanup.sync_directories(root)
        result['supported'] = True
    except (OSError, ValueError) as exc:
        result['error'] = str(exc)
    if output is not None:
        cleanup.durable(output, result)
    return result


def validate(path, config, rows):
    import cleanup
    mount = inv.mount_for(str(path), rows)
    if mount['fstype'] not in FILESYSTEMS:
        raise ValueError('Unsupported remote mutation filesystem')
    for report in config.get('nas_capabilities', []):
        inv.no_symlink_path(report)
        cleanup.local(Path(report).parent, rows)
        evidence = cleanup.load(report)
        if evidence.get('mount') != mount:
            continue
        root = evidence['root']
        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(evidence['checked'])).total_seconds()
        if (evidence.get('kind') != 'nas-capabilities' or evidence.get('schema_version') != 1
                or evidence.get('supported') is not True or not evidence.get('access_evidence')
                or not 0 <= age <= config.get('nas_capability_max_age_seconds', 86400)
                or cleanup.identity_of(root) != evidence['root_identity']):
            raise ValueError('NAS capability evidence changed, expired, or failed')
        cleanup.private_directory(root)
        return evidence
    raise ValueError('NAS requires a successful dedicated-root capability probe and access review')
