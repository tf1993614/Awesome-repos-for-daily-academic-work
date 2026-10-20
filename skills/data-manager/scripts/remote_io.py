"""Shared remote read pacing and accounting; transfer totals have no ceiling."""
from __future__ import annotations

import threading
import time

DEFAULTS = {'workers': 4, 'read_bytes_per_second': 64 * 1024 * 1024}


class Traffic:
    def __init__(self, options=None, totals=None, persist=None):
        self.options = dict(DEFAULTS, **(options or {}))
        for key, value in self.options.items():
            if key not in DEFAULTS or type(value) is not int or value < 1:
                raise ValueError('Remote I/O accepts positive workers and read_bytes_per_second only')
        if self.options['workers'] > 64:
            raise ValueError('Remote workers cannot exceed 64')
        self.totals = totals if totals is not None else {'read_bytes': 0, 'copy_attempted_bytes': 0}
        self.persist = persist
        self.lock = threading.Lock()
        self.next_read = time.monotonic()

    def read(self, size):
        with self.lock:
            current = time.monotonic()
            start = max(current, self.next_read)
            self.next_read = start + size / self.options['read_bytes_per_second']
            self.totals['read_bytes'] = self.totals.get('read_bytes', 0) + size
            if self.persist:
                self.persist()
        delay = start - current
        if delay > 0:
            time.sleep(delay)

    def copy(self, size):
        with self.lock:
            self.totals['copy_attempted_bytes'] = self.totals.get('copy_attempted_bytes', 0) + size
            if self.persist:
                self.persist()


class Reader:
    def __init__(self, stream, traffic):
        self.stream = stream
        self.traffic = traffic

    def read(self, size=-1):
        # Consumers in this skill use bounded reads; bound generic whole reads too.
        if size is None or size < 0:
            blocks = []
            while True:
                block = self.read(1024 * 1024)
                if not block:
                    return b''.join(blocks)
                blocks.append(block)
        blocks = []
        while size:
            block = self.stream.read(min(size, 1024 * 1024))
            self.traffic.read(len(block))
            if not block:
                break
            blocks.append(block); size -= len(block)
        return b''.join(blocks)

    def __getattr__(self, name):
        return getattr(self.stream, name)


_traffic = Traffic()


def configure(config, totals=None, persist=None):
    global _traffic
    _traffic = Traffic(config.get('remote_io'), totals, persist)
    return _traffic


def reader(stream, path):
    import inventory as inv
    kind = inv.mount_for(str(path), inv.mounts())['fstype']
    return Reader(stream, _traffic) if kind in inv.REMOTE or kind.startswith('fuse.') else stream
