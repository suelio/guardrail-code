"""Explicit memory reclamation utilities to keep RAM footprint minimal after scans."""

import ctypes
import gc
import os
import sys


def collect_memory(trim_working_set: bool = True) -> int:
    """Run full-generation Python garbage collection and optionally trim OS working set."""
    collected = gc.collect(2)
    if not trim_working_set:
        return collected

    try:
        if sys.platform.startswith("win"):
            # Release unused heap pages back to Windows without impacting live objects.
            kernel32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            handle = kernel32.GetCurrentProcess()
            psapi.EmptyWorkingSet(handle)
        elif sys.platform.startswith("linux"):
            libc = ctypes.CDLL("libc.so.6")
            if hasattr(libc, "malloc_trim"):
                libc.malloc_trim(0)
    except Exception:
        # Never fail application flow if OS-level heap trimming is unavailable.
        pass
    return collected
