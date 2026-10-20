"""Nonblocking cooperating-process file lock on one host, not distributed."""
import os


def acquire(stream):
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
    else:
        import fcntl
        fcntl.flock(stream.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)


def release(stream):
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
    else:
        import fcntl
        fcntl.flock(stream.fileno(),fcntl.LOCK_UN)
