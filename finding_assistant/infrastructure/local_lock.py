# 跨平台本机文件锁：Windows 锁定一个字节，其他系统使用 flock。
# 非阻塞获取失败即报错；不协调其他主机，也不替代飞书侧的数据一致性能力。
"""Nonblocking cooperating-process file lock on one host, not distributed."""
import os


# 必须使用同一路径的锁文件；调用方负责线程可重入及解锁生命周期。
def acquire(stream):
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
    else:
        import fcntl
        fcntl.flock(stream.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)


# 释放对应文件锁，由 writer_gate 的 finally 分支保证调用。
def release(stream):
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
    else:
        import fcntl
        fcntl.flock(stream.fileno(),fcntl.LOCK_UN)
