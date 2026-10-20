import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from finding_assistant.infrastructure import local_lock


class LocalProcessLockTests(unittest.TestCase):
    def test_other_process_is_excluded_and_can_acquire_after_release(self):
        code = """
import sys
from finding_assistant.infrastructure import local_lock
with open(sys.argv[1],'a+b') as stream:
    stream.seek(0)
    try:
        local_lock.acquire(stream)
    except OSError:
        print('BUSY')
    else:
        local_lock.release(stream)
        print('ACQUIRED')
"""
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/".writer.lock"
            path.write_bytes(b"0")
            def child():
                return subprocess.run([sys.executable,"-I","-c",code,str(path)],
                    capture_output=True,text=True,timeout=10,check=True).stdout.strip()
            with path.open("a+b") as stream:
                stream.seek(0)
                local_lock.acquire(stream)
                try:
                    self.assertEqual(child(),"BUSY")
                finally:
                    stream.seek(0)
                    local_lock.release(stream)
            self.assertEqual(child(),"ACQUIRED")
