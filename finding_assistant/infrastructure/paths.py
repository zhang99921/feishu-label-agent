"""All cooperating local server processes must use the SAME state directory.

The source-checkout default preserves existing experiment files. Installed
deployments must explicitly configure FINDING_ASSISTANT_STATE_DIR; this does
not provide distributed locking or a new inventory database.
"""
import os
from pathlib import Path

STATE_DIR = Path(os.environ.get("FINDING_ASSISTANT_STATE_DIR",Path(__file__).resolve().parents[2])).resolve()
