"""Compatibility import; implementation lives in finding_assistant.application.workflow."""
import importlib
import sys

if __name__ == "__main__":
    import runpy
    runpy.run_module("finding_assistant.application.workflow", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("finding_assistant.application.workflow")
