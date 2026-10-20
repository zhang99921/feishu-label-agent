"""Compatibility import; implementation lives in finding_assistant.adapters.feishu.client."""
import importlib
import sys

if __name__ == "__main__":
    import runpy
    runpy.run_module("finding_assistant.adapters.feishu.client", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("finding_assistant.adapters.feishu.client")
