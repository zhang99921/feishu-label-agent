"""Compatibility import; implementation lives in finding_assistant.adapters.feishu.pooled_client."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("finding_assistant.adapters.feishu.pooled_client")
