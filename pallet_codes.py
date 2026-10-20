"""Compatibility import; implementation lives in finding_assistant.application.pallets."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("finding_assistant.application.pallets")
