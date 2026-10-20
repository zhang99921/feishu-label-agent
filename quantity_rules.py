"""Compatibility import; implementation lives in finding_assistant.domain.quantity_rules."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("finding_assistant.domain.quantity_rules")
