"""Compatibility import; implementation lives in finding_assistant.application.administration."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("finding_assistant.application.administration")
