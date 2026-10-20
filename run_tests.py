"""Run local automated tests only; no live Feishu writes."""
import unittest

MODULES = ['local_reliability_test', 'test_feishu_probe', 'test_workflow_store', 'test_pallet_codes', 'test_backup_restore', 'test_quantity_admin', 'test_read_scope', 'test_restore_schema_v2', 'test_pooled_client', 'test_parallel_reads', 'test_feishu_login', 'test_feishu_permissions', 'test_demo_role_audit', 'test_mcp_boundaries', 'test_document_access', 'test_http_api', 'test_local_process_lock', 'test_http_workflow_integration']

if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(MODULES))
    raise SystemExit(not result.wasSuccessful())
