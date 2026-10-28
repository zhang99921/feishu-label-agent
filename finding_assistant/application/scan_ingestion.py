"""将现有表单提交登记到后台任务库，不重复实现原定时程序的库存过账。"""
from collections import Counter

from finding_assistant.domain.scan_submission import normalize_record


class ScanIngestion:
    def __init__(self, repository, base_token, table_id, *, include_blank_status=False):
        self.repository = repository
        self.base_token = base_token
        self.table_id = table_id
        self.include_blank_status = include_blank_status

    def run(self, records):
        counts = Counter()
        for record in records:
            counts["observed"] += 1
            submission = normalize_record(self.base_token, self.table_id, record,
                include_blank_status=self.include_blank_status)
            if submission is None:
                counts["ignored"] += 1
                continue
            result = self.repository.enqueue(submission)
            counts[result] += 1
        # received/queued 仅表示后台已接收，绝不回写“已入账”或报告库存操作成功。
        return dict(counts)
