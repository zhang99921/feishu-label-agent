"""前置业务拒绝的持久回执；未知写入只回读，不重发。"""
from finding_assistant.domain.scan_submission import normalize_record, field_text, creator_id
from finding_assistant.domain.validation_rejection import rejection_note
from finding_assistant.domain.inventory_posting import PostingStopped
from finding_assistant.security.errors import AccessDenied, AuthorizationUnavailable


class ValidationFeedback:
    def __init__(self, gate, access, journal):
        self.gate, self.access, self.journal = gate, access, journal

    def apply(self, session_id, identity, submission, source, guard_alive, error=None):
        key = submission.source_key
        row = self.journal.get(key, identity)
        if row is None:
            self.access.validate_feedback(identity)
            row = self.journal.create(identity, submission, error.code, error.box_code,
                field_text(source['fields'].get('处理说明')), rejection_note(error.code, error.box_code))
        result = self.journal.summary(row)
        # 每次尝试及恢复都重新鉴权和核对输入，不能覆盖他人或用户已修改的流水。
        identity = self.gate.authorize(session_id, submission.action)
        current = self.access.source(identity, submission.source_record_id)
        fields = current['fields']
        candidate = {**current, 'fields': {**fields, '处理状态': '待处理'}}
        observed = normalize_record(self.journal.repository.base, self.journal.repository.scan_table, candidate)
        if (creator_id(fields.get('操作人')) != identity.open_id or not observed
                or observed.errors or observed.fingerprint != row['fingerprint']):
            return {**result, 'review_required': True}
        after = {'处理状态': '异常', '处理说明': row['note']}
        before = {'处理状态': '待处理', '处理说明': row['before_note']}
        types = self.access.REQUIREMENTS['STATUS']
        if self.access.verify(current, after, types):
            if row['state'] in ('RUNNING', 'UNKNOWN'):
                guard_alive()
                return self.journal.summary(self.journal.confirmed(identity, key))
            return {**result, 'review_required': row['state'] != 'CONFIRMED'}
        if row['state'] != 'PENDING' or not self.access.verify(current, before, types):
            return {**result, 'review_required': True}
        self.access.validate_feedback(identity)
        guard_alive()
        self.journal.mark(identity, key, 'RUNNING')
        try:
            self.access.write(identity, {'kind': 'STATUS', 'record_id': submission.source_record_id,
                'table_id': self.access.tables['STATUS'], 'fields': after, 'types': types})
            current = self.access.source(identity, submission.source_record_id)
            fields = current['fields']
            observed = normalize_record(self.journal.repository.base, self.journal.repository.scan_table,
                {**current, 'fields': {**fields, '处理状态': '待处理'}})
            if (not self.access.verify(current, after, types) or not observed or observed.errors
                    or observed.fingerprint != row['fingerprint']
                    or creator_id(fields.get('操作人')) != identity.open_id):
                raise PostingStopped('FEEDBACK_POSTCONDITION_UNCONFIRMED')
            guard_alive()
            return self.journal.summary(self.journal.confirmed(identity, key))
        except Exception as fault:
            definitive = isinstance(fault, AccessDenied) and not isinstance(fault, AuthorizationUnavailable)
            return self.journal.summary(self.journal.mark(identity, key, 'REJECTED' if definitive else 'UNKNOWN'))
