"""跨表只读校验预览；不提交流水，不分配行码，不入账或回写状态。"""
from dataclasses import asdict

from finding_assistant.domain.inbound_rules import validate_inbound,decide_inbound_batch
from finding_assistant.adapters.feishu.business_tables import BusinessDataUnavailable


class InboundValidationService:
    def __init__(self,gate,reader):
        self.gate,self.reader=gate,reader

    def validate(self,session_id,box_codes,location_code,warehouse):
        identity=self.gate.authorize(session_id,'IN')
        if self.reader is None:
            raise BusinessDataUnavailable('BUSINESS_TABLES_NOT_CONFIGURED')
        if not isinstance(box_codes,(list,tuple)) or not 1<=len(box_codes)<=36:
            raise ValueError('ONE_TO_36_BOXES_REQUIRED')
        if any(not isinstance(v,str) or not v.strip() or len(v)>200 for v in (*box_codes,location_code,warehouse)):
            raise ValueError('INVALID_INBOUND_LOOKUP_INPUT')
        codes=tuple(dict.fromkeys(c.strip() for c in box_codes))
        # 两份查询全部成功后才标记完成，任何读取错误均上抛503/403，不用空数组代替。
        boxes=self.reader.boxes(identity,codes)
        locations=self.reader.locations(identity,(location_code.strip(),))
        check=validate_inbound(codes,location_code,boxes,locations,
            box_lookup_complete=True,location_lookup_complete=True,expected_warehouse=warehouse)
        decision=decide_inbound_batch(check)
        return {'decision':asdict(decision),'issues':[asdict(i) for i in check.issues],
                'checked_boxes':check.checked_boxes,'lookups_complete':check.lookups_complete,
                'feedback_suggestion':decision.feedback_fields,'inventory_posted':False,'read_only':True}
