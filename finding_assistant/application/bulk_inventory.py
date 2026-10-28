"""v3多箱计划的有界批量读写；逐箱意图/回执保留，未知结果只核实不重发。"""
from finding_assistant.domain.inventory_posting import PostingStopped

class BulkInventory:
    def __init__(self,engine):
        self.engine=engine;self.access=engine.access;self.repository=engine.repository

    def _observed(self,identity,steps):
        if steps[0]['kind']=='LEDGER':
            records=self.access.ledgers(identity,steps)
            return {s['ordinal']:records[s['fields']['事务号']] for s in steps}
        records=self.access.get_many(identity,steps[0]['kind'],[s['record_id'] for s in steps])
        return {s['ordinal']:[records[s['record_id']]] for s in steps}

    def run(self,identity,plan,owner):
        key=plan['source_key']
        for role in ('BOX','LEDGER','DETAIL'):
            all_steps=[s for s in self.repository.steps(key) if s['kind']==role]
            for offset in range(0,len(all_steps),36):
                self._group(identity,plan,owner,all_steps[offset:offset+36])
        self.engine._verify_all(identity,plan)
        self.engine._confirm_positions(identity,plan)
        self.repository.positions_confirmed(key,owner)
        for stored in self.repository.steps(key):
            if stored['kind']=='STATUS' and stored['state']!='CONFIRMED':self.engine._step(identity,plan,stored,owner)

    def _group(self,identity,plan,owner,stored_steps):
        if all(row['state']=='CONFIRMED' for row in stored_steps):return
        steps=[row['specification'] for row in stored_steps];key=plan['source_key']
        observed=self._observed(identity,steps);pending=[];confirmed=[]
        for stored,step in zip(stored_steps,steps):
            records=observed[step['ordinal']]
            if len(records)>1:raise PostingStopped('REMOTE_LEDGER_DUPLICATE')
            current=records[0] if records else None
            matched=current is not None and self.access.verify(current,step['after'],step['types'])
            if matched:
                if stored['remote_record_id'] and stored['remote_record_id']!=current['record_id']:
                    raise PostingStopped('REMOTE_RECORD_ID_CHANGED')
                if stored['state']=='PENDING' and step['kind']!='LEDGER' and not self.access.verify(current,step['before'],step['types']):
                    raise PostingStopped('UNOWNED_REMOTE_CHANGE')
                if stored['state']!='CONFIRMED':confirmed.append((step,current['record_id']))
                continue
            if stored['state']!='PENDING':raise PostingStopped('REMOTE_WRITE_RECONCILIATION_REQUIRED')
            if current is not None and (step['kind']=='LEDGER' or not self.access.verify(current,step['before'],step['types'])):
                raise PostingStopped('REMOTE_PRECONDITION_CHANGED')
            pending.append(step)
        # 对恢复结果同样复核来源/行映射，不因批量而略过约束。
        self.engine._guard_source(identity,plan)
        for step,rid in confirmed:self.repository.confirm(key,owner,step['ordinal'],rid)
        if not pending:return
        if steps[0]['kind'] in ('LEDGER','DETAIL'):
            boxes={s['box_record_id']:s for s in plan['steps'] if s['kind']=='BOX'}
            needed={s['box_record_id'] for s in pending}
            observed_boxes=self.access.get_many(identity,'BOX',sorted(needed))
            for bid in needed:
                expected=boxes[bid]
                if not self.access.verify(observed_boxes[bid],expected['after'],expected['types']):
                    raise PostingStopped('BOX_CHANGED_DURING_POSTING')
        # 全组意图先提交；只有所有回执及回读通过才逐箱确认。批量异常不推断原子性。
        self.repository.begin_steps(key,owner,[s['ordinal'] for s in pending])
        try:
            remote_ids=self.access.write_many(identity,pending)
            for step in pending:self.repository.response(key,owner,step['ordinal'],remote_ids[step['ordinal']])
            after=self._observed(identity,pending)
            for step in pending:
                records=after[step['ordinal']]
                if len(records)!=1 or records[0]['record_id']!=remote_ids[step['ordinal']] or not self.access.verify(records[0],step['after'],step['types']):
                    raise PostingStopped('REMOTE_POSTCONDITION_UNCONFIRMED')
            for step in pending:self.repository.confirm(key,owner,step['ordinal'],remote_ids[step['ordinal']])
        except Exception:
            for step in pending:self.repository.uncertain(key,owner,step['ordinal'],False)
            raise
