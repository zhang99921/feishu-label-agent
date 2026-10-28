-- 多来源/旧区域转仓仍保存来源快照，但不伪造唯一旧批次外键。
DO $$
DECLARE constraint_name text;
BEGIN
 SELECT conname INTO STRICT constraint_name FROM pg_constraint
 WHERE conrelid='finding_assistant.position_reservations'::regclass AND contype='c'
 AND pg_get_constraintdef(oid) LIKE '%source_reservation_id%'
 AND pg_get_constraintdef(oid) LIKE '%MOVE%';
 EXECUTE format('ALTER TABLE finding_assistant.position_reservations DROP CONSTRAINT %I', constraint_name);
END $$;
ALTER TABLE finding_assistant.position_reservations ADD CONSTRAINT position_transfer_source_snapshot
CHECK (action<>'MOVE' OR source_reservation_id IS NOT NULL OR
 (jsonb_typeof(sources)='array' AND jsonb_array_length(sources)>0));
