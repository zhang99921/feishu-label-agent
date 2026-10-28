// 流程状态独立于页面和采集设备，后续改变步骤时不修改库存协议。
export const FLOWS = Object.freeze({
  IN: {name: '入库', route: 'inbound', warehouse: true},
  OUT: {name: '出库', route: 'outbound', warehouse: false},
  MOVE: {name: '转仓', route: 'transfer', warehouse: true},
});
export const EDITABLE = 'DRAFT';

// 只调节只读进度查询；不持久化权限、不触发提交或恢复写操作。
export class ProgressPolling {
  constructor() { this.task = null; this.signature = null; this.unchanged = 0; this.errors = 0; }
  next(task, progress) {
    const signature = JSON.stringify([progress.state, progress.confirmed_steps, progress.step_count,
      progress.locations, progress.auth_required, progress.review_required, progress.failure_code]);
    this.unchanged = task === this.task && signature === this.signature ? Math.min(3, this.unchanged + 1) : 0;
    this.task = task; this.signature = signature; this.errors = 0;
    return [5000, 8000, 12000, 15000][this.unchanged];
  }
  failed(task, retryAfter = 0) {
    if (task !== this.task) { this.task = task; this.signature = null; this.unchanged = 0; this.errors = 0; }
    this.errors = Math.min(3, this.errors + 1);
    return Math.max([10000, 20000, 30000][this.errors - 1], retryAfter);
  }
}

export function retryAfterMilliseconds(value) {
  return typeof value === 'string' && /^[0-9]{1,2}$/.test(value) && Number(value) >= 1 && Number(value) <= 60
    ? Number(value) * 1000 : 0;
}

export function draft(action, owner, warehouse = '') {
  if (!Object.hasOwn(FLOWS, action) || !owner) throw Error('请选择业务并登录');
  return {version: 1, owner, created: Date.now(), action, warehouse,
    boxes: [], phase: EDITABLE, key: null, record: null};
}

export function addBoxes(state, values, max = 36) {
  if (state.phase !== EDITABLE) throw Error('本批已确认，不能修改箱号');
  const incoming = values.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  if (!incoming.length) throw Error('请先输入箱号');
  if (incoming.some(x => x.length > 200 || /\s/.test(x))) throw Error('箱号格式不正确');
  const combined = [...new Set([...state.boxes, ...incoming])];
  if (combined.length > max) throw Error(`一批最多${max}箱，请分开处理`);
  return {...state, boxes: combined};
}

export function freeze(state, key) {
  if (state.phase !== EDITABLE || !state.boxes.length) throw Error('请先添加箱号');
  if (FLOWS[state.action].warehouse && !['优福斯仓', '欣源仓'].includes(state.warehouse)) throw Error('请选择目标仓库');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(key)) throw Error('无法生成请求编号');
  return {...state, boxes: [...state.boxes], key, phase: 'SUBMITTING'};
}

export function payload(state) {
  if (!state.key || state.phase === EDITABLE) throw Error('请先确认本批货物');
  const fields = Object.fromEntries(state.boxes.map((code, i) => [`箱号${i + 1}`, code]));
  return FLOWS[state.action].warehouse ? {target_warehouse: state.warehouse, fields} : {fields};
}

export function restore(value, owner, now = Date.now()) {
  try {
    const s = JSON.parse(value);
    if (s.version !== 1 || s.owner !== owner || !Object.hasOwn(FLOWS, s.action) ||
        !Array.isArray(s.boxes) || s.boxes.length > 36 || new Set(s.boxes).size !== s.boxes.length ||
        s.boxes.some(x => typeof x !== 'string' || !x.trim() || x.length > 200 || /\s/.test(x)) ||
        !Number.isFinite(s.created) || now < s.created || (s.phase === 'DRAFT' && now - s.created > 43200000) ||
        !['DRAFT', 'SUBMITTING', 'RECORDED', 'PROCESSING', 'DONE', 'REVIEW'].includes(s.phase) ||
        !['', '优福斯仓', '欣源仓'].includes(s.warehouse) ||
        (s.phase !== 'DRAFT' && (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s.key || '') || !s.boxes.length)) ||
        (s.task !== undefined && !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s.task)) ||
        (s.record !== null && !/^[A-Za-z0-9]{1,200}$/.test(s.record))) return null;
    return s;
  } catch { return null; }
}
