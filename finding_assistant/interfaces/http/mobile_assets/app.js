import {renderLocationCard} from './location-card.mjs';
import {FLOWS, draft, addBoxes, freeze, payload, restore, ProgressPolling, retryAfterMilliseconds} from './model.mjs';
import {scanBox, scannerReady} from './scanner.mjs';

const $ = id => document.getElementById(id);
const STORAGE = 'finding-assistant.mobile.v1';
const PANELS = ['home', 'editor', 'review-panel', 'task', 'query'];
let config, identity, state = null, busy = false, timer = null, reading = false;
let queryParams = null, queryOffset = 0, queryBusy = false, detailEpoch = 0;
const polling = new ProgressPolling();

function notice(message = '') { $('notice').textContent = message; }
function show(panel) { PANELS.forEach(id => $(id).hidden = id !== panel); }
function save() {
  try { if (state) sessionStorage.setItem(STORAGE, JSON.stringify(state)); else sessionStorage.removeItem(STORAGE); }
  catch { throw Error('浏览器无法保存本批任务，请先允许本站会话存储'); }
  $('resume').hidden = !state;
}
function csrf() {
  const parts = document.cookie.split('; ').filter(x => x.startsWith('scan_csrf='));
  if (parts.length !== 1) throw Error('登录已失效，请重新登录');
  return decodeURIComponent(parts[0].slice('scan_csrf='.length));
}
async function api(path, options = {}) {
  const write = options.method === 'POST';
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), write ? 120000 : 30000);
  try {
    const response = await fetch(path, {credentials: 'same-origin', cache: 'no-store', ...options,
      signal: controller.signal, headers: {...(write ? {'X-CSRF-Token': csrf()} : {}), ...options.headers}});
    const body = await response.json();
    if (!response.ok) {
      const error = Error(body.error?.message || `请求未完成（${response.status}）`);
      error.status = response.status;
      error.retryAfter = retryAfterMilliseconds(response.headers.get('Retry-After')); throw error;
    }
    return body.data ?? body;
  } finally { clearTimeout(timeout); }
}
function post(path, body, headers = {}) {
  return api(path, {method: 'POST', headers: {'Content-Type': 'application/json', ...headers},
    ...(body === undefined ? {} : {body: JSON.stringify(body)})});
}
function button(text, callback, className = 'secondary') {
  const b = document.createElement('button'); b.textContent = text; b.className = className;
  b.onclick = callback; return b;
}
function renderEditor() {
  show('editor'); $('flow-title').textContent = FLOWS[state.action].name;
  $('warehouse-label').hidden = !FLOWS[state.action].warehouse;
  $('warehouse').value = state.warehouse; $('count').textContent = `${state.boxes.length} / ${config.max_boxes}`;
  $('box-list').replaceChildren();
  state.boxes.forEach((code, index) => {
    const item = document.createElement('li'), text = document.createElement('span');
    text.textContent = `${index + 1}. ${code}`; item.append(text, button('删除', () => {
      if (state.phase !== 'DRAFT') return;
      state.boxes.splice(index, 1); save(); renderEditor();
    })); $('box-list').append(item);
  });
  $('review').disabled = !state.boxes.length || (FLOWS[state.action].warehouse && !state.warehouse);
  $('scan').disabled = !scannerReady() || state.boxes.length >= config.max_boxes;
  $('scan-hint').textContent = scannerReady() ? '每次扫描添加一箱，扫完后统一确认。' : '手机扫码待接入；目前可用扫码枪输入或手动添加箱号。';
}
function add(value) {
  try {
    const before = state.boxes.length;
    const next = addBoxes(state, value, config.max_boxes);
    state = next; save(); renderEditor(); $('box-input').value = ''; $('box-input').focus();
    notice(next.boxes.length === before ? '该箱号已扫描，未重复添加' : '已加入本批清单');
  } catch (e) { notice(e.message); }
}
function start(action) {
  notice();
  if (!identity) return notice('请先使用飞书账号登录');
  if (state && state.phase !== 'DRAFT' && state.phase !== 'DONE') return renderTask();
  if (state?.phase === 'DRAFT' && (state.boxes.length || state.action !== action)) {
    if (!window.confirm('切换操作会清空尚未提交的箱号清单，是否继续？')) return;
  }
  state = draft(action, identity.open_id); save(); renderEditor();
}
function review() {
  if (state.phase !== 'DRAFT') return renderTask();
  show('review-panel'); $('review-summary').textContent = `${FLOWS[state.action].name} · ${state.warehouse || '按箱子当前位置处理'} · 共${state.boxes.length}箱`;
  $('review-boxes').replaceChildren(...state.boxes.map(code => {
    const item = document.createElement('li'); item.textContent = code; return item;
  }));
}
function renderLocations() { renderLocationCard($('location-card'), state); }

function renderTask() {
  show('task'); $('task-title').textContent = `${FLOWS[state.action].name}任务`;
  renderLocations();
  $('task-summary').textContent = `${state.boxes.length}箱 · ${state.warehouse || '出库'}`;
  $('continue').hidden = state.phase !== 'SUBMITTING' && !state.authRequired;
  $('new-batch').hidden = state.phase !== 'DONE';
  $('dispatch').hidden = true;
  $('task-state').textContent = state.phase === 'DONE' ? '处理完成' : state.task ? '任务已受理，等待后台处理' : state.record ? '已提交，正在核实处理进度' : '正在核实提交结果';
  $('task-message').textContent = state.task && state.phase !== 'DONE' ? '任务已保存，后台将继续处理，请等待本批完成。' : state.record ? '请以后台完成状态为准，离开页面不影响已受理任务。' : '如果连接中断，请使用原请求继续，不要重新创建一批。';
  if (state.phase === 'DONE') { $('progress').max = 1; $('progress').value = 1; }
  if ((state.task || state.record) && state.phase !== 'DONE') poll();
}
async function submit() {
  if (busy) return;
  busy = true; $('confirm').disabled = true; $('continue').disabled = true;
  try {
    if (state.phase === 'DRAFT') {
      // 请求发出前先落本机原键和冻结输入；网络失败也绝不换键。
      state = freeze(state, crypto.randomUUID()); save();
    }
    save();
    renderTask();
    if (state.task && state.authRequired) {
      await post(`/api/v1/warehouse-tasks/${state.task}/resume`);
      state.authRequired = false; state.phase = 'PROCESSING'; save(); renderTask(); return;
    }
    const result = await post('/api/v1/warehouse-tasks', {...payload(state), action:state.action}, {'Idempotency-Key': state.key});
    state.task = result.task_id; state.record = result.record_id || null;
    state.locations = result.locations || state.locations;
    state.phase = 'PROCESSING'; save(); renderTask();
  } catch (e) {
    notice(e.message); renderTask();
  } finally { busy = false; $('confirm').disabled = false; $('continue').disabled = false; }
}
async function dispatch() {
  if (!state.record || state.phase === 'DONE') return;
  state.phase = 'PROCESSING'; save(); renderTask();
  try { await post(`/api/v1/inventory-executions/${state.record}/dispatch`); }
  catch (e) { notice(`处理请求未确认：${e.message}。先查询原流水结果。`); }
  poll();
}
async function poll() {
  clearTimeout(timer);
  if (document.hidden || reading || !(state?.task || state?.record) || state.phase === 'DONE') return;
  reading = true;
  const current = state.task || state.record;
  let delay = 5000;
  try {
    let result = await api(state.task ? `/api/v1/warehouse-tasks/${current}` : `/api/v1/inventory-executions/${current}/progress`);
    if (!state.task && !result.found) result = await api(`/api/v1/inventory-executions/${current}`);
    if (current !== (state?.task || state?.record)) return;
    delay = polling.next(current, result);
    if (state.task && result.record_id) state.record = result.record_id;
    state.authRequired = result.auth_required === true;
    state.locationReadFailed = false; state.executionState = result.state;
    if (result.locations) state.locations = result.locations;
    save(); renderLocations();
    if (result.state === 'SUCCEEDED' && result.inventory_posted === true) {
      state.phase = 'DONE'; save(); renderLocations(); $('new-batch').hidden = false;
      $('task-state').textContent = '全部处理完成'; $('task-message').textContent = '本批系统入账已确认，请核对分配位置与实际摆放一致，再开始下一批。';
      $('progress').value = 1; $('progress').max = 1; return;
    }
    $('progress').max = result.step_count || 1; $('progress').value = result.confirmed_steps || 0;
    $('task-state').textContent = result.state === 'RUNNING' ? `处理中 · ${result.confirmed_steps || 0} / ${result.step_count || 0} 步` : result.state === 'QUEUED' ? '已受理，排队中' : '已提交，尚未完成';
    $('dispatch').hidden = !!state.task || !(result.resume_required || !result.found);
    if (state.authRequired) {
      state.phase = 'REVIEW'; save(); $('continue').hidden = false;
      $('task-state').textContent = '需要重新登录后继续原任务';
      $('task-message').textContent = '请使用同一飞书账号重新登录，再点击使用原请求继续。';
      notice('登录需要更新，原任务已保留'); return;
    }
    if (result.review_required || result.state === 'REVIEW' || result.state === 'VALIDATION_REJECTED' || result.state === 'RECONCILE') {
      state.phase = 'REVIEW'; save(); renderLocations(); $('task-state').textContent = '需要核查，本批未确认完成';
      $('task-message').textContent = '请联系运维人员核实原流水；不要新建请求重复处理。';
      $('dispatch').hidden = true; return;
    }
    $('task-message').textContent = '后台处理进行中，可稍后回到原任务查看。';
  } catch (e) {
    if (current !== (state?.task || state?.record)) return;
    state.locationReadFailed = true; save(); renderLocations();
    $('task-message').textContent = `进度暂时无法读取：${e.message}。将继续查询原任务。`;
    delay = e.status === 401 || e.status === 403 ? 0 : polling.failed(current, e.retryAfter);
    if (!delay) notice('请重新登录或联系管理员，原任务已保留');
  } finally {
    reading = false;
    if (delay && !document.hidden && current === (state?.task || state?.record) && !['DONE', 'REVIEW'].includes(state.phase)) timer = setTimeout(poll, delay);
  }
}

const queryFields = {box_code: '箱号', sku: 'SKU', po: 'PO单号', row_code: '行码', position_code: '位置码'};
function display(value, key = '') {
  if (value === null || value === undefined || value === '') return '—';
  if (['时间', '入库时间', '装箱日期'].includes(key) && Number.isFinite(Number(value))) {
    return new Date(Number(value)).toLocaleString('zh-CN', {timeZone: 'Asia/Shanghai'});
  }
  if (typeof value === 'object') return value.name || JSON.stringify(value);
  return String(value);
}
function fieldsTable(fields) {
  const table = document.createElement('table'); table.className = 'field-table';
  for (const [key, value] of Object.entries(fields)) {
    const row = table.insertRow(); row.insertCell().textContent = key; row.insertCell().textContent = display(value, key);
  }
  return table;
}
async function query(next = false) {
  if (queryBusy) return; queryBusy = true; $('query-next').disabled = true;
  try {
    if (!next) { detailEpoch++; queryOffset = 0; queryParams = new URLSearchParams();
      for (const [key, value] of new FormData($('query-form'))) if (value.trim()) queryParams.set(key, value.trim()); }
    const params = new URLSearchParams(queryParams); params.set('limit', '20'); params.set('offset', String(queryOffset));
    $('query-message').textContent = '正在校验权限并查询…';
    const result = await api('/api/v1/search/boxes?' + params);
    if (result.visibility_token) queryParams.set('visibility_token',result.visibility_token);
    else queryParams.delete('visibility_token');
    $('query-results').replaceChildren(); $('query-details').replaceChildren();
    $('query-message').textContent = `本页${result.items.length}条 · ${result.replica?.stale ? '副本已过期，请等待同步' : '数据以同步版本为准'}`;
    for (const row of result.items) {
      const card = document.createElement('article'); card.className = 'record';
      const title = document.createElement('strong'); title.textContent = row.box_code;
      const summary = document.createElement('p'); summary.textContent = `${row.state || '状态未提供'} · ${row.warehouse || '当前无仓库位置'} · ${row.row_code || ''}${row.position_code || ''}`;
      card.append(title, summary, button('查看全部信息', () => details(row.record_id))); $('query-results').append(card);
    }
    $('query-next').hidden = !result.has_more; if (result.has_more) queryOffset += 20;
  } catch (e) {
    $('query-results').replaceChildren(); $('query-details').replaceChildren(); $('query-next').hidden = true;
    $('query-message').textContent = `${e.message}，请重新查询`;
  }
  finally { queryBusy = false; $('query-next').disabled = false; }
}
async function details(record) {
  const epoch = ++detailEpoch;
  const container = $('query-details'); container.replaceChildren();
  try {
    const data = await api(`/api/v1/search/boxes/${record}?limit=20`);
    if (epoch !== detailEpoch) return;
    const title = document.createElement('h2'); title.textContent = '箱档案与关联记录'; container.append(title, fieldsTable(data.box_fields));
    for (const [section, value] of Object.entries(data.sections)) {
      const block = document.createElement('details'); block.open = true;
      const summary = document.createElement('summary'); summary.textContent = {details: '箱内明细', flows: '扫码流水', ledger: '事务账'}[section]; block.append(summary); container.append(block);
      if (!value.available) { const text = document.createElement('p'); text.textContent = '该部分信息暂不可查询'; block.append(text); continue; }
      const append = items => items.forEach(item => block.append(fieldsTable(item.fields)));
      append(value.items);
      let offset = value.next_offset;
      const more = button('加载更多', async () => {
        more.disabled = true;
        try {
          const scope = data.visibility_token ? `&visibility_token=${data.visibility_token}` : '';
          const page = await api(`/api/v1/search/boxes/${record}?section=${section}&limit=20&offset=${offset}&backup_id=${data.backup_id}${scope}`);
          if (epoch !== detailEpoch) return;
          const part = page.sections[section]; if (!part.available) throw Error('权限或可见范围已变化，请重新查询');
          append(part.items); offset = part.next_offset; more.hidden = !part.has_more;
        } catch (e) {
          // 版本/权限变化时清除旧展示，避免把不同版本历史拼接。
          if (epoch !== detailEpoch) return;
          container.replaceChildren(); $('query-message').textContent = `${e.message}，请重新打开详情`;
        } finally { more.disabled = false; }
      });
      more.hidden = !value.has_more; block.append(more);
    }
  } catch (e) { $('query-message').textContent = e.message; }
}

async function init() {
  try {
    config = await api('/app/config');
    config.warehouses.forEach(name => $('warehouse').add(new Option(name, name)));
    try { identity = await api('/api/v1/access/me'); } catch { identity = null; }
    $('identity').textContent = identity ? {full_access: '可管理', edit: '可编辑', view: '可阅读'}[identity.permission] || '已登录' : '未登录';
    $('login').hidden = !!identity; $('logout').hidden = !identity;
    document.querySelectorAll('[data-flow]').forEach(b => {
      b.disabled = !identity || identity.permission !== 'full_access' || !config.inventory_enabled;
      b.onclick = () => start(b.dataset.flow);
    });
    if (identity && !config.inventory_enabled) notice('当前环境尚未开放库存处理，可使用已开放的查询功能');
    if (identity) {
      state = restore(sessionStorage.getItem(STORAGE), identity.open_id);
      if (!state) sessionStorage.removeItem(STORAGE);
      $('resume').hidden = !state;
    }
    if (config.simulation) { $('identity').textContent = '模拟联调'; notice('本机界面联调：使用模拟业务数据，不会写入飞书或库存'); }
    let queryAllowed=!!identity && config.query_enabled;
    if (queryAllowed) {
      try {
        const access=await api('/api/v1/search/access');queryAllowed=access.allowed===true;
        if (!queryAllowed) notice('当前账号的库存检索范围暂未通过校验，请联系管理员');
      } catch { queryAllowed=false;notice('暂时无法校验检索权限，请稍后重试'); }
    }
    $('open-query').disabled = !queryAllowed;
    const requested = location.hash.slice(1);
    if (Object.hasOwn(FLOWS, requested) && identity?.permission === 'full_access' && config.inventory_enabled) start(requested);
  } catch (e) { notice(e.message); $('identity').textContent = '连接未就绪'; }
}
document.querySelectorAll('[data-home]').forEach(b => b.onclick = () => show('home'));
$('warehouse').onchange = () => { if (state?.phase === 'DRAFT') { state.warehouse = $('warehouse').value; save(); renderEditor(); } };
$('add-form').onsubmit = e => { e.preventDefault(); add($('box-input').value); };
$('scan').onclick = async () => { const current = state; try { const code = await scanBox(); if (state === current && state.phase === 'DRAFT') add(code); } catch (e) { notice(e.message); } };
$('review').onclick = review; $('edit').onclick = renderEditor; $('confirm').onclick = submit; $('continue').onclick = submit;
$('dispatch').onclick = async () => { $('dispatch').disabled = true; try { await dispatch(); } finally { $('dispatch').disabled = false; } };
$('refresh').onclick = poll;
document.addEventListener('visibilitychange', () => {
  clearTimeout(timer);
  // 回到页面仅查询原任务；不重新提交、不调用dispatch或resume。
  if (!document.hidden && state && !['DRAFT', 'DONE', 'REVIEW'].includes(state.phase)) poll();
});
$('resume').onclick = () => state.phase === 'DRAFT' ? renderEditor() : renderTask();
$('new-batch').onclick = () => { if (state.phase !== 'DONE') return; state = null; save(); clearTimeout(timer); notice(); show('home'); };
$('labels').onclick = () => notice('生成箱标准备中，待标签样式及生成接口确认后开放');
$('open-query').onclick = () => { notice(); show('query'); };
for (const [key, title] of Object.entries(queryFields)) {
  const label = document.createElement('label'); label.textContent = title;
  const input = document.createElement('input'); input.name = key; input.maxLength = 200; input.autocomplete = 'off'; label.append(input); $('query-fields').append(label);
}
$('query-form').onsubmit = e => { e.preventDefault(); query(); }; $('query-next').onclick = () => query(true);
$('logout').onclick = async () => { try { await post('/auth/logout'); sessionStorage.removeItem(STORAGE); location.replace('/app'); } catch (e) { notice(e.message); } };
init();
