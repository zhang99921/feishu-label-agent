/** 位置结果展示；只消费后台已返回的数据，不计算位置、不发起业务写入。 */
export function locationView(task) {
  const outbound = task.action === 'OUT';
  const points = task.locations || {};
  const target = points.target?.row_code ? points.target : null;
  const sources = Array.isArray(points.sources) ? points.sources.filter(p => p?.row_code) : [];
  const blocked = task.phase === 'REVIEW' || ['VALIDATION_REJECTED', 'RECONCILE', 'FAILED'].includes(task.executionState);
  const done = task.phase === 'DONE';
  let status, tone, message;
  if (blocked) {
    status = '需核查'; tone = 'warning';
    message = '本批尚未确认完成，请联系运维核查原流水；不要依据此位置开始新操作。';
  } else if (task.locationReadFailed) {
    status = '结果待核实'; tone = 'warning';
    message = '暂时无法读取最新进度，以下为本批上次返回的信息，请刷新原任务核实。';
  } else if (done) {
    status = '处理完成'; tone = 'success';
    message = outbound ? '本批出库已确认，以下展示原来源位置。' : target ? '本批入账已确认，请核对目标位置与实际摆放。' : '本批入账已确认，但未返回目标位置，请联系运维核对。';
  } else {
    status = outbound ? '出库处理中' : target ? '已返回位置 · 待完成' : '等待位置结果';
    tone = 'pending';
    message = outbound ? '以下为后台返回的来源位置，以最终出库结果为准。' : target ? '位置由后台返回，分配结果不代表入库已完成，请等待本批处理结果。' : '后台尚未返回目标行码及位置码，请勿自行推测位置或重复提交。';
  }
  return {status, tone, message, target:outbound ? null : target, sources,
    title:outbound ? '出库来源位置' : '本批位置结果',
    boxes:[...(task.boxes || [])], warehouse:task.warehouse || '', outbound};
}

export function renderLocationCard(root, task) {
  const view = locationView(task), doc = root.ownerDocument;
  const element = (tag, text, cls) => {
    const node = doc.createElement(tag); node.textContent = text;
    if (cls) node.className = cls;
    return node;
  };
  root.replaceChildren(); root.dataset.tone = view.tone;
  const heading = element('div', '', 'location-heading');
  heading.append(element('h3', view.title), element('span', view.status, 'location-status'));
  root.append(heading);
  if (!view.outbound) {
    const fields = element('dl', '', 'location-fields');
    for (const [label, value] of [['目标仓库', view.target?.warehouse || view.warehouse || '待返回'],
      ['行码', view.target?.row_code || '待返回'], ['位置码', view.target ? view.target.position_code || '未提供' : '待返回']]) {
      const group = element('div', ''); group.append(element('dt', label), element('dd', value)); fields.append(group);
    }
    root.append(fields);
  }
  if (view.sources.length) {
    const list = element('ul', '', 'location-sources');
    for (const p of view.sources) list.append(element('li',
      `${p.warehouse || '仓库未提供'} / ${p.row_code} / ${p.position_code || '未记录位置码'}${p.legacy_row_only ? '（旧区域档案）' : ''}`));
    root.append(element('p', view.outbound ? '来源位置' : '原来源位置', 'hint'), list);
  } else if (view.outbound) root.append(element('p', '来源位置尚未返回', 'hint'));
  root.append(element('p', view.message, 'location-message'));
  const details = element('details', '');
  details.append(element('summary', `对应本批 ${view.boxes.length} 箱 · 展开核对箱号`));
  const list = element('ol', '', 'location-boxes');
  for (const code of view.boxes) list.append(element('li', code));
  details.append(list); root.append(details);
}
