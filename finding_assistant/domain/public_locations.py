"""只从冻结计划提取操作员需要的位置；不返回执行计划或内部凭据。"""
def public_locations(plan):
    rows = plan.get('row_guards', {})
    def location(fields):
        links = fields.get('行', [])
        if not isinstance(links,list) or len(links)!=1 or links[0] not in rows:
            return None
        row = rows[links[0]]
        return {'row_code': row['行码'], 'warehouse': row['仓'],
                'position_code': fields.get('位置码',''), 'legacy_row_only': not fields.get('位置码')}
    sources, targets = [], []
    for tx in plan.get('transactions', []):
        for fields, collection in ((tx['before'],sources),(tx['after'],targets)):
            item=location(fields)
            if item is not None and item not in collection:collection.append(item)
    return {'target':targets[0] if len(targets)==1 and plan['action']!='OUT' else None,
            'sources':sources}
