"""维护账号本机入口：只读诊断包与独立监控；不提供普通员工HTTP导出。"""
import argparse,json,time
from pathlib import Path
from finding_assistant.infrastructure.environment import read_environment
from finding_assistant.infrastructure.diagnostic_bundle import diagnostic_bundle
from finding_assistant.infrastructure.monitoring import monitor_config,monitor_once

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    diagnostic=commands.add_parser('diagnostic');diagnostic.add_argument('--output',required=True);diagnostic.add_argument('--task-id');diagnostic.add_argument('--since');diagnostic.add_argument('--until');diagnostic.add_argument('--limit',type=int,default=500)
    diagnostic.add_argument('--monitor-state-dir')
    monitor=commands.add_parser('monitor');monitor.add_argument('--config',required=True);monitor.add_argument('--watch',action='store_true')
    for command in (diagnostic,monitor):command.add_argument('--env-file')
    args=parser.parse_args(argv)
    try:
        values=read_environment(args.env_file)
        if args.command=='diagnostic':
            result=diagnostic_bundle(values.get('FINDING_ASSISTANT_DATABASE_URL'),values.get('FEISHU_APP_ID'),values.get('FEISHU_APP_TOKEN'),values.get('FEISHU_SCAN_TABLE_ID'),args.output,
              task_id=args.task_id,since=args.since,until=args.until,limit=args.limit,log_dir=values.get('FINDING_ASSISTANT_LOG_DIR','logs'),
              secrets=[values.get(k,'') for k in ('FEISHU_APP_SECRET','FINDING_ASSISTANT_TOKEN_KEY','FINDING_ASSISTANT_DATABASE_URL')],monitor_state=args.monitor_state_dir)
            print(json.dumps(result,ensure_ascii=False));return 0
        config=monitor_config(args.config)
        if args.watch and not config['enabled']:
            print(json.dumps({'started':False,'code':'MONITOR_NOT_ENABLED'}));return 2
        first=True
        while True:
            result=monitor_once(values,config)
            if first or result['new_events'] or not args.watch:print(json.dumps(result,ensure_ascii=False),flush=True)
            first=False
            if not args.watch:return 0
            time.sleep(config['interval_seconds'])
    except KeyboardInterrupt:return 130
    except Exception:
        print(json.dumps({'completed':False,'code':'OPS_TOOL_UNAVAILABLE'}));return 1

if __name__=='__main__':raise SystemExit(main())
