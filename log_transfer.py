"""独立日志导出/下载入口；不启动业务服务，不连接数据库或飞书。"""
import argparse,json
from pathlib import Path
from finding_assistant.infrastructure.log_exchange import export_logs,child
from finding_assistant.infrastructure.log_download import pull_logs,read_config,SftpSource

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    export=commands.add_parser('export',help='只导出运行日志，发布受限清单')
    export.add_argument('--log-dir',required=True);export.add_argument('--output',required=True);export.add_argument('--system-id',required=True)
    for name in ('pull','status','validate'):
        command=commands.add_parser(name);command.add_argument('--config',required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='export':result=export_logs(args.log_dir,args.output,args.system_id)
        elif args.command=='pull':
            result=pull_logs(args.config);print(json.dumps(result,ensure_ascii=False));return 0 if result['state']=='SUCCEEDED' else 2
        else:
            config=read_config(args.config)
            if args.command=='validate':
                if not config['enabled']:result={'configured':False,'reason':'DOWNLOAD_NOT_CONFIGURED'}
                else:
                    if config['transport']=='sftp':SftpSource(config)
                    result={'configured':True,'transport':config['transport']}
            else:
                path=child(Path(config['destination'])/config['system_id'],'status.json')
                result=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {'state':'NEVER_RUN'}
        print(json.dumps(result,ensure_ascii=False));return 0
    except Exception:
        # 不输出配置值、SSH路径/输出、凭据或原始异常。
        print(json.dumps({'completed':False,'code':'LOG_TRANSFER_UNAVAILABLE'}));return 1

if __name__=='__main__':raise SystemExit(main())
