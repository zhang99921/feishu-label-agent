"""Start one ordinary HTTP backend; no automatic Feishu inventory wiring."""
import argparse
import logging

import uvicorn


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host",default="127.0.0.1")
    parser.add_argument("--port",type=int,default=8001)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    logger = logging.getLogger("finding_assistant.http")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    uvicorn.run("finding_assistant.interfaces.http.app:create_app",factory=True,
        host=args.host,port=args.port,workers=1,access_log=False,proxy_headers=False)


if __name__ == "__main__":
    main()
