from __future__ import annotations
import argparse, json, sys, urllib.request
from .guard import Guard
from .model import TrustLevel


def _read_target(target: str) -> str:
    if target.startswith(("http://", "https://")):
        with urllib.request.urlopen(target, timeout=10) as resp:
            return resp.read().decode("utf-8", "replace")
    with open(target, "r", encoding="utf-8") as f:
        return f.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard")
    sub = parser.add_subparsers(dest="cmd", required=True)
    scan_p = sub.add_parser("scan"); scan_p.add_argument("target"); scan_p.add_argument("--source", default="UNTRUSTED")
    serve_p = sub.add_parser("serve"); serve_p.add_argument("--host", default="127.0.0.1"); serve_p.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    if args.cmd == "scan":
        result = Guard().scan(_read_target(args.target), TrustLevel(args.source))
        print(json.dumps(result.to_dict(), indent=2))
        return 2 if result.blocked else 0
    if args.cmd == "serve":
        import uvicorn
        uvicorn.run("agentguard.server.app:app", host=args.host, port=args.port)
        return 0
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
