"""CLI for agent-security-platform."""
import argparse
import json
import sys
from pathlib import Path
from .scanner import SecurityScanner
from .rules import BUILTIN_RULES

def build_parser():
    p=argparse.ArgumentParser(prog="agent-sec",description="Agent security platform CLI")
    p.add_argument("--version",action="version",version="agent-sec 1.0.0")
    sub=p.add_subparsers(dest="command",required=True)
    p_scan=sub.add_parser("scan",help="Scan content for threats")
    p_scan.add_argument("--file",help="File to scan")
    p_scan.add_argument("--agent",default="unknown")
    p_scan.add_argument("--json",action="store_true")
    p_rules=sub.add_parser("rules",help="List rules")
    return p

def main():
    parser=build_parser()
    args=parser.parse_args()
    if args.command=="rules":
        for r in BUILTIN_RULES: print(f"  {r.id}: {r.name} [{r.severity.value}]")
    elif args.command=="scan":
        scanner=SecurityScanner()
        content=Path(args.file).read_text(encoding="utf-8") if args.file else ""
        result=scanner.scan(content,args.agent)
        if args.json: print(json.dumps(result.summary(),indent=2))
        else:
            print(f"Scan: {'PASS' if result.passed else 'FAIL'}")
            for t in result.threats: print(f"  [{t.severity.value.upper()}] {t.rule_id}: {t.description}")
        sys.exit(0 if result.passed else 1)

if __name__=="__main__": main()