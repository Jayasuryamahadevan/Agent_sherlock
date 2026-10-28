"""Installed command for the host diagnostic app."""
import argparse
import asyncio
import json

from .antigravity_diagnose import collect_system, run


def main():
    parser = argparse.ArgumentParser(prog='fieldnote', description='Local system diagnostic assistant')
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('serve', help='Start the local browser interface')
    serve.add_argument('--port', type=int, default=8000)
    commands.add_parser('inspect', help='Show collected host evidence without contacting AI')
    analyze = commands.add_parser('analyze', help='Analyze a complaint in the terminal')
    analyze.add_argument('complaint')
    analyze.add_argument('--dns-host')
    args = parser.parse_args()
    if args.command == 'serve':
        import uvicorn
        uvicorn.run('fieldnote.app:app', host='127.0.0.1', port=args.port)
    elif args.command == 'inspect':
        print(json.dumps(collect_system(), indent=2))
    else:
        args.inspect = False
        asyncio.run(run(args))


if __name__ == '__main__':
    main()
