"""vulnex-scanner: enroll once, then run.

    vulnex-scanner enroll --bundle bundle.json [--state DIR]     (--bundle - reads stdin)
    vulnex-scanner run [--state DIR] [--scope-ceiling 10.0.0.0/8 ...] [--once]

--state defaults to $VULNEX_SCANNER_STATE or /var/lib/vulnex-scanner.
--scope-ceiling: this worker refuses any target outside these ranges or hostnames, whatever a
signed lease says (an optional local limit the control plane cannot widen).

Exit codes: 0 stopped, 1 error, 3 revoked (keys deleted; enroll again with a new bundle).
"""

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path

import httpx

from vulnex_scanner.agent import Agent, Revoked, ScannerError, enroll
from vulnex_worker_protocol.messages import EnrollmentBundle
from vulnex_worker_protocol.targets import TargetError, parse_scope_entry


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="vulnex-scanner")
    parser.add_argument(
        "--state",
        type=Path,
        default=Path(os.environ.get("VULNEX_SCANNER_STATE", "/var/lib/vulnex-scanner")),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    e = sub.add_parser("enroll", help="enroll this worker with a bundle from the console")
    e.add_argument("--bundle", type=Path, required=True)
    r = sub.add_parser("run", help="run the worker loop")
    r.add_argument("--scope-ceiling", action="append", default=[], metavar="CIDR_OR_HOST")
    r.add_argument("--once", action="store_true", help="one cycle, then exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        if args.command == "enroll":
            raw = sys.stdin.buffer.read() if str(args.bundle) == "-" else args.bundle.read_bytes()
            bundle = EnrollmentBundle.model_validate_json(raw)
            creds = enroll(args.state, bundle)
            print(f"enrolled as worker {creds.worker_id}; delete {args.bundle}, it is used up")
            return
        try:
            ceiling = [parse_scope_entry(v, exclude=False) for v in args.scope_ceiling]
        except TargetError as err:
            sys.exit(f"--scope-ceiling: {err}")
        agent = Agent(args.state, ceiling=ceiling)
        if args.once:
            print(f"handled {agent.run_once()} task(s)")
            return
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        agent.run(stop)
    except Revoked as err:
        print(err, file=sys.stderr)
        sys.exit(3)
    except (ScannerError, OSError, ValueError, httpx.HTTPError) as err:
        sys.exit(str(err))


if __name__ == "__main__":
    main()
