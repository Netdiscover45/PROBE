import argparse

from .scanner import Scanner
from .output import print_banner, print_scan_result


BANNER = r"""
██████╗ ██████╗  ██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝
██████╔╝██████╔╝██████╔╝█████╗
██╔═══╝ ██╔══██╗██╔══██╗██╔══██╗██╔══╝
██║     ██║  ██║██████╔╝██║  ██║███████╗   V0.1
╚═╝     ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝

Python Web Vulnerability Scanner
Authorized targets only
"""


def main():

    parser = argparse.ArgumentParser(
        prog="probe",
        description="PROBE - Python Web Vulnerability Scanner"
    )

    # -------------------------------------------------
    # VERSION
    # -------------------------------------------------

    parser.add_argument(
        "--version",
        action="version",
        version="PROBE 0.1"
    )

    # -------------------------------------------------
    # SUBCOMMANDS
    # -------------------------------------------------

    subparsers = parser.add_subparsers(
        dest="command"
    )

    # -------------------------------------------------
    # SCAN COMMAND
    # -------------------------------------------------

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan an authorized web target"
    )

    scan_parser.add_argument(
        "target",
        help="Target URL"
    )

    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds"
    )

    scan_parser.add_argument(
        "--passive",
        action="store_true",
        help="Run passive security checks"
    )

    scan_parser.add_argument(
        "--active",
        action="store_true",
        help="Run controlled active checks"
    )

    scan_parser.add_argument(
        "--full",
        action="store_true",
        help="Run passive and controlled active checks"
    )

    args = parser.parse_args()

    # -------------------------------------------------
    # COMMAND VALIDATION
    # -------------------------------------------------

    if args.command != "scan":
        parser.print_help()
        return

    # -------------------------------------------------
    # BANNER
    # -------------------------------------------------

    print(BANNER)

    # -------------------------------------------------
    # SCANNER
    # -------------------------------------------------

    scanner = Scanner(
        timeout=args.timeout
    )

    # -------------------------------------------------
    # SCAN
    # -------------------------------------------------

    try:

        result = scanner.scan(
            args.target,
            passive=args.passive,
            active=args.active,
            full=args.full
        )

    except ValueError as exc:

        print(f"[!] Invalid target: {exc}")
        return

    # -------------------------------------------------
    # OUTPUT
    # -------------------------------------------------

    print_banner()

    print_scan_result(
        result,
        passive=args.passive,
        active=args.active,
        full=args.full
    )


if __name__ == "__main__":
    main()