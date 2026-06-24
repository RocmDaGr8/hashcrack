"""HashCrack CLI.

    python -m hashcrack identify <hash>
    python -m hashcrack crack <hash> --wordlist words.txt [--rules]
                         [--type auto|md5|sha1|sha256|sha512|...] [--quiet]

Use only against hashes you are authorized to test (CTFs, labs, your own
password audits).
"""

import argparse
import sys

from . import __version__
from .identify import identify, best_crackable_algo
from .cracker import crack

_COLORS = {"green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
           "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m"}


def _c(text, color):
    if not sys.stdout.isatty():
        return text
    return f"{_COLORS[color]}{text}{_COLORS['reset']}"


def cmd_identify(args):
    cands = identify(args.hash)
    if not cands:
        print(_c("Unrecognized hash format.", "yellow"))
        return
    print(f"\nPossible type(s) for {_c(args.hash[:40], 'bold')}"
          f"{'...' if len(args.hash) > 40 else ''}:")
    for c in cands:
        mark = _c("crackable", "green") if c["crackable"] else _c("identify-only", "dim")
        print(f"  • {c['name']:<18} [{mark}]")
    print()


def cmd_crack(args):
    algo = args.type
    if algo == "auto":
        algo = best_crackable_algo(args.hash)
        if not algo:
            cands = identify(args.hash)
            if cands:
                names = ", ".join(c["name"] for c in cands)
                sys.exit(f"error: '{names}' is recognized but not crackable by this tool "
                         f"(hashlib digests only). Try --type to override.")
            sys.exit("error: could not identify hash type — specify it with --type.")
        print(f"Auto-detected hash type: {_c(algo, 'bold')}")

    try:
        wordlist = open(args.wordlist, "r", encoding="utf-8", errors="ignore")
    except OSError as e:
        sys.exit(f"error: cannot open wordlist '{args.wordlist}': {e}")

    print(f"HashCrack {__version__} — attacking {_c(algo, 'bold')} hash"
          f"{' with rules' if args.rules else ''}...")
    with wordlist as fh:
        result = crack(args.hash, algo, fh, use_rules=args.rules,
                       progress=not args.quiet)

    print()
    if result["found"]:
        print(_c(f"  [+] CRACKED: {result['password']}", "green"))
    else:
        print(_c("  [-] Not found in wordlist.", "red"))
    print(_c(f"      {result['attempts']:,} attempts in {result['seconds']}s "
             f"({result['rate']:,}/s)", "dim"))
    print()

    sys.exit(0 if result["found"] else 1)


def build_arg_parser():
    p = argparse.ArgumentParser(prog="hashcrack",
        description="Identify hashes and run dictionary/rule-based attacks (authorized use only).")
    p.add_argument("--version", action="version", version=f"HashCrack {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("identify", help="identify a hash type")
    pi.add_argument("hash")

    pc = sub.add_parser("crack", help="dictionary attack against a hash")
    pc.add_argument("hash")
    pc.add_argument("--wordlist", "-w", required=True, help="path to wordlist file")
    pc.add_argument("--type", "-t", default="auto",
                    help="hash type (default: auto) — md5, sha1, sha224, sha256, sha384, sha512")
    pc.add_argument("--rules", "-r", action="store_true",
                    help="apply rule-based mangling to each word")
    pc.add_argument("--quiet", "-q", action="store_true", help="suppress live progress")
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    {"identify": cmd_identify, "crack": cmd_crack}[args.command](args)


if __name__ == "__main__":
    main()
