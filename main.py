"""Backward-compatible dispatcher; workflows live in src.train/src.evaluate."""
from __future__ import annotations
import argparse
import sys
from src import train, evaluate
from src.pipeline.cli_support import ROOT, execute, add_arguments
from src.pipeline import cli as data_cli


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description="LOLBin detector: train, evaluate, predict and data preparation")
    sub = cli.add_subparsers(dest="command", required=True)
    data_cli.add_subcommands(sub)
    for name in ("train", "evaluate", "predict"):
        add_arguments(sub.add_parser(name), name)
    return cli


def run(args: argparse.Namespace) -> dict:
    if args.command == "train":
        return train.run(args)
    if args.command in {"evaluate", "predict"}:
        return evaluate.run(args)
    return data_cli.run(args)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "train":
        return train.main(argv[1:])
    if argv and argv[0] == "evaluate":
        return evaluate.main(argv[1:])
    if argv and argv[0] == "predict":
        return evaluate.main(argv[1:], predict=True)
    return execute(run, parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
