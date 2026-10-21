#!/usr/bin/env python3
"""Run artifact controls inside an owned disposable Linux PID namespace."""
import argparse
import importlib.util
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', required=True)
    parser.add_argument('--daemon', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--case', choices=('normal', 'held-unregistered'), default='normal')
    parser.add_argument('--interpreter', choices=('/usr/bin/python3', '/usr/libexec/platform-python'), default='/usr/bin/python3')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('artifact_namespace',
        Path(__file__).resolve().parents[1] / 'client-artifact-namespace.py')
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    owner.run_controls(args.client, args.daemon, args.image, args.case, args.interpreter)


if __name__ == '__main__':
    main()
