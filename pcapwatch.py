#!/usr/bin/env python3

# SPDX-License-Identifier: BSL-1.0
#
# 2020, Georg Sauthoff

import argparse
import glob
import os
import shutil
import signal
import sys
import time


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('disk_path',
            help='path to check disk usage on')
    p.add_argument('patterns', metavar='pattern', nargs='+',
            help='glob patterns to collect expendable files for removal. make them absolute e.g. /mnt/scratch/*.pcap')
    p.add_argument('--on-fill-level', type=float, default=0.9,
            help='hysteresis attack level (default: %(default)f')
    p.add_argument('--off-fill-level', type=float, default=0.85,
            help='hysteresis attack level (default: %(default)f')
    p.add_argument('--interval', '-i', dest='interval_s', type=int,
            default=60,
            help='wait time after each check in seconds (default: %(default)d')
    p.add_argument('--verbose', '-v', action='store_true',
            help='print verbose messages')
    return p.parse_args()

def handle_quit(sig, f):
    print('caught signal - exiting gracefully')
    sys.exit(0)

def main():
    args = parse_args()

    signal.signal(signal.SIGINT, handle_quit)
    signal.signal(signal.SIGTERM, handle_quit)


    while True:
        total, used, _ = shutil.disk_usage(args.disk_path)

        #print(f'Fill level: {used/total}', flush=True)

        if used/total > args.on_fill_level:
            xs = []
            for p in args.patterns:
                xs.extend(glob.glob(p))
            xs.sort(key=lambda f : os.path.getmtime(f), reverse=True)
            while xs and used/total > args.off_fill_level:
                f = xs.pop()
                if args.verbose:
                    print(f'Removing {f}', flush=True)
                try:
                    os.unlink(f)
                except FileNotFoundError:
                    pass # ignore coincidental time-of-check time-of-use race conditions
                    if args.verbose:
                        print(f'Removing {f} - file not found!', flush=True)
                total, used, _ = shutil.disk_usage(args.disk_path)

        time.sleep(args.interval_s)


if __name__ == '__main__':
    sys.exit(main())
