#!/usr/bin/env python3

# SPDX-License-Identifier: BSL-1.0
#
# 2022, Georg Sauthoff

import argparse
import json
import os
import subprocess
import sys
import time


def parse_args():
    p = argparse.ArgumentParser(description='Periodically collect NVMe metrics',
            epilog='e.g. for use with the Telegraf execd input plugin')
    p.add_argument('--interval', '-i',  type=int, default=10*60,
            metavar='INTERVAL_SECS',
            help='collection interval (default: %(default)s)')
    p.add_argument('--csv', action='store_true',
            help='enable CSV output')
    p.add_argument('--table', default='nvme',
            help='Influx metrics table name (default: %(default)s)')
    args = p.parse_args()
    return args

def yield_nvme():
    try:
        for i in range(256):
            d = f'/dev/nvme{i}'
            st = os.stat(d)
            yield(d)
    except FileNotFoundError:
        pass

def get_metrics(devicename):
    o = subprocess.check_output(
            ['sudo', 'nvme', 'smart-log', devicename, '-o', 'json'],
            universal_newlines=True)
    d = json.loads(o)
    return d

def main():
    args = parse_args()

    keys = set()
    for d in yield_nvme():
        kv = get_metrics(d)
        keys.update(kv.keys())
    keys = list(keys)
    keys.sort()
    if args.csv:
        print('device,' + ','.join(keys), flush=True)

    while True:
        for d in yield_nvme():
            kv = get_metrics(d)
            if args.csv:
                print(f'{d[5:]},', end='')
                print(','.join(str(kv.get(k, '')) for k in keys), flush=True)
            else:
                ts = f'{int(time.time())}000000000'
                s = ','.join(f'{k}={v}' for k, v in kv.items())
                print(f'{args.table},device={d[5:]} {s} {ts}')
        time.sleep(args.interval)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass


