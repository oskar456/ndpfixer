#!/usr/bin/env python3

import subprocess
import re
import time
import json
import logging
import argparse
import sys

logger = logging.getLogger(__name__)


def do_tcpdump(iface, prefix, interval):
    cmd = ["/usr/sbin/tcpdump", "-nnpelti", iface, f"src net {prefix}"]
    dumpre = re.compile(r'([0-9a-f:]+) > [0-9a-f:]+, .* ([0-9a-f:]+)(?:\.[0-9]+)? > [0-9a-f:]+')
    broken_ips = set()
    broken_ips_age = -1
    with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            text=True,
        ) as p:
        for line in p.stdout:
            if time.clock_gettime(time.CLOCK_MONOTONIC) - broken_ips_age > interval:
                new_broken_ips = get_broken_neighbors(iface)
                broken_ips_age = time.clock_gettime(time.CLOCK_MONOTONIC)
                diff = new_broken_ips - broken_ips
                broken_ips = new_broken_ips
                if diff:
                    logger.info("There are %d new broken IPs (%d total): %s", len(diff), len(broken_ips), ", ".join(diff))
            m = dumpre.match(line)
            if m:
                mac, ip = m.groups()
                logger.debug("Host %s is at %s", ip, mac)
                if ip in broken_ips:
                    logger.info(f"Neighbor {ip} is possibly at {mac}")
                    fix_broken_neighbor(iface, ip, mac)
                    broken_ips.remove(ip)
            else:
                logger.warning("No match for: %s", line)
    sys.exit("Error: tcpdump finished. Check permissions.")


def get_broken_neighbors(iface):
    """
    Return a set of IPv6 addresses of neighbors that are being
    looked for by NDP.
    """
    cmd = ["/sbin/ip", "-6", "-json", "neighbor", "show", "dev", iface]
    ip = subprocess.run(cmd, capture_output=True, text=True)
    ndpt = json.loads(ip.stdout)
    return {x.get("dst") for x in ndpt
            if x.get("state", [""])[0] in ["FAILED", "INCOMPLETE"] and
            not x.get("dst").startswith("fe80")}


def fix_broken_neighbor(iface, ip, mac):
    """
    Install a STALE neighbor entry for particular IP/Mac pair.
    """
    cmd = ["/sbin/ip", "-6", "neigh", "replace", ip,
           "lladdr", mac, "dev", iface, "nud", "stale"]
    subprocess.run(cmd)


def autodetect_prefix(iface):
    """
    Try to figure out the connected prefix on an interface.
    """
    cmd = ["/sbin/ip", "-6", "-json", "route", "show", "dev", iface]
    ip = subprocess.run(cmd, capture_output=True, text=True)
    routet = json.loads(ip.stdout)
    candidates = ((x.get("metric"), x.get("dst")) for x in routet
                  if "gateway" not in x
                  and "/" in x.get("dst")
                  and not x.get("dst").startswith("f"))
    candidates = sorted(candidates)
    assert len(candidates) > 0
    return candidates[0][1]


def main():
    """
    Monitor incoming traffic from neigbors on an interface.
    Install a stale neigbor cache entry if the Neighbor Discovery Protocol
    failed to resolve the MAC address but the MAC address can be observed from 
    the incoming traffic.
    """
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("interface", help="Interface to work on")
    parser.add_argument("-p", "--prefix", help="Prefix to work on")
    parser.add_argument("-i", "--interval", help="How many seconds between neighbor cache scans", type=float, default=5)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    if args.prefix is None:
        args.prefix = autodetect_prefix(args.interface)
        logger.debug(f"Autodetected prefix: {args.prefix}")
    do_tcpdump(args.interface, args.prefix, args.interval)


if __name__ == '__main__':
    main()
