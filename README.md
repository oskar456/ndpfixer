# ndpfixer

This tool can be run on a Linux router to work around broken NDP due to broken multicast.

## What is the issue

Some (wireless) networks tend to get very unreliable in delivering Multicast.
When a client joins a network which does not deliver Solicited-node Multicast,
but still receive Router Advertisements, the clients will set up routing,
discover the default gateway, set up addressing and is able to send data.

However, on the return path, when the router wants to send data back to client,
the NDP will fail due to multicast being dropped.

## How does this work

This tool periodically scans the neighbor cache to discover unresolved neighbors,
that is neighbors with unreachability status either INCOMPLETE or FAILED.
At the same time it listens for incoming packets using `tcpdump` to see if any
of the unresolved hosts is sending any data in the forward direction. If yes,
the source MAC address is inserted as STALE entry into the neighbor cache, so
the return traffic is sent back to the same MAC address.

## Requirements
 - Python 3.9
 - `tcpdump`
 - `iproute2`
 - permissions to sniff traffic and issue `ip neigh replace` command

## Usage

See `./ndpfixer.py --help`
