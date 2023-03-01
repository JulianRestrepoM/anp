#!/bin/bash
iperf3 -c 192.168.0.175 -w 62780 -t 300 -J -R >> resultsIperf3TcpReversed.json