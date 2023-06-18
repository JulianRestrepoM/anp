#!/bin/bash
set -ex
sudo iperf3 -c 192.168.0.175 -w 62780 -l 1 -t 300 -N -J -R >> resultsIperf3TcpOneByteNodDelayReverse.json