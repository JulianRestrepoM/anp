#!/bin/bash
set -ex
sudo ./sh-hack-anp.sh iperf3 -c 192.168.0.175 -w 62780 -l 1 -t 300 -N -J >> resultsIperf3TcpOneByteNodDelayHacked.json