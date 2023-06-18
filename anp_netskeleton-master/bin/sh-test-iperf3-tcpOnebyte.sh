#!/bin/bash
sudo iperf3 -c 192.168.0.175 -w 62780 -l 1 -t 300 -J -R >> resultsIperf3TcpOneByteReversed.json
