#!/bin/bash
set -ex
for i in {1..30}; do sudo iperf -c 192.168.100.35 -J | tee -a iperf.txt; done