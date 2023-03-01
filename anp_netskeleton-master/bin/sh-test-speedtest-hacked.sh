#!/bin/bash
set -ex
speedtest --csv-header >>resultsSpeedtestHacked.csv
for i in {1..30}; do sudo ./sh-hack-anp.sh speedtest --csv >> resultsSpeedtestHacked.csv; done