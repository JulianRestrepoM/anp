#!/bin/bash
set -ex
speedtest --csv-header >>resultsSpeedtestHackedFinal3.csv
for i in {1..30}; do sudo ./sh-hack-anp.sh speedtest --csv >> resultsSpeedtestHackedFinal3.csv; done