#!/bin/bash
set -ex
speedtest --csv-header >>resultsSpeedtestFinal3.csv
for i in {1..30}; do sudo speedtest --csv >> resultsSpeedtestFinal3.csv; done