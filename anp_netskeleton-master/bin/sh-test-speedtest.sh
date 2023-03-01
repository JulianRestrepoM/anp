#!/bin/bash
set -ex
speedtest --csv-header >>resultsSpeedtest2.csv
for i in {1..30}; do sudo speedtest --csv >> resultsSpeedtest2.csv; done