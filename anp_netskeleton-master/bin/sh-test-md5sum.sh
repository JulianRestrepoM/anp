#!/bin/bash
set -ex
md5sum 100File.txt >> driveFileChecksum.txt
for i in {1..30}; do md5sum driveFile"$i" >> driveFileChecksum.txt; done