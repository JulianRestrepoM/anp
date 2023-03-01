#!/bin/bash
set -ex
for i in {1..30}; do sudo ./sh-hack-anp.sh wget --no-check-certificate 'https://docs.google.com/uc?export=download&id=1BWN_marKCOUmWtZjzju_8AprXC2tDUtN' -O driveFile"$i" ; done