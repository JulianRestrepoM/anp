#!/bin/bash
set -ex
for i in {1..30}; do sudo ./sh-hack-anp.sh wget https://youtube.com -a wgetYoutubeHacked --progress=bar:force; done