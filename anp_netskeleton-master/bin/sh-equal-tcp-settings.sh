#!/bin/bash
sudo sysctl -w net.ipv4.tcp_window_scaling=0
sudo sysctl -w net.ipv4.tcp_timestamps=0
sudo sysctl -w net.ipv4.tcp_sack=0