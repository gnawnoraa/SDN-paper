#!/bin/bash
ip=$1
port=$2

iperf3 -c $ip -n 600M -b 25M -p $port
# sleep 10s
# iperf3 -c $ip -n 600M -b 25M -p $port
# sleep 10s
# iperf3 -c $ip -n 600M -b 25M -p $port
# sleep 10s
# iperf3 -c $ip -n 600M -b 25M -p $port