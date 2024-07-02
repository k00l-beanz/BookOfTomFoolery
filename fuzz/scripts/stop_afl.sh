#!/bin/bash
# Stop all AFL++ nodes.

pid=$(ps aux | grep "afl-fuzz" | awk '{print $2}')

for pid in $pid; do
        echo "[-] killing $pid" 
        kill "$pid"
done
