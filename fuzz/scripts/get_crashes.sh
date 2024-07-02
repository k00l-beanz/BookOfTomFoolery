#!/bin/bash
# Retrieve crashes from your AFL++ out directory
#

if [ "$#" -ne 2 ]; then
        echo "usage: $0 afl_out_dir crash_dir"
        exit
fi

afl_out_dir="$1"
crash_output="$2"

mkdir -p "$crash_output" 2>/dev/null

# get all crashes
i=0
for crash_dir in $(find "$afl_out_dir" -name "crashes"); do
        for crash in $(ls $crash_dir/id* 2>/dev/null); do
                cp "$crash" "$crash_output/crash_${i}"
                i=$((i+1))
        done
done

echo "[+] Copied $i crashes"