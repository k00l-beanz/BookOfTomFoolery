#!/bin/bash
# Retrieve hangs from your AFL++ out directory.

if [ "$#" -ne 2 ]; then
        echo "usage: $0 afl_out_dir hangs_dir"
        exit
fi

afl_out_dir="$1"
hangs_output="$2"

mkdir -p "$hangs_output" 2>/dev/null

# get all hangs
i=0
for hang_dir in $(find "$afl_out_dir" -name "hangs"); do
        for hang in $(ls $hang_dir/id* 2>/dev/null); do
                cp "$hang" "$hangs_output/hang_${i}"
                i=$((i+1))
        done
done

echo "[+] Copied $i hangs"