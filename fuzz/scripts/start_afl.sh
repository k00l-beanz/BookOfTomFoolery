#!/bin/bash
# Start AFL++ with N nodes. 

export AFL_USE_ASAN=1

input_dir="./in"
output_dir="./out"
binary="./bin"

echo "[*] starting master afl-node"
afl-fuzz -M master -i "$input_dir" -o "$output_dir" -- "$binary" @@ > /dev/null 2>&1 &

for i in $(seq 1 8); do 
        echo "[*] starting afl-node $i"
        afl-fuzz -S "slave$i" -i "$input_dir" -o "$output_dir" -- "$binary" @@ > /dev/null 2>&1 &
done
