#!/bin/bash
# Generate random corpus seeds. 
#

if [ "$#" -ne 1 ]; then
        echo "usage: $0 outputdir"
        exit
fi

# store seeds temp dir
tmpdir=$(mktemp -d)
for i in $(seq 1 64); do
        echo "[-] generating seed $i"
        dd if=/dev/urandom of="$tmpdir/seed_$i" bs=64 count=64 > /dev/null 2>&1
done

# hash for identification
outputdir="$1"
mkdir -p "$outputdir" 2> /dev/null

for seed in $(ls "$tmpdir"); do
        hashid=$(sha1sum "$tmpdir/$seed" | cut -d ' ' -f 1)
        mv "$tmpdir/$seed" "$outputdir/$hashid"
done
