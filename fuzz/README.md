## Tips

### To start:
```bash
apt-get install docker
docker pull aflplusplus/aflplusplus
```

### Corpus
- AFL++ comes with a bunc of dictionaries. See `/AFLplusplus/dictionaries/`. Specify with the `-x` option

### Create Archive out of Object Files

```bash
ar rcs libxml2.a *.o
```

### Coverage

Compile with coverage:
```bash
# compile with coverage
CFLAGS="--coverage" LDFLAGS="--coverage" ./configure --disable-shared

# reset counters
lcov --zerocounters --directory ./

# return the baseline coverage data
lcov --capture --initial --directory ./ --output-file app.info

# analyze the application. You can run multiple times with different input
./bin -D -j -c -r -s -w payload

# save the coverage
lcov --no-checksum --directory ./ --capture --output-file app2.info

# generate html report
genhtml --highlight --legend -output-directory ./html-coverage/ ./app2.info

# spin up python3 server to view report. make sure to test with multiple payloads / crashes
python3 -m http.server 
```

## Repos

- [google/oss-fuzz](https://github.com/google/oss-fuzz/tree/master)
- [google.github.io/oss-fuzz](https://google.github.io/oss-fuzz/)
- [fuzzable](https://github.com/ex0dus-0x/fuzzable) - Auto create fuzz harnesses
- [AFLplusplus-blogpost](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main)
- [AFLNet](https://github.com/aflnet/aflnet) - A greybox fuzzer for network protocols
- [lcov](https://github.com/linux-test-project/lcov) - Shows coverage for an application

## Articles

- [Fuzzing tcpdump](https://countuponsecurity.com/tag/fuzzing-tcpdump/)
- [Advanced binary fuzzing with AFL++ QEMU](https://airbus-seclab.github.io/AFLplusplus-blogpost/)
- [Fuzzing capstone with AFL persistent mode](https://toastedcornflakes.github.io/articles/fuzzing_capstone_with_afl.html)
- [Fuzzing Explain with AFL](https://x9security.com/fuzzing-explained-with-afl/)
- *[Fuzzing workflows; a fuzz job from start to finish](https://foxglovesecurity.com/2016/03/15/fuzzing-workflows-a-fuzz-job-from-start-to-finish/)
- *[clusterfuzz](https://google.github.io/clusterfuzz/)