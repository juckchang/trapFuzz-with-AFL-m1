## trapFuzz with AFL and m1 support

trapfuzz: https://googleprojectzero.blogspot.com/2020/04/fuzzing-imageio.html
ida script to llvm: https://github.com/ant4g0nist/ManuFuzzer


The basic idea came from the two links above.

Use aflplusplus for trapfuzz in m1, and measure coverage using LLVM.

in the end 
[https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/afl_untracer/](afl_untracer) LLVM implementaion


```
AFL_MAP_SIZE=?? ../../afl-fuzz -i fuzz/in -o fuzz/out -- ./afl-untracer
```
