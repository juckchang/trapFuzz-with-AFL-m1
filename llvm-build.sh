#!/bin/bash
cd llvm-project
git apply --stat ../llvm.patch 
git apply --check ../llvm.patch
git apply ../llvm.patch

mkdir build 
cd/build 
cmake ../llvm 
make llvm-config && make llvm-mc

