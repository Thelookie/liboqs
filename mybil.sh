#!/bin/bash

# Remove existing build directory
rm -rf build

# Create build directory
mkdir build

# Run cmake without changing directories
cmake -GNinja -B build -S . -DCMAKE_INSTALL_PREFIX=/usr/local  -DBUILD_SHARED_LIBS=ON  -DOQS_ENABLE_KEM_NTRUPLUS=ON -DOQS_ENABLE_KEM_SMAUGT=ON -DOQS_ENABLE_KEM_PALOMA=ON -DOQS_ENABLE_SIG_AIMER=OFF -DOQS_ENABLE_SIG_HAETAE=ON -DOQS_ENABLE_SIG_NCCSIGN=OFF
#-DOQS_BUILD_ONLY_LIB=ON 
# Build the project and save output to log.txt
ninja -C build | tee build.log

# Filter FAILED logs and save to log.txt
awk '/FAILED/,0' build.log > log.txt

# Run tests
ninja -C build run_tests

# Install the built project
sudo ninja -C build install
