#!/bin/bash

LOCAL_LIB="$PWD/deps"

export LDFLAGS="-L$PWD/deps/curl-7.63.0/lib/.libs -L$PWD/deps/gmp-6.1.2/.libs -L$PWD/deps/openssl-1.1.0j"

F="--with-curl=$PWD/deps/curl-7.63.0 --with-crypto=$PWD/deps/openssl-1.1.0j --host=x86_64-w64-mingw32"

sed -i 's/"-lpthread"/"-lpthreadGC2"/g' configure.ac

mkdir release
cp README.txt release/
cp /usr/x86_64-w64-mingw32/lib/zlib1.dll release/
cp /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll release/
cp /usr/lib/gcc/x86_64-w64-mingw32/7.3-win32/libstdc++-6.dll release/
cp /usr/lib/gcc/x86_64-w64-mingw32/7.3-win32/libgcc_s_seh-1.dll release/
cp $PWD/deps/openssl-1.1.0j/libcrypto-1_1-x64.dll release/
cp $PWD/deps/curl-7.63.0/lib/.libs/libcurl-4.dll release/


#if [ "$OS" = "Windows_NT" ]; then
#    ./mingw64.sh
#    exit 0
#fi

# Linux build

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

# Ubuntu 10.04 (gcc 4.4)
# extracflags="-O3 -march=native -Wall -D_REENTRANT -funroll-loops -fvariable-expansion-in-unroller -fmerge-all-constants -fbranch-target-load-optimize2 -fsched2-use-superblocks -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16"

# Debian 7.7 / Ubuntu 14.04 (gcc 4.7+)
#extracflags="$extracflags -Ofast -flto -fuse-linker-plugin -ftree-loop-if-convert-stores"

#CFLAGS="-O3 -march=native -Wall" ./configure --with-curl --with-crypto=$HOME/usr
CFLAGS="-O2 -msse2" ./configure --with-curl=$PWD/deps/curl-7.63.0 --with-crypto=$PWD/deps/openssl-1.1.0j --host=x86_64-w64-mingw32
#CFLAGS="-O3 -march=native -Wall" CXXFLAGS="$CFLAGS -std=gnu++11" ./configure --with-curl

make -j 4

strip -s cpuminer.exe
