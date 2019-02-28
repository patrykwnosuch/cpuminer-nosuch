If you want to cross-compile for windows, you can use included openssl, libcurl and gmp sources.

1. Install mingw-w64
2. Openssl

./Configure mingw64 shared --cross-compile-prefix=x86_64-w64-mingw32-
make

3. Curl

./configure --with-winssl --with-winidn --host=x86_64-w64-mingw32
make

4. GMP

./configure --host=x86_64-w64-mingw32 #can also be compiled as shared lib instead of static
make

5. CPU miner

ln -s ../gmp-6.1.2/gmp.h #can probably be specified as lib path, but it was the simplest way to do that

... then correct paths in winbuild.sh to correct ones and ...

sh winbuild.sh

In winbuild.sh you should correct paths and set proper CFLAGS for architecture for processor i.e.:

-msha -mavx2 -msse4.2 -maes (for compatible version choose -msse2)

Please be aware that compiling with -O3 flag can make some errors, you will get share rejects during binarium mining. 
If you are not experienced in compiling programms you can use our high performance compiled version of cpuminer for windows64.


