This is a very early alpha of ZFS on OSX, to be the next generation of MacZFS.

This is spl.kext, the Solaris Portability Layer (SPL), a dependency of zfs.kext.

It is tested primarily on Mac OS 10.8.2 and secondarily on 10.6.8, with
the latest Macports.

See https://github.com/zfs-osx/ and http://MacZFS.org/ for more information.
Note MacZFS's wiki on kernel development and panic decoding.

Please note that 'llvm-gcc' or 'clang' has to be used for compiling KEXTs.
Pure 'gcc' will produce instable builds.
<<<<<<< HEAD
=======


 # ./configure CC=clang CXX=clang++
or
 # ./configure CC=llvm-gcc CXX=llvm-g++

>>>>>>> 3c06d21f12bddf2ada75824a8e0554c024750979

```
 # ./configure CC=clang CXX=clang++
 or
 # ./configure CC=llvm-gcc CXX=llvm-g++
```

```
 # git clone https://github.com/zfs-osx/spl.git
```

```
# ./autogen.sh
# ./configure CC=clang CXX=clang++ --prefix=/usr/local
# make

# rsync -ar --delete module/spl/spl.kext/ /tmp/spl.kext/
# chown -R root:wheel /tmp/spl.kext

# kextload -r /tmp/ -v /tmp/spl.kext
```

