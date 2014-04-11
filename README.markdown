OpenZFS on OS X (O3X) brings OpenZFS features to Apple's OS X.

This is spl.kext, the Solaris Portability Layer (SPL).

** spl.kext is a dependency of zfs.kext, so start with this repository.

It is tested primarily on Mac OS X Mavericks.

See http://openzfsonosx.org/ for more information.

Please note that 'llvm-gcc' or 'clang' should be used for compiling the KEXTs.
Pure 'gcc' will produce unstable builds.

```
 # ./configure CC=clang CXX=clang++
 or
 # ./configure CC=llvm-gcc CXX=llvm-g++
```

```
 # git clone https://github.com/openzfsonosx/spl.git
```

```
# ./autogen.sh
# ./configure CC=clang CXX=clang++
# make

# rsync -a --delete module/spl/spl.kext/ /tmp/spl.kext/
# chown -R root:wheel /tmp/spl.kext

# kextload -r /tmp/ -v /tmp/spl.kext

: SPL: Total memory 17179869184AGC: 3.4.5, HW version=3.2.19 [3.2.8], flags:0, features:20600
: SPL: Loaded module v0.01 (ncpu 8, memsize 17179869184, pages 4194304)

```

- lundman
