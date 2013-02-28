This is a very early alpha of ZFS on OSX, to be the next generation of MacZFS.

This is spl.kext, the Solaris Portability Layer (SPL), a dependency of zfs.kext.

It is tested primarily on Mac OS 10.8.2 and secondarily on 10.6.8, with
the latest Macports.

See https://github.com/zfs-osx/ and http://MacZFS.org/ for more information.
Note MacZFS's wiki on kernel development and panic decoding.

OSX claims that gcc has to be version 4.2
Hopefully the path to /System/Library/Frameworks/Kernel.framework is universal.

# git clone https://github.com/zfs-osx/spl.git

```

# ./autogen.sh
# ./configure --prefix=/usr/local
# make

# rsync -ar --delete module/spl/spl.kext/ /tmp/spl.kext/
# chown -R root:wheel /tmp/spl.kext

# kextload -r /tmp/ -v /tmp/spl.kext

