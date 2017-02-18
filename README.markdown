OpenZFS on OS X (O3X) brings OpenZFS features to Apple's OS X.

This is spl.kext, the Solaris Portability Layer (SPL).

** spl.kext is a dependency of zfs.kext, so start with this repository.

It is tested primarily on Mac OS X Sierra.

See http://openzfsonosx.org/ for more information.

```
 # git clone https://github.com/openzfsonosx/spl.git
 # cd spl
 # ./autogen.sh
 # ./configure
 # make
```

- lundman
