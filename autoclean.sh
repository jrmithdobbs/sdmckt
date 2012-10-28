#!/bin/sh
if [ -f build/Makefile ]; then
  (cd build && make maintainer-clean)
fi
if [ -f Makefile ]; then
  make maintainer-clean
fi
rm -rf Makefile Makefile.in aclocal.m4 autom4te.cache config.* configure depcomp install-sh missing
