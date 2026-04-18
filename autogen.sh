#!/bin/sh
# Run this to generate all the initial makefiles, etc.

echo Building configuration system...
autoreconf --install --symlink -f -Wno-obsolete && echo Now run ./configure and make
