#!/bin/sh

autoreconf
export LD_PRELOAD=/usr/local/ssl/lib/libcrypto.so.1.0.0:/usr/local/ssl/lib/libssl.so.1.0.0:/usr/local/lib/libcurl.so
./configure
make
