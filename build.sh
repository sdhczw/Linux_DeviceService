#!/bin/sh

autoreconf --force --install
./configure --with-ssl=/usr/local/ssl
export LD_PRELOAD=/usr/local/ssl/lib/libcrypto.so.1.0.0:/usr/local/ssl/lib/libssl.so.1.0.0:/usr/local/lib/libcurl.so
make
