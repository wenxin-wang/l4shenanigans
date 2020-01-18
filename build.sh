#!/bin/bash

set -e

__DIR__="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

builddir=$__DIR__/build
openresty_tar=openresty-1.15.8.2.tar.gz
openresty_dir=openresty-1.15.8.2

mkdir -p $builddir

if [ ! -e $builddir/$openresty_tar ]; then
    wget -P $builddir -c https://openresty.org/download/$openresty_tar
fi

tar xf $builddir/$openresty_tar -C $builddir

patch -d $builddir/$openresty_dir/bundle/nginx-1.15.8 -Np1 -i $__DIR__/nginx-tproxy-patches/nginx-1.17.4-tproxy-for-linux.patch
patch -d $builddir/$openresty_dir/bundle/nginx-1.15.8 -Np1 -i $__DIR__/nginx-tproxy-patches/nginx-1.17.4-netns-for-linux.patch
patch -d $builddir/$openresty_dir/bundle/ngx_stream_lua-0.0.7 -Np1 -i $__DIR__/resty-patches/stream-lua-nginx-module-0.0.7-udp-multi-pkts-per-conn.patch
