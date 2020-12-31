#!/bin/bash

set -e

__DIR__="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

builddir=$__DIR__/build
nginx_tar=nginx-1.17.7.tar.gz
nginx_dir=nginx-1.17.7
url=http://nginx.org/download/nginx-1.17.7.tar.gz

mkdir -p $builddir

if [ ! -e $builddir/$nginx_tar ]; then
    wget -P $builddir -c $url
fi

rm -rf $nginx_dir
tar xf $builddir/$nginx_tar -C $builddir

patch -d $builddir/$nginx_dir -Np1 -i $__DIR__/nginx-tproxy-patches/nginx-1.17.4-tproxy-for-linux.patch
patch -d $builddir/$nginx_dir -Np1 -i $__DIR__/nginx-tproxy-patches/nginx-1.17.4-netns-for-linux.patch
patch -d $builddir/$nginx_dir -Np1 -i $__DIR__/nginx-tproxy-patches/nginx-1.17.4-udp-proxy-protocol.patch
patch -d $builddir/$nginx_dir -Np1 -i $__DIR__/nginx-tproxy-patches/nginx-1.17.4-l4shenanigan.patch
patch -d $builddir/$nginx_dir -Np1 -i $__DIR__/nginx-tproxy-patches/nginx-1.17.4-udp-proxy-protocol-no-seperate.patch

cd $builddir/$nginx_dir
./configure --with-compat --with-stream --with-threads --without-http_rewrite_module --without-http_gzip_module
make -j$(nproc)
