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
CFLAGS="-g -O0" ./configure --with-compat --with-file-aio --with-http_gunzip_module --with-http_gzip_static_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-pcre-jit --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-threads --with-debug
make -j8
