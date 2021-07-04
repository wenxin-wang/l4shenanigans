# Build & Install

## Prerequisites
### Centos 7

```
sudo yum install -y kernel-devel gcc make binutils pkgconfig iptables-devel
```

### Debian

```
sudo apt-get install -y build-essential linux-headers-amd64 libxtables-dev pkg-config
```

## Install

```
cd kmod-ivi
cd src
make
sudo make install-all
sudo depmod -ae
```

# Design

intended usage

```bash

## road warrior
# TCP
sudo iptables -t mangle -F L4SHENANIGAN-OUTPUT || :
sudo iptables -t mangle -X L4SHENANIGAN-OUTPUT || :
sudo iptables -t mangle -N L4SHENANIGAN-OUTPUT || :

sudo iptables -t mangle -F OUTPUT
sudo iptables -t mangle -A OUTPUT -m set ! --match-set friendroute dst -j L4SHENANIGAN-OUTPUT
sudo iptables -t mangle -A L4SHENANIGAN-OUTPUT -j CONNMARK --set-mark 0x2
sudo iptables -t mangle -A L4SHENANIGAN-OUTPUT -j L4SHENANIGAN-ENCAP # syn for tcp, all for udp
sudo iptables -t mangle -A L4SHENANIGAN-OUTPUT -j L4SHENANIGAN-INVERT

sudo iptables -t nat -F OUTPUT
sudo iptables -t nat -A OUTPUT -m connmark --mark 0x2 -j DNAT --to-dest 192.168.1.2:40000-41000

sudo iptables -t mangle -F PREROUTING
sudo iptables -t mangle -A PREROUTING -m connmark --mark 0x2 -j L4SHENANIGAN-INVERT

## middlebox

# forwarding from l4shenanigan road warriors
sudo iptables -t mangle -F PREROUTING
sudo iptables -t mangle -A PREROUTING -d 192.168.1.2 -m multiport --dports 40000:41000 -j MARK --set-mark 0x1

sudo iptables -t nat -A PREROUTING -m mark --mark 0x1 -j DNAT --to-dest 192.168.2.2

sudo iptables -t nat -F POSTROUTING
sudo iptables -t nat -A POSTROUTING -m mark --mark 0x1 -j MASQUERADE

# forwarding from other road warriors, see above, change L4SHENANIGAN-OUTPUT to L4SHENANIGAN-PREROUTING-MB

## server

sudo iptables -t mangle -F L4SHENANIGAN-PREROUTING-SVR || :
sudo iptables -t mangle -X L4SHENANIGAN-PREROUTING-SVR || :
sudo iptables -t mangle -N L4SHENANIGAN-PREROUTING-SVR || :

sudo iptables -t mangle -F PREROUTING
sudo iptables -t mangle -A PREROUTING -d 192.168.2.2 -m multiport --dports 40000:41000 -j L4SHENANIGAN-PREROUTING-SVR # request from inside

# request from inside
sudo iptables -t mangle -A L4SHENANIGAN-PREROUTING-SVR -j MARK --set-mark 0x1
sudo iptables -t mangle -A L4SHENANIGAN-PREROUTING-SVR -j CONNMARK --set-mark 0x1
sudo iptables -t mangle -A L4SHENANIGAN-PREROUTING-SVR -j L4SHENANIGAN-INVERT

sudo iptables -t nat -F PREROUTING
sudo iptables -t nat -A PREROUTING -m connmark --mark 0x1 -m mark --mark 0x1 -j L4SHENANIGAN-DNAT # request from inside

sudo iptables -t mangle -F POSTROUTING
sudo iptables -t mangle -A POSTROUTING -m connmark --mark 0x1 -m mark --mark 0x1 -j L4SHENANIGAN-DECAP # request from inside
sudo iptables -t mangle -A POSTROUTING -m connmark --mark 0x1 ! -m mark --mark 0x1 -j L4SHENANIGAN-INVERT # reponse from outside

sudo iptables -t nat -F POSTROUTING
sudo iptables -t nat -A POSTROUTING -m connmark --mark 0x1 -m mark --mark 0x1 -j MASQUERADE # request from inside
```
