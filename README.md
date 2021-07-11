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
sudo iptables -t mangle -F L4SHENANIGAN-OUTPUT || :
sudo iptables -t mangle -X L4SHENANIGAN-OUTPUT || :
sudo iptables -t mangle -N L4SHENANIGAN-OUTPUT || :

sudo iptables -t mangle -F OUTPUT
sudo iptables -t mangle -A OUTPUT -m set ! --match-set friendroute dst -j L4SHENANIGAN-OUTPUT
sudo iptables -t mangle -A L4SHENANIGAN-OUTPUT -j CONNMARK --set-mark 0x2
sudo iptables -t mangle -A L4SHENANIGAN-OUTPUT -j L4SHENANIGAN_ENCAP # syn for tcp, all for udp
sudo iptables -t mangle -A L4SHENANIGAN-OUTPUT -j L4SHENANIGAN_INVERT

sudo iptables -t nat -F OUTPUT
sudo iptables -t nat -A OUTPUT -p tcp -m connmark --mark 0x2 -j DNAT --to-dest 192.168.1.2:40000-41000
sudo iptables -t nat -A OUTPUT -p udp -m connmark --mark 0x2 -j DNAT --to-dest 192.168.1.2:40000-41000

sudo iptables -t mangle -F PREROUTING
sudo iptables -t mangle -A PREROUTING -m connmark --mark 0x2 -j L4SHENANIGAN_INVERT

## middlebox

# forwarding from l4shenanigan road warriors
sudo iptables -t mangle -F PREROUTING

sudo iptables -t mangle -F L4SHENANIGAN-PREROUTING-FW || :
sudo iptables -t mangle -X L4SHENANIGAN-PREROUTING-FW || :
sudo iptables -t mangle -N L4SHENANIGAN-PREROUTING-FW || :

sudo iptables -t mangle -A PREROUTING -d 192.168.1.2 -p tcp -m multiport --dports 40000:41000 -j L4SHENANIGAN-PREROUTING-FW
sudo iptables -t mangle -A PREROUTING -d 192.168.1.2 -p udp -m multiport --dports 40000:41000 -j L4SHENANIGAN-PREROUTING-FW
sudo iptables -t mangle -A L4SHENANIGAN-PREROUTING-FW -j MARK --set-mark 0x1
sudo iptables -t mangle -A L4SHENANIGAN-PREROUTING-FW -j CONNMARK --set-mark 0x1

sudo iptables -t nat -A PREROUTING -m mark --mark 0x1 -j DNAT --to-dest 192.168.2.2

sudo iptables -t nat -F POSTROUTING
sudo iptables -t nat -A POSTROUTING -m mark --mark 0x1 -j MASQUERADE

# forwarding from other road warriors, see above, change L4SHENANIGAN-OUTPUT to L4SHENANIGAN-PREROUTING-MB

## server

defsrc=$(ip r | grep src | head -n1 | awk '{print $9}')

sudo iptables -t mangle -F PREROUTING
sudo iptables -t nat -F PREROUTING
sudo iptables -t mangle -F POSTROUTING

sudo iptables -t mangle -F L4SHENANIGAN-PREROUTING-SVR || :
sudo iptables -t mangle -X L4SHENANIGAN-PREROUTING-SVR || :
sudo iptables -t mangle -N L4SHENANIGAN-PREROUTING-SVR || :

(
cd /lib/modules/$(uname -r)/extra/
for x in ipt_L4SHENANIGAN_*.ko; do
  rmmod ${x%.*} || :
  insmod $x
done
)

sudo iptables -t mangle -A PREROUTING -d $defsrc -p tcp -m multiport --dports 40000:41000 -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x1 # first request from inside
sudo iptables -t mangle -A PREROUTING -d $defsrc -p udp -m multiport --dports 40000:41000 -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x1 # first request from inside

sudo iptables -t mangle -A PREROUTING -d $defsrc -m connmark --mark 0x1 -m conntrack --ctdir ORIGINAL -j L4SHENANIGAN-PREROUTING-SVR # requests from inside

# requests from inside
sudo iptables -t mangle -A L4SHENANIGAN-PREROUTING-SVR -j MARK --set-mark 0x1
sudo iptables -t mangle -A L4SHENANIGAN-PREROUTING-SVR -j L4SHENANIGAN_INVERT
# sudo iptables -t mangle -A L4SHENANIGAN-PREROUTING-SVR -j NFLOG

sudo iptables -t nat -A PREROUTING -m connmark --mark 0x1 -m mark --mark 0x1 -j L4SHENANIGAN_DNAT # requests from inside

sudo iptables -t mangle -A POSTROUTING -m connmark --mark 0x1 -m mark --mark 0x1 -j L4SHENANIGAN_DECAP # requests from inside
sudo iptables -t mangle -A POSTROUTING -m connmark --mark 0x1 -m mark ! --mark 0x1 -j L4SHENANIGAN_INVERT # reponses from outside

sudo iptables -t nat -F POSTROUTING
sudo iptables -t nat -A POSTROUTING -m connmark --mark 0x1 -m mark --mark 0x1 -j MASQUERADE # requests from inside
```
