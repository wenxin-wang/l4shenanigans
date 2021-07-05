#ifndef COMPAT_CONNTRACK_COMPAT_H
#define COMPAT_CONNTRACK_COMPAT_H

#include "common.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
#define COMPAT_CT_NO_NETNS_GETPUT
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
#define COMPAT_NAT_NO_RANGE2
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#include <net/netfilter/nf_nat_core.h>
#else
#include <net/netfilter/nf_nat.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
#define COMPAT_CT_NO_DISABLE_DEFRAG_NS
#endif

#include <net/netfilter/nf_conntrack.h>

#endif /* COMPAT_CONNTRACK_COMPAT_H */
