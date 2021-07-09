#ifndef COMPAT_H
#define COMPAT_H

#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/types.h>
#include <generated/utsrelease.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#error "requires Linux >= 3.10"
#endif

#ifdef RHEL_MAJOR
#if RHEL_MAJOR == 7
#define ISRHEL7
#endif
#ifdef RHEL_MINOR
#if RHEL_MINOR > 4
#define GTRHEL74
#endif
#endif
#endif

#include <linux/cache.h>
#ifndef __ro_after_init
#define __ro_after_init __read_mostly
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
#define skb_frag_off(skb) ((skb)->page_offset)
#endif

#endif /* COMPAT_H */
