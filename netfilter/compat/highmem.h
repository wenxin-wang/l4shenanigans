#ifndef HIGHMEM_H
#define HIGHMEM_H

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define COMPAT_HIGHMEM_NO_KMAP_LOCAL_PAGE
#endif

#endif /* HIGHMEM_H */