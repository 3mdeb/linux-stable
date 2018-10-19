/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_AMD_DEV_H
#define _ASM_X86_AMD_DEV_H

/*
 * Copyright (c) 2019 Apertus Solutions, LLC
 *
 * Author(s):
 * 	Daniel P. Smith <dpsmith@apertussolutions.com>
 */

#include <linux/types.h>

#define DEV_PCI_BUS                     0x0
#define DEV_PCI_DEVICE                  0x18
#define DEV_PCI_FUNCTION                0x3
#define DEV_PCI_HDR                     0xF0
#define DEV_PCI_OP                      0xF4
#define DEV_PCI_DATA                    0xF8

#define PCI_CAPABILITIES_ID_DEV         0x0F

/* DEV Functions */
#define DEV_BASE_LO                     0
#define DEV_BASE_HI                     1
#define DEV_MAP                         2
#define DEV_CAP                         3
#define DEV_CR                          4
#define DEV_ERR_STATUS                  5
#define DEV_ERR_ADDR_LO                 6
#define DEV_ERR_ADDR_HI                 7

/* Contrl Register  */
#define DEV_CR_ENABLE_MASK              1<<0
#define DEV_CR_MEM_CLR_MASK             1<<1
#define DEV_CR_IOSP_EN_MASK             1<<2
#define DEV_CR_MCE_EN_MASK              1<<3
#define DEV_CR_INV_CACHE_MASK           1<<4
#define DEV_CR_SL_DEV_EN_MASK           1<<5
#define DEV_CR_WALK_PROBE_MASK          1<<6

#define DEV_BASE_LO_VALID_MASK          1<<0
#define DEV_BASE_LO_PROTECTED_MASK      1<<1
#define DEV_BASE_LO_SET_SIZE(b,s)       (b & (s << 2))
#define DEV_BASE_LO_ADDR_MASK           0xFFFFF000


u32 amd_dev_locate(void);
u8 amd_get_map_count(void);
u8 amd_get_domain_count(void);
void amd_dev_load_map(u8 domain, u8 size, u32 dev_bitmap_paddr);
u32 amd_dev_fetch_map(u8 domain);
u32 amd_dev_enable(u32 domain, u32 dev_bitmap_paddr);
void amd_dev_flush_cache(void);
int amd_dev_protect_pages(u32 domain, u32 start, u32 size, u32 map);

#endif /* _ASM_X86_AMD_DEV_H */
