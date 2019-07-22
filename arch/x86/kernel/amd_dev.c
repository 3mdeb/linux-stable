/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 Apertus Solutions, LLC
 *
 * Author(s):
 *	Daniel P. Smith <dpsmith@apertussolutions.com>
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/pfn.h>
#include <asm/pci-direct.h>
#include <asm/processor.h>
#include <asm/amd_dev.h>

static u32 dev_read(u8 func, u8 index)
{
	u32 dev_op = (func << 8) | (index);
	u32 data;

	write_pci_config(DEV_PCI_BUS, DEV_PCI_DEVICE, DEV_PCI_FUNCTION,
			DEV_PCI_OP, dev_op);

	data = read_pci_config(DEV_PCI_BUS, DEV_PCI_DEVICE, DEV_PCI_FUNCTION,
			DEV_PCI_DATA);

	return data;
}

static void dev_write(u8 func, u8 index, u32 val)
{
	u32 dev_op = (func << 8) | (index);

	write_pci_config(DEV_PCI_BUS, DEV_PCI_DEVICE, DEV_PCI_FUNCTION,
			DEV_PCI_OP, dev_op);

	write_pci_config(DEV_PCI_BUS, DEV_PCI_DEVICE, DEV_PCI_FUNCTION,
			DEV_PCI_DATA, val);
}

u32 amd_dev_locate(void)
{
	u32 dev_cap_hdr;

	/* read capabilities pointer */
	dev_cap_hdr = read_pci_config(DEV_PCI_BUS, DEV_PCI_DEVICE,
			DEV_PCI_FUNCTION, DEV_PCI_HDR);

	if ( (dev_cap_hdr & 0xFF) != PCI_CAPABILITIES_ID_DEV)
		return 0;

	return dev_cap_hdr;
}

u8 amd_get_map_count(void)
{
	u32 cap_reg;

	cap_reg = dev_read(DEV_CAP, 0);

	return (u8)((cap_reg >> 16) & 0xFF);
}

u8 amd_get_domain_count(void)
{
	u32 cap_reg;

	cap_reg = dev_read(DEV_CAP, 0);

	return (u8)((cap_reg >> 8) & 0xFF);
}

void amd_dev_load_map(u8 domain, u8 size, u32 dev_bitmap_paddr)
{
	u32 dev_base_hi = 0;
	u32 dev_base_low = 0;
	u8 fields;

	fields = ((size << 2) & 0x7c);
	fields |= DEV_BASE_LO_VALID_MASK;

	dev_base_low = dev_bitmap_paddr & DEV_BASE_LO_ADDR_MASK;
	dev_base_low |= fields;

	dev_write(DEV_BASE_HI, domain, dev_base_hi);
	dev_write(DEV_BASE_LO, domain, dev_base_low);
}

u32 amd_dev_fetch_map(u8 domain)
{
	u32 dev_base_hi = 0;
	u32 dev_base_low = 0;

	dev_base_hi = dev_read(DEV_BASE_HI, domain);
	dev_base_low = dev_read(DEV_BASE_LO, domain);

	dev_base_low &= DEV_BASE_LO_ADDR_MASK;

	return dev_base_low;
}

u32 amd_dev_enable(u32 domain, u32 dev_bitmap_paddr)
{
	u32 dev_cr;

	/* enable DEV protections */
	dev_cr = (DEV_CR_ENABLE_MASK | DEV_CR_IOSP_EN_MASK |
			DEV_CR_SL_DEV_EN_MASK);

	dev_write(DEV_CR, 0, dev_cr);

	return 0;
}

void amd_dev_flush_cache(void)
{
	u32 dev_cr;

	dev_cr = dev_read(DEV_CR, 0);
	dev_cr |= (DEV_CR_INV_CACHE_MASK | DEV_CR_ENABLE_MASK);
	dev_write(DEV_CR, 0, dev_cr);

	/* TODO: extend loop with timeout to prohibit infinite loop */
	while (dev_cr && DEV_CR_INV_CACHE_MASK)
                dev_cr = dev_read(DEV_CR, 0);
}


int amd_dev_protect_pages(u32 domain, u32 start, u32 size, u32 map)
{
	u32 dev_map;
	u32 pfn, end_pfn;
	int err;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD)
		return 0;

	if (map == 0) {
		dev_map = amd_dev_fetch_map(domain);
		if (dev_map == 0) {
			err = -ENODEV;
			goto out;
		}
	} else {
		dev_map = map;
	}

	pfn = PHYS_PFN(start);
	end_pfn = PHYS_PFN((start + size) & PAGE_MASK);

	/* TODO: check end_pfn is not ouside of range of DEV map */

	/* build protection bitmap */
	for ( ; pfn <= end_pfn; pfn++) {
		u32 byte, bit;
		u8 *bit_vector = (u8*)(u64)dev_map;

		byte= pfn / 8;
		bit= pfn & 7;
		bit_vector[byte] |= (1 << bit);
	}

out:
	return err;
}
