/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019 Apertus Solutions, LLC
 *
 * Author(s):
 *     Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/memblock.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/setup.h>
#include <asm/slaunch.h>

#define PREFIX	"SLAUNCH: "

u32 sl_flags = 0;

u32 slaunch_get_flags(void)
{
	return sl_flags;
}

void __iomem *txt_early_get_heap_table(u32 type, u32 bytes)
{
	void __iomem *txt;
	void __iomem *heap;
	u64 base, size, offset = 0;
	int i;

	if (type > TXT_SINIT_MLE_DATA_TABLE) {
		printk(KERN_ERR PREFIX
		       "Error invalid type for early heap walk\n");
		/* TODO add TPM info log entry */
		return NULL;
	}

	txt = early_ioremap(TXT_PRIV_CONFIG_REGS_BASE,
			    TXT_NR_CONFIG_PAGES * PAGE_SIZE);
	if (!txt) {
		printk(KERN_ERR PREFIX
		       "Error early_ioremap of TXT registers for heap walk\n");
		/* TODO add TPM info log entry */
		return NULL;
	}

	memcpy_fromio(&base, txt + TXTCR_HEAP_BASE, sizeof(u64));
	if (unlikely(base == ~0ULL)) {
		printk(KERN_ERR PREFIX "Error early invalid TXT heap base\n");
		/* TODO add TPM info log entry */
		early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);
		return NULL;
	}

	memcpy_fromio(&size, txt + TXTCR_HEAP_SIZE, sizeof(u64));
	if (unlikely(size == ~0ULL)) {
		printk(KERN_ERR PREFIX "Error early invalid TXT heap size\n");
		/* TODO add TPM info log entry */
		early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);
		return NULL;
	}

	early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);

	/*
	 * The TXT heap is too big to map all at once with early_ioremap
	 * so it is done a table at a time.
	 */
	for (i = 0; i < type; i++) {
		base += offset;
		heap = early_ioremap(base, sizeof(u64));
		if (!heap) {
			printk(KERN_ERR PREFIX
			       "Error early_ioremap of heap for heap walk\n");
			/* TODO add TPM info log entry */
			return NULL;
		}
		memcpy_fromio(&offset, heap, sizeof(u64));
		early_iounmap(heap, sizeof(u64));
	}

	/* Skip the size field at the head of each table */
	base += sizeof(u64);
	heap = early_ioremap(base, bytes);
	if (!heap) {
		printk(KERN_ERR PREFIX
		       "Error early_ioremap of heap section\n");
		/* TODO add TPM info log entry */
		return NULL;
	}

	return heap;
}

static void slaunch_setup_intel(void)
{
	void __iomem *txt;
	u64 val = 0x1ULL;
	phys_addr_t base;

	txt = early_ioremap(TXT_PRIV_CONFIG_REGS_BASE,
			    TXT_NR_CONFIG_PAGES * PAGE_SIZE);
	if (!txt) {
		printk(KERN_ERR PREFIX
		       "Error early_ioremap of TXT registers\n");
		/* TODO add TPM info log entry */
		sl_flags = 0;
		return;
	}

	/*
	 * Try to read the Intel VID from the TXT private registers to see if
	 * TXT is active and the measured launch happened.
	 */
	memcpy_fromio(&val, txt + TXTCR_DIDVID, sizeof(u64));
	if ((u16)(val & 0xffff) != 0x8086) {
		printk(KERN_ERR PREFIX
		       "Invalid TXT vendor ID\n");
		/* TODO add TPM info log entry */
		sl_flags = 0;
		return;
	}

	/* On Intel, have to handle TPM localities via TXT */
	val = 0x1ULL;
	memcpy_toio(txt + TXTCR_CMD_SECRETS, &val, sizeof(u64));
	memcpy_fromio(&val, txt + TXTCR_E2STS, sizeof(u64));
	val = 0x1ULL;
	memcpy_toio(txt + TXTCR_CMD_OPEN_LOCALITY1, &val, sizeof(u64));
	memcpy_fromio(&val, txt + TXTCR_E2STS, sizeof(u64));

	early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);

	/*
	 * Protect the secure launch area in the .text section of the
	 * protected mode enty area where the APs are idling. Note the
	 * size we care about is far smaller than a page.
	 */
	base = boot_params.hdr.code32_start +
		boot_params.hdr.slaunch_header;
	if (memblock_reserve(base, PAGE_SIZE)) {
		printk(KERN_ERR PREFIX
		       "Secure Launch could not reserve AP wake region\n");
		/* TODO add TPM info log entry */
		sl_flags = 0;
		return;
	}

	/* TODO protect TXT priv-regs, heap and SINIT */
	/* TODO process MDRs and reserve mem regions */
	/* TODO validate the PMRs */
}

static void slaunch_setup_amd(void)
{
	/* TODO how to know we launched via SKINIT */
	/* TODO validate the DEV tables and devices */
}

void slaunch_setup(void)
{
	u32 vendor[4];

	/*
	 * First assume Secure Launch is enabled and this is a
	 * supported platform.
	 */
	sl_flags = SL_FLAG_ACTIVE;

	cpuid(0, &vendor[0], &vendor[1], &vendor[2], &vendor[3]);

	if (vendor[1] == 0x756e6547 &&        /* "Genu" */
	    vendor[2] == 0x6c65746e &&        /* "ntel" */
	    vendor[3] == 0x49656e69) {        /* "ineI" */
		sl_flags |= SL_FLAG_ARCH_TXT;
		slaunch_setup_intel();
	} else if (vendor[1] == 0x68747541 && /* "Auth" */
		   vendor[2] == 0x444d4163 && /* "cAMD" */
		   vendor[3] == 0x69746e65) { /* "enti" */
		sl_flags |= SL_FLAG_ARCH_SKINIT;
		slaunch_setup_amd();
	} else {
		printk(KERN_ERR PREFIX
		       "Invalid platform: not Intel or AMD\n");
		return;
	}
}
