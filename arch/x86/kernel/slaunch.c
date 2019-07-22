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
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/security.h>
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

/* This should be plenty of room */
static u8 txt_dmar[PAGE_SIZE] __attribute__((aligned(16)));

struct acpi_table_header *slaunch_get_dmar_table(struct acpi_table_header *dmar)
{
	if (memcmp(txt_dmar, "DMAR", 4))
		return dmar;
	return (struct acpi_table_header*)(&txt_dmar[0]);
}

static void slaunch_copy_dmar_table(void)
{
	void __iomem *txt;
	void __iomem *heap;
	void __iomem *sinit_mle_data;
	u32 dmar_offset, dmar_size;
	u64 base, size;

	memset(&txt_dmar, 0, PAGE_SIZE);

	txt = ioremap(TXT_PRIV_CONFIG_REGS_BASE,
		      TXT_NR_CONFIG_PAGES * PAGE_SIZE);
	if (!txt) {
		printk(KERN_ERR PREFIX
		       "Error ioremap of TXT registers\n");
		/* TODO add TPM info log entry */
		return;
	}

	memcpy_fromio(&base, txt + TXTCR_HEAP_BASE, sizeof(u64));
	if (unlikely(base == ~0ULL)) {
		printk(KERN_ERR PREFIX "Error invalid TXT heap base\n");
		/* TODO add TPM info log entry */
		iounmap(txt);
		return;
	}

	memcpy_fromio(&size, txt + TXTCR_HEAP_SIZE, sizeof(u64));
	if (unlikely(size == ~0ULL)) {
		printk(KERN_ERR PREFIX "Error invalid TXT heap size\n");
		/* TODO add TPM info log entry */
		iounmap(txt);
		return;
	}

	iounmap(txt);

	heap = ioremap(base, size);
	if (unlikely(!heap)) {
		printk(KERN_ERR PREFIX "Error ioremap TXT heap failed\n");
		/* TODO add TPM info log entry */
		return;
	}

	sinit_mle_data = txt_sinit_mle_data_start(heap);
	dmar_size = readl(sinit_mle_data + TXT_SINIT_MLE_DMAR_TABLE_SIZE);
	dmar_offset = readl(sinit_mle_data + TXT_SINIT_MLE_DMAR_TABLE_OFFSET);

	if (unlikely(dmar_size > PAGE_SIZE)) {
		/* TODO add TPM info log entry */
		iounmap(heap);
		return;
	}

	memcpy_fromio(&txt_dmar[0], (void*)(sinit_mle_data + dmar_offset),
		      dmar_size);
	iounmap(heap);
}

struct memfile {
	char *name;
	void __iomem *addr;
	size_t size;
};

static struct memfile sl_evtlog = {"eventlog", 0, 0};
static void __iomem *txt_heap = NULL;

static ssize_t sl_memfile_read(struct memfile *file, char __user *outbuf, size_t count, loff_t *pos)
{
	void *buf;
	int ret = -EFAULT;

	if (!file->addr)
		goto err;

	if (*pos >= file->size) {
		ret = 0;
		goto err;
	}

	if (*pos + count > file->size)
		count = file->size - *pos;

	buf = kmalloc(count, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto free;
	}

	memcpy_fromio(buf, file->addr + *pos, count);
	if (copy_to_user(outbuf, buf, count))
		goto free;

	*pos += count;

	ret = count;

free:
	kfree(buf);

err:
	return ret;
}

static ssize_t sl_evtlog_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	return sl_memfile_read(&sl_evtlog, buf, count, pos);
}

static const struct file_operations sl_evtlog_ops = {
        .read = sl_evtlog_read,
	.llseek	= default_llseek,
};

#define SL_DIR_ENTRY	1 /* directoy node must be last */
#define SL_FS_ENTRIES	2

static struct dentry *fs_entries[SL_FS_ENTRIES];

static long slaunch_expose_securityfs(void)
{
	long ret = 0;
	int entry = SL_DIR_ENTRY;

	fs_entries[entry] = securityfs_create_dir("slaunch", NULL);
	if (IS_ERR(fs_entries[entry])) {
		printk(KERN_ERR PREFIX
			"Error creating securityfs sl_evt_log directory\n");
		ret = PTR_ERR(fs_entries[entry]);
		goto out;
	}

	if (sl_evtlog.addr > 0) {
		entry--;
		fs_entries[entry] = securityfs_create_file(sl_evtlog.name,
					   S_IRUSR | S_IRGRP,
					   fs_entries[SL_DIR_ENTRY], NULL,
					   &sl_evtlog_ops);
		if (IS_ERR(fs_entries[entry])) {
			printk(KERN_ERR PREFIX
				"Error creating securityfs %s file\n",
				sl_evtlog.name);
			ret = PTR_ERR(fs_entries[entry]);
			goto out_dir;
		}
	}

	return 0;

out_dir:
	securityfs_remove(fs_entries[SL_DIR_ENTRY]);
out:
	return ret;
}

static void slaunch_teardown_securityfs(void)
{
	int i;

	for (i = 0; i < SL_FS_ENTRIES; i++)
		securityfs_remove(fs_entries[i]);

	if (sl_flags & SL_FLAG_ARCH_TXT) {
		if (txt_heap) {
			iounmap(txt_heap);
			txt_heap = NULL;
		}
	}

	/* TODO AMD */

	sl_evtlog.addr = 0;
	sl_evtlog.size = 0;
}

static void slaunch_intel_evtlog(void)
{
	void __iomem *config;
	struct txt_os_mle_data *params;

	config = ioremap(TXT_PUB_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
			 PAGE_SIZE);
	if (!config) {
		printk(KERN_ERR PREFIX "Error failed to ioremap TXT reqs\n");
		return;
	}

	/* now map TXT heap */
	txt_heap = ioremap(*(u64 *)(config + TXTCR_HEAP_BASE),
		    *(u64 *)(config + TXTCR_HEAP_SIZE));
	iounmap(config);
	if (!txt_heap) {
		printk(KERN_ERR PREFIX "Error failed to ioremap TXT heap\n");
		return;
	}

	params = (struct txt_os_mle_data *)txt_os_mle_data_start(txt_heap);

	sl_evtlog.size = TXT_MAX_EVENT_LOG_SIZE;
	sl_evtlog.addr = (void __iomem*)&params->event_log_buffer[0];
}

static void slaunch_amd_evtlog(void)
{
	/* TODO */
}

static int __init slaunch_late_init(void)
{
	if (sl_flags & SL_FLAG_ARCH_TXT) {
		/* Make a copy of the TXT heap provided DMAR for IOMMU later */
		slaunch_copy_dmar_table();
		/* Any errors from previous call will go in event log */
		slaunch_intel_evtlog();
	}
	else if (sl_flags & SL_FLAG_ARCH_SKINIT)
		slaunch_amd_evtlog();
	else
		BUG();

	return slaunch_expose_securityfs();
}

static void __exit slaunch_exit(void)
{
	slaunch_teardown_securityfs();
}

late_initcall(slaunch_late_init);

__exitcall(slaunch_exit);
