/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/sha1.h>
#include <asm/tpm.h>
#include <asm/bootparam.h>
#include <asm/slaunch.h>

extern u32 sl_cpu_type;

static u64 sl_txt_read(u32 reg)
{
	void *addr = (void*)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg);
	u64 val;

	barrier();
	val = (*(volatile u64*)(addr));
	rmb();

	return val;
}

static void sl_txt_write(u32 reg, u64 val)
{
	void *addr = (void*)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg);

	barrier();
	(*(volatile u64 *)(addr)) = val;
	wmb();
	barrier();
}

static void sl_txt_reset(u64 error)
{
	sl_txt_write(TXTCR_ERRORCODE, error);
	(void)sl_txt_read(TXTCR_E2STS);
	sl_txt_write(TXTCR_CMD_UNLOCK_MEM_CONFIG, 1);
	(void)sl_txt_read(TXTCR_E2STS);
	sl_txt_write(TXTCR_CMD_RESET, 1);
	for ( ; ; )
		__asm__ __volatile__ ("pause");
}

static void sl_skinit_reset(void)
{
	/* TODO not sure what else to do here. Is there an error reg */
	__asm__ __volatile__ ("ud2");
}

static u64 sl_rdmsr(u32 reg)
{
	u32 lo, hi;
	u64 val;

	__asm__ __volatile__ ("rdmsr"  : "=a" (lo), "=d" (hi) : "c" (reg));
	val = hi;
	return ((val << 32) & 0xffffffff00000000) | lo;
}

static void sl_txt_validate_msrs(struct txt_os_mle_data *os_mle_data)
{
#define CAPS_VARIABLE_MTRR_COUNT_MASK   0xff
	u64 mtrr_caps, mtrr_def_type, mtrr_var, misc_en_msr;
	u32 vcnt, i;
	struct txt_mtrr_state *saved_bsp_mtrrs =
		&(os_mle_data->saved_bsp_mtrrs);

	mtrr_caps = sl_rdmsr(MSR_MTRRcap);
	vcnt = (u32)(mtrr_caps & CAPS_VARIABLE_MTRR_COUNT_MASK);

	if (saved_bsp_mtrrs->mtrr_vcnt > vcnt)
		sl_txt_reset(TXT_SLERROR_MTRR_INV_VCNT);
	if (saved_bsp_mtrrs->mtrr_vcnt > TXT_MAX_VARIABLE_MTRRS)
		sl_txt_reset(TXT_SLERROR_MTRR_INV_VCNT);

	mtrr_def_type = sl_rdmsr(MSR_MTRRdefType);
	if (saved_bsp_mtrrs->default_type_reg != mtrr_def_type)
		sl_txt_reset(TXT_SLERROR_MTRR_INV_DEF_TYPE);

	for (i = 0; i < saved_bsp_mtrrs->mtrr_vcnt; i++) {
		mtrr_var = sl_rdmsr(MTRRphysBase_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physbase != mtrr_var)
			sl_txt_reset(TXT_SLERROR_MTRR_INV_BASE);
		mtrr_var = sl_rdmsr(MTRRphysMask_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physmask != mtrr_var)
			sl_txt_reset(TXT_SLERROR_MTRR_INV_MASK);
	}

	misc_en_msr = sl_rdmsr(MSR_IA32_MISC_ENABLE);
	if (os_mle_data->saved_misc_enable_msr != misc_en_msr)
		sl_txt_reset(TXT_SLERROR_MSR_INV_MISC_EN);
}

void sl_main(u8 *bootparams)
{
	struct sha1_state sctx = {0};
	u8 sha1_hash[SHA1_DIGEST_SIZE];
	struct tpm *tpm;
	struct boot_params *bp;
	int ret;

	memset(sha1_hash, 0, SHA1_DIGEST_SIZE);

	/*
	 * If enable_tpm fails there is no point going on. The entire secure
	 * environment depends on this and the other TPM operations succeeding.
	 */
	tpm = enable_tpm();
	if (!tpm) {
		if (sl_cpu_type == SL_CPU_INTEL)
			sl_txt_reset(TXT_SLERROR_TPM_INIT);
		else
			sl_skinit_reset();
	}

	if (tpm_request_locality(tpm, 2) == TPM_NO_LOCALITY) {
		if (sl_cpu_type == SL_CPU_INTEL)
			sl_txt_reset(TXT_SLERROR_TPM_GET_LOC);
		else
			sl_skinit_reset();
	}

	/* Measure the zero page/boot params */
	early_sha1_init(&sctx);
	early_sha1_update(&sctx, bootparams, PAGE_SIZE);
	early_sha1_finalize(&sctx);
	early_sha1_finish(&sctx, &sha1_hash[0]);
	ret = tpm_extend_pcr(tpm, 18, TPM_HASH_ALG_SHA1, &sha1_hash[0]);
	if (ret) {
		if (sl_cpu_type == SL_CPU_INTEL)
			sl_txt_reset(TXT_SLERROR_TPM_EXTEND);
		else
			sl_skinit_reset();
	}

	/* Now safe to use boot params */
	bp = (struct boot_params*)bootparams;

	/* Measure the command line */
	memset(sha1_hash, 0, SHA1_DIGEST_SIZE);
	early_sha1_init(&sctx);
	early_sha1_update(&sctx, (u8*)((u64)bp->hdr.cmd_line_ptr),
			  bp->hdr.cmdline_size);
	early_sha1_finalize(&sctx);
	early_sha1_finish(&sctx, &sha1_hash[0]);
	ret = tpm_extend_pcr(tpm, 18, TPM_HASH_ALG_SHA1, &sha1_hash[0]);
	if (ret) {
		if (sl_cpu_type == SL_CPU_INTEL)
			sl_txt_reset(TXT_SLERROR_TPM_EXTEND);
		else
			sl_skinit_reset();
	}

	/* Measure any external initrd */
	if (bp->hdr.ramdisk_image != 0 && bp->hdr.ramdisk_size != 0) {
		memset(sha1_hash, 0, SHA1_DIGEST_SIZE);
		early_sha1_init(&sctx);
		early_sha1_update(&sctx, (u8*)((u64)bp->hdr.ramdisk_image),
				  bp->hdr.ramdisk_size);
		early_sha1_finalize(&sctx);
		early_sha1_finish(&sctx, &sha1_hash[0]);
		ret = tpm_extend_pcr(tpm, 17, TPM_HASH_ALG_SHA1, &sha1_hash[0]);
		if (ret) {
			if (sl_cpu_type == SL_CPU_INTEL)
				sl_txt_reset(TXT_SLERROR_TPM_EXTEND);
			else
				sl_skinit_reset();
		}
	}

	if (sl_cpu_type == SL_CPU_INTEL) {
		struct txt_os_mle_data *os_mle_data;
		u64 *txt_heap;
		u64 bios_data_size;
		u32 os_mle_len;

		/*
		 * Some extra work to do on Intel, have to measure the OS-MLE
		 * heap area.
		 */
		txt_heap = (void*)sl_txt_read(TXTCR_HEAP_BASE);
		bios_data_size = *txt_heap;
		os_mle_data = (struct txt_os_mle_data*)
				((u8*)txt_heap + bios_data_size + sizeof(u64));

		/* Measure OS-MLE data up to the TPM log into 18 */
		os_mle_len = offsetof(struct txt_os_mle_data, event_log_buffer);
		early_sha1_init(&sctx);
		early_sha1_update(&sctx, (u8*)os_mle_data, os_mle_len);
		early_sha1_finalize(&sctx);
		early_sha1_finish(&sctx, &sha1_hash[0]);
		ret = tpm_extend_pcr(tpm, 18, TPM_HASH_ALG_SHA1, &sha1_hash[0]);
		if (ret) {
			if (sl_cpu_type == SL_CPU_INTEL)
				sl_txt_reset(TXT_SLERROR_TPM_EXTEND);
			else
				sl_skinit_reset();
		}

		/*
		 * Now that the OS-MLE data is measured, ensure the MTRR and
		 * misc enable MSRs are what we expect.
		 */
		sl_txt_validate_msrs(os_mle_data);
	}

	tpm_relinquish_locality(tpm);
	free_tpm(tpm);
}
