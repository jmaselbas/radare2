/* radare - LGPL - Copyright 2023 - jmaselbas */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_arch.h>

enum {
	OP_NONE,
	OP_RS,
	OP_RS2,
	OP_RD,
	OP_DSP8,
	OP_DSP16,
	OP_UIMM4,
	OP_SIMM8,
	OP_SIMM16,
	OP_SIMM24,
	OP_UIMM32,
	OP_IMM3,
	OP_IMM5,
	OP_MI, /* MEMory EXtension */
};

struct rx_insn {
	const char *mnemonic;
	const char *fmt;
	ut16 len;
	ut8 msk[8];
	ut8 val[8];
	ut8 opt[8];
	ut32 type;
	ut32 cond;
};

#define LI_SIMM8  (1 << 2)
#define LI_SIMM16 (2 << 2)
#define LI_SIMM24 (3 << 2)
#define LI_UIMM32 (0 << 2)

#define MEMX     (0x06)
#define MI_B     (0 << 6)
#define MI_W     (1 << 6)
#define MI_L     (2 << 6)
#define MI_UL    (3 << 6)

#define LD_MSK   (3)
#define LD_DSP0  (0)
#define LD_DSP8  (1)
#define LD_DSP16 (2)

#define SZ_B     (0)
#define SZ_W     (1)
#define SZ_L     (2)

#define CD_EQ    (0x0)
#define CD_Z     CD_EQ
#define CD_NE    (0x1)
#define CD_NZ    CD_NE
#define CD_GEU   (0x2)
#define CD_C     CD_GEU
#define CD_LTU   (0x3)
#define CD_NC    CD_LTU
#define CD_GTU   (0x4)
#define CD_LEU   (0x5)
#define CD_PZ    (0x6)
#define CD_N     (0x7)
#define CD_GE    (0x8)
#define CD_LT    (0x9)
#define CD_GT    (0xa)
#define CD_LE    (0xb)
#define CD_O     (0xc)
#define CD_NO    (0xd)

struct rx_insn rx_insn[] = {
	/* ops   fmt          len  msk                 val */
	{ "abs", "%s",          2, {0xff, 0xf0},       {0x7e, 0x20}, },
	{ "abs", "%s, %s",      3, {0xff, 0xff},       {0xfc, 0x0f}, },
	{ "adc", "#%s, %s",     4, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_SIMM8,  0x20}, },
	{ "adc", "#%s, %s",     5, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_SIMM16, 0x20}, },
	{ "adc", "#%s, %s",     6, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_SIMM24, 0x20}, },
	{ "adc", "#%s, %s",     7, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_UIMM32, 0x20}, },
	{ "adc", "%s, %s",      3, {0xff, 0xff},       {0xfc, 0x0b}, },
	{ "adc", "[%s], %s",    4, {0xff, 0xff, 0xff}, {MEMX, MI_L | 0x20 | LD_DSP0,  0x02}, },
	{ "adc", "%s[%s], %s",  5, {0xff, 0xff, 0xff}, {MEMX, MI_L | 0x20 | LD_DSP8,  0x02}, },
	{ "adc", "%s[%s], %s",  6, {0xff, 0xff, 0xff}, {MEMX, MI_L | 0x20 | LD_DSP16, 0x02}, },

	/* (1) ADD src, dest */
	{ "add", "#%s, %s",     2, {0xff}, {0x62}, {OP_UIMM4, OP_RD} },
	/* (2) ADD src, dest */
	{ "add", "[%s], %s",    2, {0xff}, {0x48 | LD_DSP0},  {OP_RS, OP_RD} },
	{ "add", "[%s], %s",    2, {0xff}, {0x48 | 0x3},      {OP_RS, OP_RD} }, //??? add rs,rd ?
	{ "add", "%s[%s], %s",  3, {0xff}, {0x48 | LD_DSP8},  {OP_DSP8,  OP_RS, OP_RD} },
	{ "add", "%s[%s], %s",  4, {0xff}, {0x48 | LD_DSP16}, {OP_DSP16, OP_RS, OP_RD} },
	{ "add", "%s[%s]%s, %s",3, {0xff, 0x3f}, {MEMX, 0x02 | LD_DSP0 }, {0, OP_RD, OP_MI} },
	/* (3) ADD src, src2, dest */
	{ "add", "#%s, %s, %s", 3, {0xff}, {0x70 | LI_SIMM8},  {OP_SIMM8,  OP_RS, OP_RD} },
	{ "add", "#%s, %s, %s", 4, {0xff}, {0x70 | LI_SIMM16}, {OP_SIMM16, OP_RS, OP_RD} },
	{ "add", "#%s, %s, %s", 5, {0xff}, {0x70 | LI_SIMM24}, {OP_SIMM24, OP_RS, OP_RD} },
	{ "add", "#%s, %s, %s", 6, {0xff}, {0x70 | LI_UIMM32}, {OP_UIMM32, OP_RS, OP_RD} },
	{ "add", "%s, %s, %s",  3, {0xff, 0xf0}, {0xff, 0x20}, {OP_RS, OP_RS2, OP_RD} },
	{ "and" },
	/* Bcnd */
	{ "beq.s",  "%s", 1, {0xf8}, {0x10},         .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_EQ, },
	{ "bz.s",   "%s", 1, {0xf8}, {0x10},         .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_EQ, },
	{ "bne.s",  "%s", 1, {0xf8}, {0x18},         .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_NE, },
	{ "bnz.s",  "%s", 1, {0xf8}, {0x18},         .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_NE, },
	{ "beq.b",  "%s", 2, {0xff}, {0x20 | CD_EQ}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_EQ, },
	{ "bz.b",   "%s", 2, {0xff}, {0x20 | CD_Z},  .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_EQ, },
	{ "bne.b",  "%s", 2, {0xff}, {0x20 | CD_NE}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_NE, },
	{ "bnz.b",  "%s", 2, {0xff}, {0x20 | CD_NZ}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_NE, },
	{ "bgeu.b", "%s", 2, {0xff}, {0x20 | CD_GEU}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_GE, },
	{ "bc.b",   "%s", 2, {0xff}, {0x20 | CD_C},   .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_GE, },
	{ "bltu.b", "%s", 2, {0xff}, {0x20 | CD_LTU}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_LT, },
	{ "bnc.b",  "%s", 2, {0xff}, {0x20 | CD_NC},  .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_LT, },
	{ "bgtu.b", "%s", 2, {0xff}, {0x20 | CD_GTU}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_GT, },
	{ "bleu.b", "%s", 2, {0xff}, {0x20 | CD_LEU}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_LE, },
	{ "bpz.b",  "%s", 2, {0xff}, {0x20 | CD_PZ},  .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_PL, },
	{ "bn.b",   "%s", 2, {0xff}, {0x20 | CD_N},   .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_MI, },
	{ "bge.b",  "%s", 2, {0xff}, {0x20 | CD_GE},  .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_GE, },
	{ "blt.b",  "%s", 2, {0xff}, {0x20 | CD_LT},  .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_LT, },
	{ "bgt.b",  "%s", 2, {0xff}, {0x20 | CD_GT},  .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_GT, },
	{ "ble.b",  "%s", 2, {0xff}, {0x20 | CD_LE},  .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_LE, },
	{ "bo.b",   "%s", 2, {0xff}, {0x20 | CD_O},   .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_VS, },
	{ "bno.b",  "%s", 2, {0xff}, {0x20 | CD_NO},  .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_VC, },
	{ "beq.w",  "%s", 3, {0xff}, {0x3a}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_EQ },
	{ "bz.w",   "%s", 3, {0xff}, {0x3a}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_EQ },
	{ "bne.w",  "%s", 3, {0xff}, {0x3b}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_NE },
	{ "bnz.w",  "%s", 3, {0xff}, {0x3b}, .type = R_ANAL_OP_TYPE_CJMP, .cond = R_ANAL_COND_NE },
	{ "bm" }, /* BMcnd */

	{ "bnot", "#%s, [%s]",   3, {0xff, 0xe0 | LD_MSK, 0x0f}, {0xfc, 0xe0 | LD_DSP0,  0x0f}, {OP_IMM3, OP_RD}, },
	{ "bnot", "#%s, %s[%s]", 4, {0xff, 0xe0 | LD_MSK, 0x0f}, {0xfc, 0xe0 | LD_DSP8,  0x0f}, {OP_IMM3, OP_DSP8,  OP_RD}, },
	{ "bnot", "#%s, %s[%s]", 5, {0xff, 0xe0 | LD_MSK, 0x0f}, {0xfc, 0xe0 | LD_DSP16, 0x0f}, {OP_IMM3, OP_DSP16, OP_RD}, },
	{ "bnot", "%s, [%s]",    3, {0xff, 0xfc | LD_MSK},       {0xfc, 0x6c | LD_DSP0},        {OP_RS, OP_RD}, },
	{ "bnot", "%s, %s[%s]",  4, {0xff, 0xfc | LD_MSK},       {0xfc, 0x6c | LD_DSP8},        {OP_RS, OP_DSP8, OP_RD}, },
	{ "bnot", "%s, %s[%s]",  5, {0xff, 0xfc | LD_MSK},       {0xfc, 0x6c | LD_DSP16},       {OP_RS, OP_DSP16, OP_RD}, },
	{ "bnot", "#%s, %s",     3, {0xff, 0xe0, 0xf0},          {0xfd, 0xe0, 0xf0}, {OP_IMM5, OP_RD}, },
	{ "bnot", "%s, %s",      3, {0xff, 0xff},                {0xfc, 0x6f},  {OP_RD, OP_RS}, },

	{ "bra.s", "%s", 1, {0xf8},       {0x08} },
	{ "bra.b", "%s", 2, {0xff},       {0x2e} },
	{ "bra.w", "%s", 3, {0xff},       {0x38} },
	{ "bra.a", "%s", 4, {0xff},       {0x04} },
	{ "bra.l", "%s", 2, {0xff, 0xf0}, {0x7f, 0x40} },
	{ "brk", "", 1, {0xff}, {0x00},  },
	{ "bset" },
	{ "bsr.l", "%s", 2, {0xff, 0xf0}, {0x7f, 0x50}, },
	{ "bsr.w", "%s", 3, {0xff},       {0xc9}, },
	{ "bsr.a", "%s", 4, {0xff},       {0x05}, },
	{ "btst" },
	{ "clrpsw", "%s", 2, {0xff, 0xf0}, {0x7f, 0xb0} }, // CB
	{ "cmp" },
	{ "div" },
	{ "divu" },
	{ "emaca" },
	{ "emsba" },
	{ "emul" },
	{ "emula" },
	{ "emulu" },
	{ "fadd" },
	{ "fcmp" },
	{ "fdiv" },
	{ "fmul" },
	{ "fsqrt" },
	{ "fsub" },
	{ "ftoi" },
	{ "ftou" },
	{ "int", "%s", 3, {0xff, 0xff}, {0x75, 0x60} }, // IMM8
	{ "itof" },
	{ "jmp", "%s", 2, {0xff, 0xf0}, {0x7f, 0x00} },
	{ "jsr", "%s", 2, {0xff, 0xf0}, {0x7f, 0x10} },
	{ "machi", "%s, %s, A0", 3, {0xff, 0xff}, {0xfd, 0x04} },
	{ "machi", "%s, %s, A1", 3, {0xff, 0xff}, {0xfd, 0x0c} },
	{ "maclh", "%s, %s, A0", 3, {0xff, 0xff}, {0xfd, 0x06} },
	{ "maclh", "%s, %s, A1", 3, {0xff, 0xff}, {0xfd, 0x0e} },
	{ "maclo", "%s, %s, A0", 3, {0xff, 0xff}, {0xfd, 0x05} },
	{ "maclo", "%s, %s, A1", 3, {0xff, 0xff}, {0xfd, 0x07} },
	{ "max" },
	{ "min" },
	{ "mov" },
	{ "movco" },
	{ "movli" },
	{ "movu" },
	{ "msbhi" },
	{ "msblh" },
	{ "msblo" },
	{ "mul" },
	{ "mulhi" },
	{ "mullh" },
	{ "mullo" },
	{ "mvfacgu" },
	{ "mvfachi" },
	{ "mvfaclo" },
	{ "mvfacmi" },
	{ "mvfc" },
	{ "mvtipl" },
	{ "neg", "%s",        2, {0xff, 0xf0}, {0x7e, 0x10} },
	{ "neg", "%s, %s",    3, {0xff, 0xff}, {0xfc, 0x07} },
	{ "nop", "",          1, {0xff},       {0x03} },
	{ "not", "%s",        2, {0xff, 0xf0}, {0x7e, 0x00} },
	{ "not", "%s, %s",    3, {0xff, 0xff}, {0xfc, 0x3b} },
	{ "or" },
	{ "pop",  "%s",       2, {0xff, 0xf0}, {0x7e, 0xb0} },
	{ "popc", "%s",       2, {0xff, 0xf0}, {0x7e, 0xe0} },
	{ "popm", "%s",       2, {0xff},       {0x6f} },
	{ "push", },
	{ "pushc", },
	{ "pushm", },
	{ "racl" },
	{ "racw" },
	{ "rdacl" },
	{ "revl" },
	{ "revw" },
	{ "rmpa" },
	{ "rolc" },
	{ "rorc" },
	{ "rotl" },
	{ "rotr" },
	{ "round" },
	{ "rte", "",             2, {0xff, 0xff}, {0x7f, 0x95} },
	{ "rtfi", "",            2, {0xff, 0xff}, {0x7f, 0x94} },
	{ "rts", "",             1, {0xff},       {0x02} },
	{ "rtsd", "#%s",         2, {0xff},       {0x67} }, // UIMM8
	{ "rtsd", "#%s, %s",     3, {0xff},       {0x3f} }, // RDRD2 UIMM8
	{ "sat", "%s",           2, {0xff, 0xf0}, {0x7e, 0x30} }, // RD
	{ "satr", "",            2, {0xff, 0xff}, {0x7f, 0x9c} },
	{ "sbb", },
	{ "sceq" },
	{ "scmpu", "",           2, {0xff, 0xff}, {0x7f, 0x83} },
	{ "setpsw", "",          2, {0xff, 0xf0}, {0x7f, 0x90} }, // CB
	{ "shar", "#%s, %s",     2, {0xfe},       {0x6a} }, // SIMM5 RD
	{ "shar", "%s, %s",      3, {0xff, 0xff}, {0xfd, 0x61} }, // RS RD
	{ "shar", "#%s, %s, %s", 3, {0xff, 0xe0}, {0xfd, 0xa0} },
	{ "shll", "#%s, %s",     2, {0xfe},       {0x6c} },
	{ "shll", "%s, %s",      3, {0xff, 0xff}, {0xfd, 0x62} },
	{ "shll", "#%s, %s, %s", 3, {0xff, 0xe0}, {0xfd, 0xc0} },
	{ "shlr", "#%s, %s",     2, {0xfe},       {0x68} },
	{ "shlr", "#%s, %s",     3, {0xff, 0xff}, {0xfd, 0x60} },
	{ "shlr", "#%s, %s",     3, {0xff, 0xe0}, {0xfd, 0x80} },
	{ "smovb", "",  2, {0xff, 0xff}, {0x7f, 0x8b} },
	{ "smovf", "",  2, {0xff, 0xff}, {0x7f, 0x8f} },
	{ "smovu", "",  2, {0xff, 0xff}, {0x7f, 0x87} },
	{ "sstr.b", "", 2, {0xff, 0xff}, {0x7f, 0x88 | SZ_B} },
	{ "sstr.w", "", 2, {0xff, 0xff}, {0x7f, 0x88 | SZ_W} },
	{ "sstr.l", "", 2, {0xff, 0xff}, {0x7f, 0x88 | SZ_L} },

	{ "stnz", "#%s, %s",  4, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_SIMM8,  0xf0} },
	{ "stnz", "#%s, %s",  5, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_SIMM16, 0xf0} },
	{ "stnz", "#%s, %s",  6, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_SIMM24, 0xf0} },
	{ "stnz", "#%s, %s",  7, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_UIMM32, 0xf0} },
	{ "stnz", "%s, %s",   3, {0xff, 0xff},       {0xfc, 0x4f} },

	{ "stz", "#%s, %s",   4, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_SIMM8,  0xe0} },
	{ "stz", "#%s, %s",   5, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_SIMM16, 0xe0} },
	{ "stz", "#%s, %s",   6, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_SIMM24, 0xe0} },
	{ "stz", "#%s, %s",   7, {0xff, 0xff, 0xf0}, {0xfd, 0x70 | LI_UIMM32, 0xe0} },
	{ "stz", "%s, %s",    3, {0xff, 0xff},       {0xfc, 0x4b} },
	{ "sub" },

	{ "suntil.b", "",     2, {0xff, 0xff},       {0x7f, 0x80 | SZ_B} },
	{ "suntil.w", "",     2, {0xff, 0xff},       {0x7f, 0x80 | SZ_W} },
	{ "suntil.l", "",     2, {0xff, 0xff},       {0x7f, 0x80 | SZ_L} },
	{ "swhile.b", "",     2, {0xff, 0xff},       {0x7f, 0x84 | SZ_B} },
	{ "swhile.w", "",     2, {0xff, 0xff},       {0x7f, 0x84 | SZ_W} },
	{ "swhile.l", "",     2, {0xff, 0xff},       {0x7f, 0x84 | SZ_L} },
	{ "tst" },
	{ "utof" },
	{ "wait", "",         2, {0xff, 0xff}, {0x7f, 0x96} },
	{ "xchg" },
	{ "xor" },
};

static int rx_insn_cmp(const struct rx_insn *insn, size_t len, const ut8 *data) {
	size_t i;
	if (len < insn->len) {
		return false;
	}
	for (i = 0; i < insn->len; i++) {
		if ((data[i] & insn->msk[i]) != insn->val[i]) {
			return false;
		}
	}
	return true;
}

static const struct rx_insn *rx_match_insn(size_t len, const ut8 *data) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE(rx_insn); i++) {
		if (rx_insn_cmp(&rx_insn[i], len, data)) {
			return &rx_insn[i];
		}
	}
	return NULL;
}

static bool rx_op(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const size_t len = op->size;
	const ut8 *data = op->bytes;
	char strasm[64];

	struct rx_insn *insn = rxv2_decode_opc (addr, len, data);
	if (!insn) {
		op->type = R_ANAL_OP_TYPE_UNK;
		return false; /* invalid */
	}
	op->size = insn->len * sizeof (ut8);

	if (mask & R_ARCH_OP_MASK_DISASM) {
		//rx_opc_print (opcinsn, addr, strasm, sizeof (strasm));
		// op->mnemonic = strdup (strasm);
		op->mnemonic = strdup (insn->mnemonic);
	}

	op->type = insn->type;
	op->cond = insn->cond;
	// op->fail = addr;
	// op->jump = get jump addr
	op->eob = ((op->type & R_ANAL_OP_TYPE_RET) == R_ANAL_OP_TYPE_RET);

	return true;
}

static int rx_info(RArchSession *a, ut32 query) {
	switch (query) {
	case R_ARCH_INFO_MIN_OP_SIZE:
		return 1;
	case R_ARCH_INFO_MAX_OP_SIZE:
		return 7;
	case R_ARCH_INFO_ALIGN:
		return 1;
	case R_ARCH_INFO_DATA_ALIGN:
		return 0;
	default:
		return 0;
	}
}

RArchPlugin r_arch_plugin_rx = {
	.name = "rx",
	.desc = "Renesas RX family",
	.arch = "rx",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.info = rx_info,
	.decode = rx_op,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_rx,
	.version = R2_VERSION
};
#endif
