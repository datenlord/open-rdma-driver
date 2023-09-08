/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef DTLD_HDR_H
#define DTLD_HDR_H

/* extracted information about a packet carried in an sk_buff struct fits in
 * the skbuff cb array. Must be at most 48 bytes. stored in control block of
 * sk_buff for received packets.
 */
struct dtld_pkt_info {
	struct dtld_dev		*dtld;		/* device that owns packet */
	struct dtld_qp		*qp;		/* qp that owns packet */
	struct dtld_send_wqe	*wqe;		/* send wqe */
	u8			*hdr;		/* points to bth */
	u32			mask;		/* useful info about pkt */
	u32			psn;		/* bth psn of packet */
	u16			pkey_index;	/* partition of pkt */
	u16			paylen;		/* length of bth - icrc */
	u8			port_num;	/* port pkt received on */
	u8			opcode;		/* bth opcode of packet */
};

/* Macros should be used only for received skb */
static inline struct dtld_pkt_info *SKB_TO_PKT(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct dtld_pkt_info) > sizeof(skb->cb));
	return (void *)skb->cb;
}

static inline struct sk_buff *PKT_TO_SKB(struct dtld_pkt_info *pkt)
{
	return container_of((void *)pkt, struct sk_buff, cb);
}

/*
 * IBA header types and methods
 *
 * Some of these are for reference and completeness only since
 * dtld does not currently support RD transport
 * most of this could be moved into IB core. ib_pack.h has
 * part of this but is incomplete
 *
 * Header specific routines to insert/extract values to/from headers
 * the routines that are named __hhh_(set_)fff() take a pointer to a
 * hhh header and get(set) the fff field. The routines named
 * hhh_(set_)fff take a packet info struct and find the
 * header and field based on the opcode in the packet.
 * Conversion to/from network byte order from cpu order is also done.
 */

#define DTLD_ICRC_SIZE		(4)
#define DTLD_MAX_HDR_LENGTH	(80)

/******************************************************************************
 * Base Transport Header
 ******************************************************************************/
struct dtld_bth {
	u8			opcode;
	u8			flags;
	__be16			pkey;
	__be32			qpn;
	__be32			apsn;
};

#define BTH_TVER		(0)
#define BTH_DEF_PKEY		(0xffff)

#define BTH_SE_MASK		(0x80)
#define BTH_MIG_MASK		(0x40)
#define BTH_PAD_MASK		(0x30)
#define BTH_TVER_MASK		(0x0f)
#define BTH_FECN_MASK		(0x80000000)
#define BTH_BECN_MASK		(0x40000000)
#define BTH_RESV6A_MASK		(0x3f000000)
#define BTH_QPN_MASK		(0x00ffffff)
#define BTH_ACK_MASK		(0x80000000)
#define BTH_RESV7_MASK		(0x7f000000)
#define BTH_PSN_MASK		(0x00ffffff)

static inline u8 __bth_opcode(void *arg)
{
	struct dtld_bth *bth = arg;

	return bth->opcode;
}

static inline void __bth_set_opcode(void *arg, u8 opcode)
{
	struct dtld_bth *bth = arg;

	bth->opcode = opcode;
}

static inline u8 __bth_se(void *arg)
{
	struct dtld_bth *bth = arg;

	return 0 != (BTH_SE_MASK & bth->flags);
}

static inline void __bth_set_se(void *arg, int se)
{
	struct dtld_bth *bth = arg;

	if (se)
		bth->flags |= BTH_SE_MASK;
	else
		bth->flags &= ~BTH_SE_MASK;
}

static inline u8 __bth_mig(void *arg)
{
	struct dtld_bth *bth = arg;

	return 0 != (BTH_MIG_MASK & bth->flags);
}

static inline void __bth_set_mig(void *arg, u8 mig)
{
	struct dtld_bth *bth = arg;

	if (mig)
		bth->flags |= BTH_MIG_MASK;
	else
		bth->flags &= ~BTH_MIG_MASK;
}

static inline u8 __bth_pad(void *arg)
{
	struct dtld_bth *bth = arg;

	return (BTH_PAD_MASK & bth->flags) >> 4;
}

static inline void __bth_set_pad(void *arg, u8 pad)
{
	struct dtld_bth *bth = arg;

	bth->flags = (BTH_PAD_MASK & (pad << 4)) |
			(~BTH_PAD_MASK & bth->flags);
}

static inline u8 __bth_tver(void *arg)
{
	struct dtld_bth *bth = arg;

	return BTH_TVER_MASK & bth->flags;
}

static inline void __bth_set_tver(void *arg, u8 tver)
{
	struct dtld_bth *bth = arg;

	bth->flags = (BTH_TVER_MASK & tver) |
			(~BTH_TVER_MASK & bth->flags);
}

static inline u16 __bth_pkey(void *arg)
{
	struct dtld_bth *bth = arg;

	return be16_to_cpu(bth->pkey);
}

static inline void __bth_set_pkey(void *arg, u16 pkey)
{
	struct dtld_bth *bth = arg;

	bth->pkey = cpu_to_be16(pkey);
}

static inline u32 __bth_qpn(void *arg)
{
	struct dtld_bth *bth = arg;

	return BTH_QPN_MASK & be32_to_cpu(bth->qpn);
}

static inline void __bth_set_qpn(void *arg, u32 qpn)
{
	struct dtld_bth *bth = arg;
	u32 resvqpn = be32_to_cpu(bth->qpn);

	bth->qpn = cpu_to_be32((BTH_QPN_MASK & qpn) |
			       (~BTH_QPN_MASK & resvqpn));
}

static inline int __bth_fecn(void *arg)
{
	struct dtld_bth *bth = arg;

	return 0 != (cpu_to_be32(BTH_FECN_MASK) & bth->qpn);
}

static inline void __bth_set_fecn(void *arg, int fecn)
{
	struct dtld_bth *bth = arg;

	if (fecn)
		bth->qpn |= cpu_to_be32(BTH_FECN_MASK);
	else
		bth->qpn &= ~cpu_to_be32(BTH_FECN_MASK);
}

static inline int __bth_becn(void *arg)
{
	struct dtld_bth *bth = arg;

	return 0 != (cpu_to_be32(BTH_BECN_MASK) & bth->qpn);
}

static inline void __bth_set_becn(void *arg, int becn)
{
	struct dtld_bth *bth = arg;

	if (becn)
		bth->qpn |= cpu_to_be32(BTH_BECN_MASK);
	else
		bth->qpn &= ~cpu_to_be32(BTH_BECN_MASK);
}

static inline u8 __bth_resv6a(void *arg)
{
	struct dtld_bth *bth = arg;

	return (BTH_RESV6A_MASK & be32_to_cpu(bth->qpn)) >> 24;
}

static inline void __bth_set_resv6a(void *arg)
{
	struct dtld_bth *bth = arg;

	bth->qpn = cpu_to_be32(~BTH_RESV6A_MASK);
}

static inline int __bth_ack(void *arg)
{
	struct dtld_bth *bth = arg;

	return 0 != (cpu_to_be32(BTH_ACK_MASK) & bth->apsn);
}

static inline void __bth_set_ack(void *arg, int ack)
{
	struct dtld_bth *bth = arg;

	if (ack)
		bth->apsn |= cpu_to_be32(BTH_ACK_MASK);
	else
		bth->apsn &= ~cpu_to_be32(BTH_ACK_MASK);
}

static inline void __bth_set_resv7(void *arg)
{
	struct dtld_bth *bth = arg;

	bth->apsn &= ~cpu_to_be32(BTH_RESV7_MASK);
}

static inline u32 __bth_psn(void *arg)
{
	struct dtld_bth *bth = arg;

	return BTH_PSN_MASK & be32_to_cpu(bth->apsn);
}

static inline void __bth_set_psn(void *arg, u32 psn)
{
	struct dtld_bth *bth = arg;
	u32 apsn = be32_to_cpu(bth->apsn);

	bth->apsn = cpu_to_be32((BTH_PSN_MASK & psn) |
			(~BTH_PSN_MASK & apsn));
}

static inline u8 bth_opcode(struct dtld_pkt_info *pkt)
{
	return __bth_opcode(pkt->hdr);
}

static inline void bth_set_opcode(struct dtld_pkt_info *pkt, u8 opcode)
{
	__bth_set_opcode(pkt->hdr, opcode);
}

static inline u8 bth_se(struct dtld_pkt_info *pkt)
{
	return __bth_se(pkt->hdr);
}

static inline void bth_set_se(struct dtld_pkt_info *pkt, int se)
{
	__bth_set_se(pkt->hdr, se);
}

static inline u8 bth_mig(struct dtld_pkt_info *pkt)
{
	return __bth_mig(pkt->hdr);
}

static inline void bth_set_mig(struct dtld_pkt_info *pkt, u8 mig)
{
	__bth_set_mig(pkt->hdr, mig);
}

static inline u8 bth_pad(struct dtld_pkt_info *pkt)
{
	return __bth_pad(pkt->hdr);
}

static inline void bth_set_pad(struct dtld_pkt_info *pkt, u8 pad)
{
	__bth_set_pad(pkt->hdr, pad);
}

static inline u8 bth_tver(struct dtld_pkt_info *pkt)
{
	return __bth_tver(pkt->hdr);
}

static inline void bth_set_tver(struct dtld_pkt_info *pkt, u8 tver)
{
	__bth_set_tver(pkt->hdr, tver);
}

static inline u16 bth_pkey(struct dtld_pkt_info *pkt)
{
	return __bth_pkey(pkt->hdr);
}

static inline void bth_set_pkey(struct dtld_pkt_info *pkt, u16 pkey)
{
	__bth_set_pkey(pkt->hdr, pkey);
}

static inline u32 bth_qpn(struct dtld_pkt_info *pkt)
{
	return __bth_qpn(pkt->hdr);
}

static inline void bth_set_qpn(struct dtld_pkt_info *pkt, u32 qpn)
{
	__bth_set_qpn(pkt->hdr, qpn);
}

static inline int bth_fecn(struct dtld_pkt_info *pkt)
{
	return __bth_fecn(pkt->hdr);
}

static inline void bth_set_fecn(struct dtld_pkt_info *pkt, int fecn)
{
	__bth_set_fecn(pkt->hdr, fecn);
}

static inline int bth_becn(struct dtld_pkt_info *pkt)
{
	return __bth_becn(pkt->hdr);
}

static inline void bth_set_becn(struct dtld_pkt_info *pkt, int becn)
{
	__bth_set_becn(pkt->hdr, becn);
}

static inline u8 bth_resv6a(struct dtld_pkt_info *pkt)
{
	return __bth_resv6a(pkt->hdr);
}

static inline void bth_set_resv6a(struct dtld_pkt_info *pkt)
{
	__bth_set_resv6a(pkt->hdr);
}

static inline int bth_ack(struct dtld_pkt_info *pkt)
{
	return __bth_ack(pkt->hdr);
}

static inline void bth_set_ack(struct dtld_pkt_info *pkt, int ack)
{
	__bth_set_ack(pkt->hdr, ack);
}

static inline void bth_set_resv7(struct dtld_pkt_info *pkt)
{
	__bth_set_resv7(pkt->hdr);
}

static inline u32 bth_psn(struct dtld_pkt_info *pkt)
{
	return __bth_psn(pkt->hdr);
}

static inline void bth_set_psn(struct dtld_pkt_info *pkt, u32 psn)
{
	__bth_set_psn(pkt->hdr, psn);
}

static inline void bth_init(struct dtld_pkt_info *pkt, u8 opcode, int se,
			    int mig, int pad, u16 pkey, u32 qpn, int ack_req,
			    u32 psn)
{
	struct dtld_bth *bth = (struct dtld_bth *)(pkt->hdr);

	bth->opcode = opcode;
	bth->flags = (pad << 4) & BTH_PAD_MASK;
	if (se)
		bth->flags |= BTH_SE_MASK;
	if (mig)
		bth->flags |= BTH_MIG_MASK;
	bth->pkey = cpu_to_be16(pkey);
	bth->qpn = cpu_to_be32(qpn & BTH_QPN_MASK);
	psn &= BTH_PSN_MASK;
	if (ack_req)
		psn |= BTH_ACK_MASK;
	bth->apsn = cpu_to_be32(psn);
}

/******************************************************************************
 * Reliable Datagram Extended Transport Header
 ******************************************************************************/
struct dtld_rdeth {
	__be32			een;
};

#define RDETH_EEN_MASK		(0x00ffffff)

static inline u8 __rdeth_een(void *arg)
{
	struct dtld_rdeth *rdeth = arg;

	return RDETH_EEN_MASK & be32_to_cpu(rdeth->een);
}

static inline void __rdeth_set_een(void *arg, u32 een)
{
	struct dtld_rdeth *rdeth = arg;

	rdeth->een = cpu_to_be32(RDETH_EEN_MASK & een);
}

static inline u8 rdeth_een(struct dtld_pkt_info *pkt)
{
	return __rdeth_een(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_RDETH]);
}

static inline void rdeth_set_een(struct dtld_pkt_info *pkt, u32 een)
{
	__rdeth_set_een(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_RDETH], een);
}

/******************************************************************************
 * Datagram Extended Transport Header
 ******************************************************************************/
struct dtld_deth {
	__be32			qkey;
	__be32			sqp;
};

#define GSI_QKEY		(0x80010000)
#define DETH_SQP_MASK		(0x00ffffff)

static inline u32 __deth_qkey(void *arg)
{
	struct dtld_deth *deth = arg;

	return be32_to_cpu(deth->qkey);
}

static inline void __deth_set_qkey(void *arg, u32 qkey)
{
	struct dtld_deth *deth = arg;

	deth->qkey = cpu_to_be32(qkey);
}

static inline u32 __deth_sqp(void *arg)
{
	struct dtld_deth *deth = arg;

	return DETH_SQP_MASK & be32_to_cpu(deth->sqp);
}

static inline void __deth_set_sqp(void *arg, u32 sqp)
{
	struct dtld_deth *deth = arg;

	deth->sqp = cpu_to_be32(DETH_SQP_MASK & sqp);
}

static inline u32 deth_qkey(struct dtld_pkt_info *pkt)
{
	return __deth_qkey(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_DETH]);
}

static inline void deth_set_qkey(struct dtld_pkt_info *pkt, u32 qkey)
{
	__deth_set_qkey(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_DETH], qkey);
}

static inline u32 deth_sqp(struct dtld_pkt_info *pkt)
{
	return __deth_sqp(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_DETH]);
}

static inline void deth_set_sqp(struct dtld_pkt_info *pkt, u32 sqp)
{
	__deth_set_sqp(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_DETH], sqp);
}

/******************************************************************************
 * RDMA Extended Transport Header
 ******************************************************************************/
struct dtld_reth {
	__be64			va;
	__be32			rkey;
	__be32			len;
};

static inline u64 __reth_va(void *arg)
{
	struct dtld_reth *reth = arg;

	return be64_to_cpu(reth->va);
}

static inline void __reth_set_va(void *arg, u64 va)
{
	struct dtld_reth *reth = arg;

	reth->va = cpu_to_be64(va);
}

static inline u32 __reth_rkey(void *arg)
{
	struct dtld_reth *reth = arg;

	return be32_to_cpu(reth->rkey);
}

static inline void __reth_set_rkey(void *arg, u32 rkey)
{
	struct dtld_reth *reth = arg;

	reth->rkey = cpu_to_be32(rkey);
}

static inline u32 __reth_len(void *arg)
{
	struct dtld_reth *reth = arg;

	return be32_to_cpu(reth->len);
}

static inline void __reth_set_len(void *arg, u32 len)
{
	struct dtld_reth *reth = arg;

	reth->len = cpu_to_be32(len);
}

static inline u64 reth_va(struct dtld_pkt_info *pkt)
{
	return __reth_va(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_RETH]);
}

static inline void reth_set_va(struct dtld_pkt_info *pkt, u64 va)
{
	__reth_set_va(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_RETH], va);
}

static inline u32 reth_rkey(struct dtld_pkt_info *pkt)
{
	return __reth_rkey(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_RETH]);
}

static inline void reth_set_rkey(struct dtld_pkt_info *pkt, u32 rkey)
{
	__reth_set_rkey(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_RETH], rkey);
}

static inline u32 reth_len(struct dtld_pkt_info *pkt)
{
	return __reth_len(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_RETH]);
}

static inline void reth_set_len(struct dtld_pkt_info *pkt, u32 len)
{
	__reth_set_len(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_RETH], len);
}

/******************************************************************************
 * Atomic Extended Transport Header
 ******************************************************************************/
struct dtld_atmeth {
	__be64			va;
	__be32			rkey;
	__be64			swap_add;
	__be64			comp;
} __packed;

static inline u64 __atmeth_va(void *arg)
{
	struct dtld_atmeth *atmeth = arg;

	return be64_to_cpu(atmeth->va);
}

static inline void __atmeth_set_va(void *arg, u64 va)
{
	struct dtld_atmeth *atmeth = arg;

	atmeth->va = cpu_to_be64(va);
}

static inline u32 __atmeth_rkey(void *arg)
{
	struct dtld_atmeth *atmeth = arg;

	return be32_to_cpu(atmeth->rkey);
}

static inline void __atmeth_set_rkey(void *arg, u32 rkey)
{
	struct dtld_atmeth *atmeth = arg;

	atmeth->rkey = cpu_to_be32(rkey);
}

static inline u64 __atmeth_swap_add(void *arg)
{
	struct dtld_atmeth *atmeth = arg;

	return be64_to_cpu(atmeth->swap_add);
}

static inline void __atmeth_set_swap_add(void *arg, u64 swap_add)
{
	struct dtld_atmeth *atmeth = arg;

	atmeth->swap_add = cpu_to_be64(swap_add);
}

static inline u64 __atmeth_comp(void *arg)
{
	struct dtld_atmeth *atmeth = arg;

	return be64_to_cpu(atmeth->comp);
}

static inline void __atmeth_set_comp(void *arg, u64 comp)
{
	struct dtld_atmeth *atmeth = arg;

	atmeth->comp = cpu_to_be64(comp);
}

static inline u64 atmeth_va(struct dtld_pkt_info *pkt)
{
	return __atmeth_va(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMETH]);
}

static inline void atmeth_set_va(struct dtld_pkt_info *pkt, u64 va)
{
	__atmeth_set_va(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMETH], va);
}

static inline u32 atmeth_rkey(struct dtld_pkt_info *pkt)
{
	return __atmeth_rkey(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMETH]);
}

static inline void atmeth_set_rkey(struct dtld_pkt_info *pkt, u32 rkey)
{
	__atmeth_set_rkey(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMETH], rkey);
}

static inline u64 atmeth_swap_add(struct dtld_pkt_info *pkt)
{
	return __atmeth_swap_add(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMETH]);
}

static inline void atmeth_set_swap_add(struct dtld_pkt_info *pkt, u64 swap_add)
{
	__atmeth_set_swap_add(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMETH], swap_add);
}

static inline u64 atmeth_comp(struct dtld_pkt_info *pkt)
{
	return __atmeth_comp(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMETH]);
}

static inline void atmeth_set_comp(struct dtld_pkt_info *pkt, u64 comp)
{
	__atmeth_set_comp(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMETH], comp);
}

/******************************************************************************
 * Ack Extended Transport Header
 ******************************************************************************/
struct dtld_aeth {
	__be32			smsn;
};

#define AETH_SYN_MASK		(0xff000000)
#define AETH_MSN_MASK		(0x00ffffff)

enum aeth_syndrome {
	AETH_TYPE_MASK		= 0xe0,
	AETH_ACK		= 0x00,
	AETH_RNR_NAK		= 0x20,
	AETH_RSVD		= 0x40,
	AETH_NAK		= 0x60,
	AETH_ACK_UNLIMITED	= 0x1f,
	AETH_NAK_PSN_SEQ_ERROR	= 0x60,
	AETH_NAK_INVALID_REQ	= 0x61,
	AETH_NAK_REM_ACC_ERR	= 0x62,
	AETH_NAK_REM_OP_ERR	= 0x63,
	AETH_NAK_INV_RD_REQ	= 0x64,
};

static inline u8 __aeth_syn(void *arg)
{
	struct dtld_aeth *aeth = arg;

	return (AETH_SYN_MASK & be32_to_cpu(aeth->smsn)) >> 24;
}

static inline void __aeth_set_syn(void *arg, u8 syn)
{
	struct dtld_aeth *aeth = arg;
	u32 smsn = be32_to_cpu(aeth->smsn);

	aeth->smsn = cpu_to_be32((AETH_SYN_MASK & (syn << 24)) |
			 (~AETH_SYN_MASK & smsn));
}

static inline u32 __aeth_msn(void *arg)
{
	struct dtld_aeth *aeth = arg;

	return AETH_MSN_MASK & be32_to_cpu(aeth->smsn);
}

static inline void __aeth_set_msn(void *arg, u32 msn)
{
	struct dtld_aeth *aeth = arg;
	u32 smsn = be32_to_cpu(aeth->smsn);

	aeth->smsn = cpu_to_be32((AETH_MSN_MASK & msn) |
			 (~AETH_MSN_MASK & smsn));
}

static inline u8 aeth_syn(struct dtld_pkt_info *pkt)
{
	return __aeth_syn(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_AETH]);
}

static inline void aeth_set_syn(struct dtld_pkt_info *pkt, u8 syn)
{
	__aeth_set_syn(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_AETH], syn);
}

static inline u32 aeth_msn(struct dtld_pkt_info *pkt)
{
	return __aeth_msn(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_AETH]);
}

static inline void aeth_set_msn(struct dtld_pkt_info *pkt, u32 msn)
{
	__aeth_set_msn(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_AETH], msn);
}

/******************************************************************************
 * Atomic Ack Extended Transport Header
 ******************************************************************************/
struct dtld_atmack {
	__be64			orig;
};

static inline u64 __atmack_orig(void *arg)
{
	struct dtld_atmack *atmack = arg;

	return be64_to_cpu(atmack->orig);
}

static inline void __atmack_set_orig(void *arg, u64 orig)
{
	struct dtld_atmack *atmack = arg;

	atmack->orig = cpu_to_be64(orig);
}

static inline u64 atmack_orig(struct dtld_pkt_info *pkt)
{
	return __atmack_orig(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMACK]);
}

static inline void atmack_set_orig(struct dtld_pkt_info *pkt, u64 orig)
{
	__atmack_set_orig(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_ATMACK], orig);
}

/******************************************************************************
 * Immediate Extended Transport Header
 ******************************************************************************/
struct dtld_immdt {
	__be32			imm;
};

static inline __be32 __immdt_imm(void *arg)
{
	struct dtld_immdt *immdt = arg;

	return immdt->imm;
}

static inline void __immdt_set_imm(void *arg, __be32 imm)
{
	struct dtld_immdt *immdt = arg;

	immdt->imm = imm;
}

static inline __be32 immdt_imm(struct dtld_pkt_info *pkt)
{
	return __immdt_imm(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_IMMDT]);
}

static inline void immdt_set_imm(struct dtld_pkt_info *pkt, __be32 imm)
{
	__immdt_set_imm(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_IMMDT], imm);
}

/******************************************************************************
 * Invalidate Extended Transport Header
 ******************************************************************************/
struct dtld_ieth {
	__be32			rkey;
};

static inline u32 __ieth_rkey(void *arg)
{
	struct dtld_ieth *ieth = arg;

	return be32_to_cpu(ieth->rkey);
}

static inline void __ieth_set_rkey(void *arg, u32 rkey)
{
	struct dtld_ieth *ieth = arg;

	ieth->rkey = cpu_to_be32(rkey);
}

static inline u32 ieth_rkey(struct dtld_pkt_info *pkt)
{
	return __ieth_rkey(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_IETH]);
}

static inline void ieth_set_rkey(struct dtld_pkt_info *pkt, u32 rkey)
{
	__ieth_set_rkey(pkt->hdr +
		dtld_opcode[pkt->opcode].offset[DTLD_IETH], rkey);
}

enum dtld_hdr_length {
	DTLD_BTH_BYTES		= sizeof(struct dtld_bth),
	DTLD_DETH_BYTES		= sizeof(struct dtld_deth),
	DTLD_IMMDT_BYTES		= sizeof(struct dtld_immdt),
	DTLD_RETH_BYTES		= sizeof(struct dtld_reth),
	DTLD_AETH_BYTES		= sizeof(struct dtld_aeth),
	DTLD_ATMACK_BYTES	= sizeof(struct dtld_atmack),
	DTLD_ATMETH_BYTES	= sizeof(struct dtld_atmeth),
	DTLD_IETH_BYTES		= sizeof(struct dtld_ieth),
	DTLD_RDETH_BYTES		= sizeof(struct dtld_rdeth),
};

static inline size_t header_size(struct dtld_pkt_info *pkt)
{
	return dtld_opcode[pkt->opcode].length;
}

static inline void *payload_addr(struct dtld_pkt_info *pkt)
{
	return pkt->hdr + dtld_opcode[pkt->opcode].offset[DTLD_PAYLOAD];
}

static inline size_t payload_size(struct dtld_pkt_info *pkt)
{
	return pkt->paylen - dtld_opcode[pkt->opcode].offset[DTLD_PAYLOAD]
		- bth_pad(pkt) - DTLD_ICRC_SIZE;
}

#endif /* DTLD_HDR_H */
