/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef DTLD_OPCODE_H
#define DTLD_OPCODE_H

/*
 * contains header bit mask definitions and header lengths
 * declaration of the dtld_opcode_info struct and
 * dtld_wr_opcode_info struct
 */

enum dtld_wr_mask {
	WR_INLINE_MASK			= BIT(0),
	WR_ATOMIC_MASK			= BIT(1),
	WR_SEND_MASK			= BIT(2),
	WR_READ_MASK			= BIT(3),
	WR_WRITE_MASK			= BIT(4),
	WR_LOCAL_OP_MASK		= BIT(5),

	WR_READ_OR_WRITE_MASK		= WR_READ_MASK | WR_WRITE_MASK,
	WR_WRITE_OR_SEND_MASK		= WR_WRITE_MASK | WR_SEND_MASK,
	WR_ATOMIC_OR_READ_MASK		= WR_ATOMIC_MASK | WR_READ_MASK,
};

#define WR_MAX_QPT		(8)

struct dtld_wr_opcode_info {
	char			*name;
	enum dtld_wr_mask	mask[WR_MAX_QPT];
};

extern struct dtld_wr_opcode_info dtld_wr_opcode_info[];

enum dtld_hdr_type {
	DTLD_LRH,
	DTLD_GRH,
	DTLD_BTH,
	DTLD_RETH,
	DTLD_AETH,
	DTLD_ATMETH,
	DTLD_ATMACK,
	DTLD_IETH,
	DTLD_RDETH,
	DTLD_DETH,
	DTLD_IMMDT,
	DTLD_PAYLOAD,
	NUM_HDR_TYPES
};

enum dtld_hdr_mask {
	DTLD_LRH_MASK		= BIT(DTLD_LRH),
	DTLD_GRH_MASK		= BIT(DTLD_GRH),
	DTLD_BTH_MASK		= BIT(DTLD_BTH),
	DTLD_IMMDT_MASK		= BIT(DTLD_IMMDT),
	DTLD_RETH_MASK		= BIT(DTLD_RETH),
	DTLD_AETH_MASK		= BIT(DTLD_AETH),
	DTLD_ATMETH_MASK		= BIT(DTLD_ATMETH),
	DTLD_ATMACK_MASK		= BIT(DTLD_ATMACK),
	DTLD_IETH_MASK		= BIT(DTLD_IETH),
	DTLD_RDETH_MASK		= BIT(DTLD_RDETH),
	DTLD_DETH_MASK		= BIT(DTLD_DETH),
	DTLD_PAYLOAD_MASK	= BIT(DTLD_PAYLOAD),

	DTLD_REQ_MASK		= BIT(NUM_HDR_TYPES + 0),
	DTLD_ACK_MASK		= BIT(NUM_HDR_TYPES + 1),
	DTLD_SEND_MASK		= BIT(NUM_HDR_TYPES + 2),
	DTLD_WRITE_MASK		= BIT(NUM_HDR_TYPES + 3),
	DTLD_READ_MASK		= BIT(NUM_HDR_TYPES + 4),
	DTLD_ATOMIC_MASK		= BIT(NUM_HDR_TYPES + 5),

	DTLD_RWR_MASK		= BIT(NUM_HDR_TYPES + 6),
	DTLD_COMP_MASK		= BIT(NUM_HDR_TYPES + 7),

	DTLD_START_MASK		= BIT(NUM_HDR_TYPES + 8),
	DTLD_MIDDLE_MASK		= BIT(NUM_HDR_TYPES + 9),
	DTLD_END_MASK		= BIT(NUM_HDR_TYPES + 10),

	DTLD_LOOPBACK_MASK	= BIT(NUM_HDR_TYPES + 12),

	DTLD_READ_OR_ATOMIC_MASK	= (DTLD_READ_MASK | DTLD_ATOMIC_MASK),
	DTLD_WRITE_OR_SEND_MASK	= (DTLD_WRITE_MASK | DTLD_SEND_MASK),
	DTLD_READ_OR_WRITE_MASK	= (DTLD_READ_MASK | DTLD_WRITE_MASK),
};

#define OPCODE_NONE		(-1)
#define DTLD_NUM_OPCODE		256

struct dtld_opcode_info {
	char			*name;
	enum dtld_hdr_mask	mask;
	int			length;
	int			offset[NUM_HDR_TYPES];
};

extern struct dtld_opcode_info dtld_opcode[DTLD_NUM_OPCODE];

#endif /* DTLD_OPCODE_H */
