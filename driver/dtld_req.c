// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

// #include <linux/skbuff.h>
#include <crypto/hash.h>

#include "dtld.h"
#include "dtld_loc.h"
#include "dtld_queue.h"

// static int next_opcode(struct dtld_qp *qp, struct dtld_send_wqe *wqe,
// 		       u32 opcode);

// static inline void retry_first_write_send(struct dtld_qp *qp,
// 					  struct dtld_send_wqe *wqe,
// 					  unsigned int mask, int npsn)
// {
// 	int i;

// 	for (i = 0; i < npsn; i++) {
// 		int to_send = (wqe->dma.resid > qp->mtu) ?
// 				qp->mtu : wqe->dma.resid;

// 		qp->req.opcode = next_opcode(qp, wqe,
// 					     wqe->wr.opcode);

// 		if (wqe->wr.send_flags & IB_SEND_INLINE) {
// 			wqe->dma.resid -= to_send;
// 			wqe->dma.sge_offset += to_send;
// 		} else {
// 			advance_dma_data(&wqe->dma, to_send);
// 		}
// 	}
// }

// static void req_retry(struct dtld_qp *qp)
// {
// 	struct dtld_send_wqe *wqe;
// 	unsigned int wqe_index;
// 	unsigned int mask;
// 	int npsn;
// 	int first = 1;
// 	struct dtld_queue *q = qp->sq.queue;
// 	unsigned int cons;
// 	unsigned int prod;

// 	cons = queue_get_consumer(q, QUEUE_TYPE_FROM_CLIENT);
// 	prod = queue_get_producer(q, QUEUE_TYPE_FROM_CLIENT);

// 	qp->req.wqe_index	= cons;
// 	qp->req.psn		= qp->comp.psn;
// 	qp->req.opcode		= -1;

// 	for (wqe_index = cons; wqe_index != prod;
// 			wqe_index = queue_next_index(q, wqe_index)) {
// 		wqe = queue_addr_from_index(qp->sq.queue, wqe_index);
// 		mask = wr_opcode_mask(wqe->wr.opcode, qp);

// 		if (wqe->state == wqe_state_posted)
// 			break;

// 		if (wqe->state == wqe_state_done)
// 			continue;

// 		wqe->iova = (mask & WR_ATOMIC_MASK) ?
// 			     wqe->wr.wr.atomic.remote_addr :
// 			     (mask & WR_READ_OR_WRITE_MASK) ?
// 			     wqe->wr.wr.rdma.remote_addr :
// 			     0;

// 		if (!first || (mask & WR_READ_MASK) == 0) {
// 			wqe->dma.resid = wqe->dma.length;
// 			wqe->dma.cur_sge = 0;
// 			wqe->dma.sge_offset = 0;
// 		}

// 		if (first) {
// 			first = 0;

// 			if (mask & WR_WRITE_OR_SEND_MASK) {
// 				npsn = (qp->comp.psn - wqe->first_psn) &
// 					BTH_PSN_MASK;
// 				retry_first_write_send(qp, wqe, mask, npsn);
// 			}

// 			if (mask & WR_READ_MASK) {
// 				npsn = (wqe->dma.length - wqe->dma.resid) /
// 					qp->mtu;
// 				wqe->iova += npsn * qp->mtu;
// 			}
// 		}

// 		wqe->state = wqe_state_posted;
// 	}
// }

void rnr_nak_timer(struct timer_list *t)
{
	struct dtld_qp *qp = from_timer(qp, t, rnr_nak_timer);

	pr_debug("qp#%d rnr nak timer fired\n", qp_num(qp));
	dtld_run_task(&qp->req.task, 1);
}

// static struct dtld_send_wqe *req_next_wqe(struct dtld_qp *qp)
// {
// 	struct dtld_send_wqe *wqe;
// 	struct dtld_queue *q = qp->sq.queue;
// 	unsigned int index = qp->req.wqe_index;
// 	unsigned int cons;
// 	unsigned int prod;

// 	wqe = queue_head(q, QUEUE_TYPE_FROM_CLIENT);
// 	cons = queue_get_consumer(q, QUEUE_TYPE_FROM_CLIENT);
// 	prod = queue_get_producer(q, QUEUE_TYPE_FROM_CLIENT);

// 	if (unlikely(qp->req.state == QP_STATE_DRAIN)) {
// 		/* check to see if we are drained;
// 		 * state_lock used by requester and completer
// 		 */
// 		spin_lock_bh(&qp->state_lock);
// 		do {
// 			if (qp->req.state != QP_STATE_DRAIN) {
// 				/* comp just finished */
// 				spin_unlock_bh(&qp->state_lock);
// 				break;
// 			}

// 			if (wqe && ((index != cons) ||
// 				(wqe->state != wqe_state_posted))) {
// 				/* comp not done yet */
// 				spin_unlock_bh(&qp->state_lock);
// 				break;
// 			}

// 			qp->req.state = QP_STATE_DRAINED;
// 			spin_unlock_bh(&qp->state_lock);

// 			if (qp->ibqp.event_handler) {
// 				struct ib_event ev;

// 				ev.device = qp->ibqp.device;
// 				ev.element.qp = &qp->ibqp;
// 				ev.event = IB_EVENT_SQ_DRAINED;
// 				qp->ibqp.event_handler(&ev,
// 					qp->ibqp.qp_context);
// 			}
// 		} while (0);
// 	}

// 	if (index == prod)
// 		return NULL;

// 	wqe = queue_addr_from_index(q, index);

// 	if (unlikely((qp->req.state == QP_STATE_DRAIN ||
// 		      qp->req.state == QP_STATE_DRAINED) &&
// 		     (wqe->state != wqe_state_processing)))
// 		return NULL;

// 	if (unlikely((wqe->wr.send_flags & IB_SEND_FENCE) &&
// 						     (index != cons))) {
// 		qp->req.wait_fence = 1;
// 		return NULL;
// 	}

// 	wqe->mask = wr_opcode_mask(wqe->wr.opcode, qp);
// 	return wqe;
// }

// static int next_opcode_rc(struct dtld_qp *qp, u32 opcode, int fits)
// {
// 	switch (opcode) {
// 	case IB_WR_RDMA_WRITE:
// 		if (qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
// 		    qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
// 			return fits ?
// 				IB_OPCODE_RC_RDMA_WRITE_LAST :
// 				IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
// 		else
// 			return fits ?
// 				IB_OPCODE_RC_RDMA_WRITE_ONLY :
// 				IB_OPCODE_RC_RDMA_WRITE_FIRST;

// 	case IB_WR_RDMA_WRITE_WITH_IMM:
// 		if (qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
// 		    qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
// 			return fits ?
// 				IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
// 				IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
// 		else
// 			return fits ?
// 				IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
// 				IB_OPCODE_RC_RDMA_WRITE_FIRST;

// 	case IB_WR_SEND:
// 		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
// 		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
// 			return fits ?
// 				IB_OPCODE_RC_SEND_LAST :
// 				IB_OPCODE_RC_SEND_MIDDLE;
// 		else
// 			return fits ?
// 				IB_OPCODE_RC_SEND_ONLY :
// 				IB_OPCODE_RC_SEND_FIRST;

// 	case IB_WR_SEND_WITH_IMM:
// 		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
// 		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
// 			return fits ?
// 				IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE :
// 				IB_OPCODE_RC_SEND_MIDDLE;
// 		else
// 			return fits ?
// 				IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE :
// 				IB_OPCODE_RC_SEND_FIRST;

// 	case IB_WR_RDMA_READ:
// 		return IB_OPCODE_RC_RDMA_READ_REQUEST;

// 	case IB_WR_ATOMIC_CMP_AND_SWP:
// 		return IB_OPCODE_RC_COMPARE_SWAP;

// 	case IB_WR_ATOMIC_FETCH_AND_ADD:
// 		return IB_OPCODE_RC_FETCH_ADD;

// 	case IB_WR_SEND_WITH_INV:
// 		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
// 		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
// 			return fits ? IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE :
// 				IB_OPCODE_RC_SEND_MIDDLE;
// 		else
// 			return fits ? IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE :
// 				IB_OPCODE_RC_SEND_FIRST;
// 	case IB_WR_REG_MR:
// 	case IB_WR_LOCAL_INV:
// 		return opcode;
// 	}

// 	return -EINVAL;
// }

// static int next_opcode_uc(struct dtld_qp *qp, u32 opcode, int fits)
// {
// 	switch (opcode) {
// 	case IB_WR_RDMA_WRITE:
// 		if (qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_FIRST ||
// 		    qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_MIDDLE)
// 			return fits ?
// 				IB_OPCODE_UC_RDMA_WRITE_LAST :
// 				IB_OPCODE_UC_RDMA_WRITE_MIDDLE;
// 		else
// 			return fits ?
// 				IB_OPCODE_UC_RDMA_WRITE_ONLY :
// 				IB_OPCODE_UC_RDMA_WRITE_FIRST;

// 	case IB_WR_RDMA_WRITE_WITH_IMM:
// 		if (qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_FIRST ||
// 		    qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_MIDDLE)
// 			return fits ?
// 				IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
// 				IB_OPCODE_UC_RDMA_WRITE_MIDDLE;
// 		else
// 			return fits ?
// 				IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
// 				IB_OPCODE_UC_RDMA_WRITE_FIRST;

// 	case IB_WR_SEND:
// 		if (qp->req.opcode == IB_OPCODE_UC_SEND_FIRST ||
// 		    qp->req.opcode == IB_OPCODE_UC_SEND_MIDDLE)
// 			return fits ?
// 				IB_OPCODE_UC_SEND_LAST :
// 				IB_OPCODE_UC_SEND_MIDDLE;
// 		else
// 			return fits ?
// 				IB_OPCODE_UC_SEND_ONLY :
// 				IB_OPCODE_UC_SEND_FIRST;

// 	case IB_WR_SEND_WITH_IMM:
// 		if (qp->req.opcode == IB_OPCODE_UC_SEND_FIRST ||
// 		    qp->req.opcode == IB_OPCODE_UC_SEND_MIDDLE)
// 			return fits ?
// 				IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE :
// 				IB_OPCODE_UC_SEND_MIDDLE;
// 		else
// 			return fits ?
// 				IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE :
// 				IB_OPCODE_UC_SEND_FIRST;
// 	}

// 	return -EINVAL;
// }

// static int next_opcode(struct dtld_qp *qp, struct dtld_send_wqe *wqe,
// 		       u32 opcode)
// {
// 	int fits = (wqe->dma.resid <= qp->mtu);

// 	switch (qp_type(qp)) {
// 	case IB_QPT_RC:
// 		return next_opcode_rc(qp, opcode, fits);

// 	case IB_QPT_UC:
// 		return next_opcode_uc(qp, opcode, fits);

// 	case IB_QPT_UD:
// 	case IB_QPT_GSI:
// 		switch (opcode) {
// 		case IB_WR_SEND:
// 			return IB_OPCODE_UD_SEND_ONLY;

// 		case IB_WR_SEND_WITH_IMM:
// 			return IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
// 		}
// 		break;

// 	default:
// 		break;
// 	}

// 	return -EINVAL;
// }

// static inline int check_init_depth(struct dtld_qp *qp, struct dtld_send_wqe *wqe)
// {
// 	int depth;

// 	if (wqe->has_rd_atomic)
// 		return 0;

// 	qp->req.need_rd_atomic = 1;
// 	depth = atomic_dec_return(&qp->req.rd_atomic);

// 	if (depth >= 0) {
// 		qp->req.need_rd_atomic = 0;
// 		wqe->has_rd_atomic = 1;
// 		return 0;
// 	}

// 	atomic_inc(&qp->req.rd_atomic);
// 	return -EAGAIN;
// }

// static inline int get_mtu(struct dtld_qp *qp)
// {
// 	struct dtld_dev *dtld = to_rdev(qp->ibqp.device);

// 	if ((qp_type(qp) == IB_QPT_RC) || (qp_type(qp) == IB_QPT_UC))
// 		return qp->mtu;

// 	return dtld->port.mtu_cap;
// }

// static struct sk_buff *init_req_packet(struct dtld_qp *qp,
// 				       struct dtld_av *av,
// 				       struct dtld_send_wqe *wqe,
// 				       int opcode, u32 payload,
// 				       struct dtld_pkt_info *pkt)
// {
// 	struct dtld_dev		*dtld = to_rdev(qp->ibqp.device);
// 	struct sk_buff		*skb;
// 	struct dtld_send_wr	*ibwr = &wqe->wr;
// 	int			pad = (-payload) & 0x3;
// 	int			paylen;
// 	int			solicited;
// 	u32			qp_num;
// 	int			ack_req;

// 	/* length from start of bth to end of icrc */
// 	paylen = dtld_opcode[opcode].length + payload + pad + DTLD_ICRC_SIZE;
// 	pkt->paylen = paylen;

// 	/* init skb */
// 	skb = dtld_init_packet(dtld, av, paylen, pkt);
// 	if (unlikely(!skb))
// 		return NULL;

// 	/* init bth */
// 	solicited = (ibwr->send_flags & IB_SEND_SOLICITED) &&
// 			(pkt->mask & DTLD_END_MASK) &&
// 			((pkt->mask & (DTLD_SEND_MASK)) ||
// 			(pkt->mask & (DTLD_WRITE_MASK | DTLD_IMMDT_MASK)) ==
// 			(DTLD_WRITE_MASK | DTLD_IMMDT_MASK));

// 	qp_num = (pkt->mask & DTLD_DETH_MASK) ? ibwr->wr.ud.remote_qpn :
// 					 qp->attr.dest_qp_num;

// 	ack_req = ((pkt->mask & DTLD_END_MASK) ||
// 		(qp->req.noack_pkts++ > DTLD_MAX_PKT_PER_ACK));
// 	if (ack_req)
// 		qp->req.noack_pkts = 0;

// 	bth_init(pkt, pkt->opcode, solicited, 0, pad, IB_DEFAULT_PKEY_FULL, qp_num,
// 		 ack_req, pkt->psn);

// 	/* init optional headers */
// 	if (pkt->mask & DTLD_RETH_MASK) {
// 		reth_set_rkey(pkt, ibwr->wr.rdma.rkey);
// 		reth_set_va(pkt, wqe->iova);
// 		reth_set_len(pkt, wqe->dma.resid);
// 	}

// 	if (pkt->mask & DTLD_IMMDT_MASK)
// 		immdt_set_imm(pkt, ibwr->ex.imm_data);

// 	if (pkt->mask & DTLD_IETH_MASK)
// 		ieth_set_rkey(pkt, ibwr->ex.invalidate_rkey);

// 	if (pkt->mask & DTLD_ATMETH_MASK) {
// 		atmeth_set_va(pkt, wqe->iova);
// 		if (opcode == IB_OPCODE_RC_COMPARE_SWAP) {
// 			atmeth_set_swap_add(pkt, ibwr->wr.atomic.swap);
// 			atmeth_set_comp(pkt, ibwr->wr.atomic.compare_add);
// 		} else {
// 			atmeth_set_swap_add(pkt, ibwr->wr.atomic.compare_add);
// 		}
// 		atmeth_set_rkey(pkt, ibwr->wr.atomic.rkey);
// 	}

// 	if (pkt->mask & DTLD_DETH_MASK) {
// 		if (qp->ibqp.qp_num == 1)
// 			deth_set_qkey(pkt, GSI_QKEY);
// 		else
// 			deth_set_qkey(pkt, ibwr->wr.ud.remote_qkey);
// 		deth_set_sqp(pkt, qp->ibqp.qp_num);
// 	}

// 	return skb;
// }

// static int finish_packet(struct dtld_qp *qp, struct dtld_av *av,
// 			 struct dtld_send_wqe *wqe, struct dtld_pkt_info *pkt,
// 			 struct sk_buff *skb, u32 payload)
// {
// 	int err;

// 	err = dtld_prepare(av, pkt, skb);
// 	if (err)
// 		return err;

// 	if (pkt->mask & DTLD_WRITE_OR_SEND_MASK) {
// 		if (wqe->wr.send_flags & IB_SEND_INLINE) {
// 			u8 *tmp = &wqe->dma.inline_data[wqe->dma.sge_offset];

// 			memcpy(payload_addr(pkt), tmp, payload);

// 			wqe->dma.resid -= payload;
// 			wqe->dma.sge_offset += payload;
// 		} else {
// 			err = copy_data(qp->pd, 0, &wqe->dma,
// 					payload_addr(pkt), payload,
// 					DTLD_FROM_MR_OBJ);
// 			if (err)
// 				return err;
// 		}
// 		if (bth_pad(pkt)) {
// 			u8 *pad = payload_addr(pkt) + payload;

// 			memset(pad, 0, bth_pad(pkt));
// 		}
// 	}

// 	return 0;
// }

// static void update_wqe_state(struct dtld_qp *qp,
// 		struct dtld_send_wqe *wqe,
// 		struct dtld_pkt_info *pkt)
// {
// 	if (pkt->mask & DTLD_END_MASK) {
// 		if (qp_type(qp) == IB_QPT_RC)
// 			wqe->state = wqe_state_pending;
// 	} else {
// 		wqe->state = wqe_state_processing;
// 	}
// }

// static void update_wqe_psn(struct dtld_qp *qp,
// 			   struct dtld_send_wqe *wqe,
// 			   struct dtld_pkt_info *pkt,
// 			   u32 payload)
// {
// 	/* number of packets left to send including current one */
// 	int num_pkt = (wqe->dma.resid + payload + qp->mtu - 1) / qp->mtu;

// 	/* handle zero length packet case */
// 	if (num_pkt == 0)
// 		num_pkt = 1;

// 	if (pkt->mask & DTLD_START_MASK) {
// 		wqe->first_psn = qp->req.psn;
// 		wqe->last_psn = (qp->req.psn + num_pkt - 1) & BTH_PSN_MASK;
// 	}

// 	if (pkt->mask & DTLD_READ_MASK)
// 		qp->req.psn = (wqe->first_psn + num_pkt) & BTH_PSN_MASK;
// 	else
// 		qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
// }

// static void save_state(struct dtld_send_wqe *wqe,
// 		       struct dtld_qp *qp,
// 		       struct dtld_send_wqe *rollback_wqe,
// 		       u32 *rollback_psn)
// {
// 	rollback_wqe->state     = wqe->state;
// 	rollback_wqe->first_psn = wqe->first_psn;
// 	rollback_wqe->last_psn  = wqe->last_psn;
// 	*rollback_psn		= qp->req.psn;
// }

// static void rollback_state(struct dtld_send_wqe *wqe,
// 			   struct dtld_qp *qp,
// 			   struct dtld_send_wqe *rollback_wqe,
// 			   u32 rollback_psn)
// {
// 	wqe->state     = rollback_wqe->state;
// 	wqe->first_psn = rollback_wqe->first_psn;
// 	wqe->last_psn  = rollback_wqe->last_psn;
// 	qp->req.psn    = rollback_psn;
// }

// static void update_state(struct dtld_qp *qp, struct dtld_pkt_info *pkt)
// {
// 	qp->req.opcode = pkt->opcode;

// 	if (pkt->mask & DTLD_END_MASK)
// 		qp->req.wqe_index = queue_next_index(qp->sq.queue,
// 						     qp->req.wqe_index);

// 	qp->need_req_skb = 0;

// 	if (qp->qp_timeout_jiffies && !timer_pending(&qp->retrans_timer))
// 		mod_timer(&qp->retrans_timer,
// 			  jiffies + qp->qp_timeout_jiffies);
// }

// static int dtld_do_local_ops(struct dtld_qp *qp, struct dtld_send_wqe *wqe)
// {
// 	u8 opcode = wqe->wr.opcode;
// 	u32 rkey;
// 	int ret;

// 	switch (opcode) {
// 	case IB_WR_LOCAL_INV:
// 		rkey = wqe->wr.ex.invalidate_rkey;
// 		if (rkey_is_mw(rkey))
// 			ret = dtld_invalidate_mw(qp, rkey);
// 		else
// 			ret = dtld_invalidate_mr(qp, rkey);

// 		if (unlikely(ret)) {
// 			wqe->status = IB_WC_LOC_QP_OP_ERR;
// 			return ret;
// 		}
// 		break;
// 	case IB_WR_REG_MR:
// 		ret = dtld_reg_fast_mr(qp, wqe);
// 		if (unlikely(ret)) {
// 			wqe->status = IB_WC_LOC_QP_OP_ERR;
// 			return ret;
// 		}
// 		break;
// 	case IB_WR_BIND_MW:
// 		ret = dtld_bind_mw(qp, wqe);
// 		if (unlikely(ret)) {
// 			wqe->status = IB_WC_MW_BIND_ERR;
// 			return ret;
// 		}
// 		break;
// 	default:
// 		pr_err("Unexpected send wqe opcode %d\n", opcode);
// 		wqe->status = IB_WC_LOC_QP_OP_ERR;
// 		return -EINVAL;
// 	}

// 	wqe->state = wqe_state_done;
// 	wqe->status = IB_WC_SUCCESS;
// 	qp->req.wqe_index = queue_next_index(qp->sq.queue, qp->req.wqe_index);

// 	if ((wqe->wr.send_flags & IB_SEND_SIGNALED) ||
// 	    qp->sq_sig_type == IB_SIGNAL_ALL_WR)
// 		dtld_run_task(&qp->comp.task, 1);

// 	return 0;
// }

int dtld_requester(void *arg)
{
    return 1;
// 	struct dtld_qp *qp = (struct dtld_qp *)arg;
// 	struct dtld_dev *dtld = to_rdev(qp->ibqp.device);
// 	struct dtld_pkt_info pkt;
// 	struct sk_buff *skb;
// 	struct dtld_send_wqe *wqe;
// 	enum dtld_hdr_mask mask;
// 	u32 payload;
// 	int mtu;
// 	int opcode;
// 	int ret;
// 	struct dtld_send_wqe rollback_wqe;
// 	u32 rollback_psn;
// 	struct dtld_queue *q = qp->sq.queue;
// 	struct dtld_ah *ah;
// 	struct dtld_av *av;

// 	if (!dtld_get(qp))
// 		return -EAGAIN;

// next_wqe:
// 	if (unlikely(!qp->valid || qp->req.state == QP_STATE_ERROR))
// 		goto exit;

// 	if (unlikely(qp->req.state == QP_STATE_RESET)) {
// 		qp->req.wqe_index = queue_get_consumer(q,
// 						QUEUE_TYPE_FROM_CLIENT);
// 		qp->req.opcode = -1;
// 		qp->req.need_rd_atomic = 0;
// 		qp->req.wait_psn = 0;
// 		qp->req.need_retry = 0;
// 		goto exit;
// 	}

// 	if (unlikely(qp->req.need_retry)) {
// 		req_retry(qp);
// 		qp->req.need_retry = 0;
// 	}

// 	wqe = req_next_wqe(qp);
// 	if (unlikely(!wqe))
// 		goto exit;

// 	if (wqe->mask & WR_LOCAL_OP_MASK) {
// 		ret = dtld_do_local_ops(qp, wqe);
// 		if (unlikely(ret))
// 			goto err;
// 		else
// 			goto next_wqe;
// 	}

// 	if (unlikely(qp_type(qp) == IB_QPT_RC &&
// 		psn_compare(qp->req.psn, (qp->comp.psn +
// 				DTLD_MAX_UNACKED_PSNS)) > 0)) {
// 		qp->req.wait_psn = 1;
// 		goto exit;
// 	}

// 	/* Limit the number of inflight SKBs per QP */
// 	if (unlikely(atomic_read(&qp->skb_out) >
// 		     DTLD_INFLIGHT_SKBS_PER_QP_HIGH)) {
// 		qp->need_req_skb = 1;
// 		goto exit;
// 	}

// 	opcode = next_opcode(qp, wqe, wqe->wr.opcode);
// 	if (unlikely(opcode < 0)) {
// 		wqe->status = IB_WC_LOC_QP_OP_ERR;
// 		goto err;
// 	}

// 	mask = dtld_opcode[opcode].mask;
// 	if (unlikely(mask & DTLD_READ_OR_ATOMIC_MASK)) {
// 		if (check_init_depth(qp, wqe))
// 			goto exit;
// 	}

// 	mtu = get_mtu(qp);
// 	payload = (mask & DTLD_WRITE_OR_SEND_MASK) ? wqe->dma.resid : 0;
// 	if (payload > mtu) {
// 		if (qp_type(qp) == IB_QPT_UD) {
// 			/* C10-93.1.1: If the total sum of all the buffer lengths specified for a
// 			 * UD message exceeds the MTU of the port as returned by QueryHCA, the CI
// 			 * shall not emit any packets for this message. Further, the CI shall not
// 			 * generate an error due to this condition.
// 			 */

// 			/* fake a successful UD send */
// 			wqe->first_psn = qp->req.psn;
// 			wqe->last_psn = qp->req.psn;
// 			qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
// 			qp->req.opcode = IB_OPCODE_UD_SEND_ONLY;
// 			qp->req.wqe_index = queue_next_index(qp->sq.queue,
// 						       qp->req.wqe_index);
// 			wqe->state = wqe_state_done;
// 			wqe->status = IB_WC_SUCCESS;
// 			__dtld_do_task(&qp->comp.task);
// 			dtld_put(qp);
// 			return 0;
// 		}
// 		payload = mtu;
// 	}

// 	pkt.dtld = dtld;
// 	pkt.opcode = opcode;
// 	pkt.qp = qp;
// 	pkt.psn = qp->req.psn;
// 	pkt.mask = dtld_opcode[opcode].mask;
// 	pkt.wqe = wqe;

// 	av = dtld_get_av(&pkt, &ah);
// 	if (unlikely(!av)) {
// 		pr_err("qp#%d Failed no address vector\n", qp_num(qp));
// 		wqe->status = IB_WC_LOC_QP_OP_ERR;
// 		goto err_drop_ah;
// 	}

// 	skb = init_req_packet(qp, av, wqe, opcode, payload, &pkt);
// 	if (unlikely(!skb)) {
// 		pr_err("qp#%d Failed allocating skb\n", qp_num(qp));
// 		wqe->status = IB_WC_LOC_QP_OP_ERR;
// 		goto err_drop_ah;
// 	}

// 	ret = finish_packet(qp, av, wqe, &pkt, skb, payload);
// 	if (unlikely(ret)) {
// 		pr_debug("qp#%d Error during finish packet\n", qp_num(qp));
// 		if (ret == -EFAULT)
// 			wqe->status = IB_WC_LOC_PROT_ERR;
// 		else
// 			wqe->status = IB_WC_LOC_QP_OP_ERR;
// 		kfree_skb(skb);
// 		goto err_drop_ah;
// 	}

// 	if (ah)
// 		dtld_put(ah);

// 	/*
// 	 * To prevent a race on wqe access between requester and completer,
// 	 * wqe members state and psn need to be set before calling
// 	 * dtld_xmit_packet().
// 	 * Otherwise, completer might initiate an unjustified retry flow.
// 	 */
// 	save_state(wqe, qp, &rollback_wqe, &rollback_psn);
// 	update_wqe_state(qp, wqe, &pkt);
// 	update_wqe_psn(qp, wqe, &pkt, payload);
// 	ret = dtld_xmit_packet(qp, &pkt, skb);
// 	if (ret) {
// 		qp->need_req_skb = 1;

// 		rollback_state(wqe, qp, &rollback_wqe, rollback_psn);

// 		if (ret == -EAGAIN) {
// 			dtld_run_task(&qp->req.task, 1);
// 			goto exit;
// 		}

// 		wqe->status = IB_WC_LOC_QP_OP_ERR;
// 		goto err;
// 	}

// 	update_state(qp, &pkt);

// 	goto next_wqe;

// err_drop_ah:
// 	if (ah)
// 		dtld_put(ah);
// err:
// 	wqe->state = wqe_state_error;
// 	__dtld_do_task(&qp->comp.task);

// exit:
// 	dtld_put(qp);
// 	return -EAGAIN;
}
