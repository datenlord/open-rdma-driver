// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <rdma/uverbs_ioctl.h>

#include "dtld.h"
#include "dtld_loc.h"
#include "dtld_queue.h"
#include "dtld_task.h"

static int dtld_qp_chk_cap(struct dtld_dev *dtld, struct ib_qp_cap *cap,
			  int has_srq)
{
	if (cap->max_send_wr > dtld->attr.max_qp_wr) {
		pr_warn("invalid send wr = %d > %d\n",
			cap->max_send_wr, dtld->attr.max_qp_wr);
		goto err1;
	}

	if (cap->max_send_sge > dtld->attr.max_send_sge) {
		pr_warn("invalid send sge = %d > %d\n",
			cap->max_send_sge, dtld->attr.max_send_sge);
		goto err1;
	}

	if (!has_srq) {
		if (cap->max_recv_wr > dtld->attr.max_qp_wr) {
			pr_warn("invalid recv wr = %d > %d\n",
				cap->max_recv_wr, dtld->attr.max_qp_wr);
			goto err1;
		}

		if (cap->max_recv_sge > dtld->attr.max_recv_sge) {
			pr_warn("invalid recv sge = %d > %d\n",
				cap->max_recv_sge, dtld->attr.max_recv_sge);
			goto err1;
		}
	}

	if (cap->max_inline_data > dtld->max_inline_data) {
		pr_warn("invalid max inline data = %d > %d\n",
			cap->max_inline_data, dtld->max_inline_data);
		goto err1;
	}

	return 0;

err1:
	return -EINVAL;
}

int dtld_qp_chk_init(struct dtld_dev *dtld, struct ib_qp_init_attr *init)
{
	struct ib_qp_cap *cap = &init->cap;
	struct dtld_port *port;
	int port_num = init->port_num;

	switch (init->qp_type) {
	case IB_QPT_GSI:
	case IB_QPT_RC:
	case IB_QPT_UC:
	case IB_QPT_UD:
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!init->recv_cq || !init->send_cq) {
		pr_warn("missing cq\n");
		goto err1;
	}

	if (dtld_qp_chk_cap(dtld, cap, !!init->srq))
		goto err1;

	if (init->qp_type == IB_QPT_GSI) {
		if (!rdma_is_port_valid(&dtld->ib_dev, port_num)) {
			pr_warn("invalid port = %d\n", port_num);
			goto err1;
		}

		port = &dtld->port;

		if (init->qp_type == IB_QPT_GSI && port->qp_gsi_index) {
			pr_warn("GSI QP exists for port %d\n", port_num);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

static int alloc_rd_atomic_resources(struct dtld_qp *qp, unsigned int n)
{
	qp->resp.res_head = 0;
	qp->resp.res_tail = 0;
	qp->resp.resources = kcalloc(n, sizeof(struct resp_res), GFP_KERNEL);

	if (!qp->resp.resources)
		return -ENOMEM;

	return 0;
}

static void free_rd_atomic_resources(struct dtld_qp *qp)
{
	if (qp->resp.resources) {
		int i;

		for (i = 0; i < qp->attr.max_dest_rd_atomic; i++) {
			struct resp_res *res = &qp->resp.resources[i];

			free_rd_atomic_resource(qp, res);
		}
		kfree(qp->resp.resources);
		qp->resp.resources = NULL;
	}
}

void free_rd_atomic_resource(struct dtld_qp *qp, struct resp_res *res)
{
	// if (res->type == DTLD_ATOMIC_MASK)
	// 	kfree_skb(res->atomic.skb);
	res->type = 0;
}

static void cleanup_rd_atomic_resources(struct dtld_qp *qp)
{
	int i;
	struct resp_res *res;

	if (qp->resp.resources) {
		for (i = 0; i < qp->attr.max_dest_rd_atomic; i++) {
			res = &qp->resp.resources[i];
			free_rd_atomic_resource(qp, res);
		}
	}
}

static void dtld_qp_init_misc(struct dtld_dev *dtld, struct dtld_qp *qp,
			     struct ib_qp_init_attr *init)
{
	struct dtld_port *port;
	u32 qpn;

	qp->sq_sig_type		= init->sq_sig_type;
	qp->attr.path_mtu	= 1;
	qp->mtu			= ib_mtu_enum_to_int(qp->attr.path_mtu);

	qpn			= qp->elem.index;
	port			= &dtld->port;

	switch (init->qp_type) {
	case IB_QPT_GSI:
		qp->ibqp.qp_num		= 1;
		port->qp_gsi_index	= qpn;
		qp->attr.port_num	= init->port_num;
		break;

	default:
		qp->ibqp.qp_num		= qpn;
		break;
	}

	spin_lock_init(&qp->state_lock);

	atomic_set(&qp->ssn, 0);
	atomic_set(&qp->skb_out, 0);
}

static int dtld_qp_init_req(struct dtld_dev *dtld, struct dtld_qp *qp,
			   struct ib_qp_init_attr *init, struct ib_udata *udata,
			   struct dtld_create_qp_resp __user *uresp)
{
	int err;
	int wqe_size;
	enum queue_type type;

	// err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, 0, &qp->sk);
	// if (err < 0)
	// 	return err;
	// qp->sk->sk->sk_user_data = qp;

	/* pick a source UDP port number for this QP based on
	 * the source QPN. this spreads traffic for different QPs
	 * across different NIC RX queues (while using a single
	 * flow for a given QP to maintain packet order).
	 * the port number must be in the Dynamic Ports range
	 * (0xc000 - 0xffff).
	 */
	// qp->src_port = DTLD_ROCE_V2_SPORT + (hash_32(qp_num(qp), 14) & 0x3fff);
	qp->sq.max_wr		= init->cap.max_send_wr;

	/* These caps are limited by dtld_qp_chk_cap() done by the caller */
	wqe_size = max_t(int, init->cap.max_send_sge * sizeof(struct ib_sge),
			 init->cap.max_inline_data);
	qp->sq.max_sge = init->cap.max_send_sge =
		wqe_size / sizeof(struct ib_sge);
	qp->sq.max_inline = init->cap.max_inline_data = wqe_size;
	wqe_size += sizeof(struct dtld_send_wqe);

	type = QUEUE_TYPE_FROM_CLIENT;
	qp->sq.queue = dtld_queue_init(dtld, &qp->sq.max_wr,
				wqe_size, type);
	if (!qp->sq.queue)
		return -ENOMEM;

	err = do_mmap_info(dtld, uresp ? &uresp->sq_mi : NULL, udata,
			   qp->sq.queue->buf, qp->sq.queue->buf_size,
			   &qp->sq.queue->ip);

	if (err) {
		vfree(qp->sq.queue->buf);
		kfree(qp->sq.queue);
		qp->sq.queue = NULL;
		return err;
	}

	qp->req.wqe_index = queue_get_producer(qp->sq.queue,
					       QUEUE_TYPE_FROM_CLIENT);

	qp->req.state		= QP_STATE_RESET;
	qp->req.opcode		= -1;
	qp->comp.opcode		= -1;

	spin_lock_init(&qp->sq.sq_lock);
	// skb_queue_head_init(&qp->req_pkts);

	dtld_init_task(dtld, &qp->req.task, qp,
		      dtld_requester, "req");
	dtld_init_task(dtld, &qp->comp.task, qp,
		      dtld_completer, "comp");

	qp->qp_timeout_jiffies = 0; /* Can't be set for UD/UC in modify_qp */
	if (init->qp_type == IB_QPT_RC) {
		timer_setup(&qp->rnr_nak_timer, rnr_nak_timer, 0);
		timer_setup(&qp->retrans_timer, retransmit_timer, 0);
	}
	return 0;
}

static int dtld_qp_init_resp(struct dtld_dev *dtld, struct dtld_qp *qp,
			    struct ib_qp_init_attr *init,
			    struct ib_udata *udata,
			    struct dtld_create_qp_resp __user *uresp)
{
	int err;
	int wqe_size;
	enum queue_type type;

	if (!qp->srq) {
		qp->rq.max_wr		= init->cap.max_recv_wr;
		qp->rq.max_sge		= init->cap.max_recv_sge;

		wqe_size = rcv_wqe_size(qp->rq.max_sge);

		pr_debug("qp#%d max_wr = %d, max_sge = %d, wqe_size = %d\n",
			 qp_num(qp), qp->rq.max_wr, qp->rq.max_sge, wqe_size);

		type = QUEUE_TYPE_FROM_CLIENT;
		qp->rq.queue = dtld_queue_init(dtld, &qp->rq.max_wr,
					wqe_size, type);
		if (!qp->rq.queue)
			return -ENOMEM;

		err = do_mmap_info(dtld, uresp ? &uresp->rq_mi : NULL, udata,
				   qp->rq.queue->buf, qp->rq.queue->buf_size,
				   &qp->rq.queue->ip);
		if (err) {
			vfree(qp->rq.queue->buf);
			kfree(qp->rq.queue);
			qp->rq.queue = NULL;
			return err;
		}
	}

	spin_lock_init(&qp->rq.producer_lock);
	spin_lock_init(&qp->rq.consumer_lock);

	// skb_queue_head_init(&qp->resp_pkts);

	dtld_init_task(dtld, &qp->resp.task, qp,
		      dtld_responder, "resp");

	// qp->resp.opcode		= OPCODE_NONE;
	qp->resp.msn		= 0;
	qp->resp.state		= QP_STATE_RESET;

	return 0;
}

/* called by the create qp verb */
int dtld_qp_from_init(struct dtld_dev *dtld, struct dtld_qp *qp, struct dtld_pd *pd,
		     struct ib_qp_init_attr *init,
		     struct dtld_create_qp_resp __user *uresp,
		     struct ib_pd *ibpd,
		     struct ib_udata *udata)
{
	int err;
	struct dtld_cq *rcq = to_dtld_cq(init->recv_cq);
	struct dtld_cq *scq = to_dtld_cq(init->send_cq);
	struct dtld_srq *srq = init->srq ? to_dtld_srq(init->srq) : NULL;

	dtld_get(pd);
	dtld_get(rcq);
	dtld_get(scq);
	if (srq)
		dtld_get(srq);

	qp->pd			= pd;
	qp->rcq			= rcq;
	qp->scq			= scq;
	qp->srq			= srq;

	atomic_inc(&rcq->num_wq);
	atomic_inc(&scq->num_wq);

	dtld_qp_init_misc(dtld, qp, init);

	err = dtld_qp_init_req(dtld, qp, init, udata, uresp);
	if (err)
		goto err1;

	err = dtld_qp_init_resp(dtld, qp, init, udata, uresp);
	if (err)
		goto err2;

	qp->attr.qp_state = IB_QPS_RESET;
	qp->valid = 1;

	return 0;

err2:
	dtld_queue_cleanup(qp->sq.queue);
	qp->sq.queue = NULL;
err1:
	atomic_dec(&rcq->num_wq);
	atomic_dec(&scq->num_wq);

	qp->pd = NULL;
	qp->rcq = NULL;
	qp->scq = NULL;
	qp->srq = NULL;

	if (srq)
		dtld_put(srq);
	dtld_put(scq);
	dtld_put(rcq);
	dtld_put(pd);

	return err;
}

// /* called by the query qp verb */
// int dtld_qp_to_init(struct dtld_qp *qp, struct ib_qp_init_attr *init)
// {
// 	init->event_handler		= qp->ibqp.event_handler;
// 	init->qp_context		= qp->ibqp.qp_context;
// 	init->send_cq			= qp->ibqp.send_cq;
// 	init->recv_cq			= qp->ibqp.recv_cq;
// 	init->srq			= qp->ibqp.srq;

// 	init->cap.max_send_wr		= qp->sq.max_wr;
// 	init->cap.max_send_sge		= qp->sq.max_sge;
// 	init->cap.max_inline_data	= qp->sq.max_inline;

// 	if (!qp->srq) {
// 		init->cap.max_recv_wr		= qp->rq.max_wr;
// 		init->cap.max_recv_sge		= qp->rq.max_sge;
// 	}

// 	init->sq_sig_type		= qp->sq_sig_type;

// 	init->qp_type			= qp->ibqp.qp_type;
// 	init->port_num			= 1;

// 	return 0;
// }

/* called by the modify qp verb, this routine checks all the parameters before
 * making any changes
 */
int dtld_qp_chk_attr(struct dtld_dev *dtld, struct dtld_qp *qp,
		    struct ib_qp_attr *attr, int mask)
{
	enum ib_qp_state cur_state = (mask & IB_QP_CUR_STATE) ?
					attr->cur_qp_state : qp->attr.qp_state;
	enum ib_qp_state new_state = (mask & IB_QP_STATE) ?
					attr->qp_state : cur_state;

	if (!ib_modify_qp_is_ok(cur_state, new_state, qp_type(qp), mask)) {
		pr_warn("invalid mask or state for qp\n");
		goto err1;
	}

	if (mask & IB_QP_STATE) {
		if (cur_state == IB_QPS_SQD) {
			if (qp->req.state == QP_STATE_DRAIN &&
			    new_state != IB_QPS_ERR)
				goto err1;
		}
	}

	if (mask & IB_QP_PORT) {
		if (!rdma_is_port_valid(&dtld->ib_dev, attr->port_num)) {
			pr_warn("invalid port %d\n", attr->port_num);
			goto err1;
		}
	}

	if (mask & IB_QP_CAP && dtld_qp_chk_cap(dtld, &attr->cap, !!qp->srq))
		goto err1;

	if (mask & IB_QP_AV && dtld_av_chk_attr(dtld, &attr->ah_attr))
		goto err1;

	if (mask & IB_QP_ALT_PATH) {
		if (dtld_av_chk_attr(dtld, &attr->alt_ah_attr))
			goto err1;
		if (!rdma_is_port_valid(&dtld->ib_dev, attr->alt_port_num))  {
			pr_warn("invalid alt port %d\n", attr->alt_port_num);
			goto err1;
		}
		if (attr->alt_timeout > 31) {
			pr_warn("invalid QP alt timeout %d > 31\n",
				attr->alt_timeout);
			goto err1;
		}
	}

	if (mask & IB_QP_PATH_MTU) {
		struct dtld_port *port = &dtld->port;

		enum ib_mtu max_mtu = port->attr.max_mtu;
		enum ib_mtu mtu = attr->path_mtu;

		if (mtu > max_mtu) {
			pr_debug("invalid mtu (%d) > (%d)\n",
				 ib_mtu_enum_to_int(mtu),
				 ib_mtu_enum_to_int(max_mtu));
			goto err1;
		}
	}

	if (mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (attr->max_rd_atomic > dtld->attr.max_qp_rd_atom) {
			pr_warn("invalid max_rd_atomic %d > %d\n",
				attr->max_rd_atomic,
				dtld->attr.max_qp_rd_atom);
			goto err1;
		}
	}

	if (mask & IB_QP_TIMEOUT) {
		if (attr->timeout > 31) {
			pr_warn("invalid QP timeout %d > 31\n",
				attr->timeout);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

/* move the qp to the reset state */
static void dtld_qp_reset(struct dtld_qp *qp)
{
	/* stop tasks from running */
	dtld_disable_task(&qp->resp.task);

	/* stop request/comp */
	if (qp->sq.queue) {
		if (qp_type(qp) == IB_QPT_RC)
			dtld_disable_task(&qp->comp.task);
		dtld_disable_task(&qp->req.task);
	}

	/* move qp to the reset state */
	qp->req.state = QP_STATE_RESET;
	qp->resp.state = QP_STATE_RESET;

	/* let state machines reset themselves drain work and packet queues
	 * etc.
	 */
	__dtld_do_task(&qp->resp.task);

	if (qp->sq.queue) {
		__dtld_do_task(&qp->comp.task);
		__dtld_do_task(&qp->req.task);
		dtld_queue_reset(qp->sq.queue);
	}

	/* cleanup attributes */
	atomic_set(&qp->ssn, 0);
	qp->req.opcode = -1;
	qp->req.need_retry = 0;
	qp->req.noack_pkts = 0;
	qp->resp.msn = 0;
	qp->resp.opcode = -1;
	qp->resp.drop_msg = 0;
	qp->resp.goto_error = 0;
	qp->resp.sent_psn_nak = 0;

	if (qp->resp.mr) {
		dtld_put(qp->resp.mr);
		qp->resp.mr = NULL;
	}

	cleanup_rd_atomic_resources(qp);

	/* reenable tasks */
	dtld_enable_task(&qp->resp.task);

	if (qp->sq.queue) {
		if (qp_type(qp) == IB_QPT_RC)
			dtld_enable_task(&qp->comp.task);

		dtld_enable_task(&qp->req.task);
	}
}

/* drain the send queue */
static void dtld_qp_drain(struct dtld_qp *qp)
{
	if (qp->sq.queue) {
		if (qp->req.state != QP_STATE_DRAINED) {
			qp->req.state = QP_STATE_DRAIN;
			if (qp_type(qp) == IB_QPT_RC)
				dtld_run_task(&qp->comp.task, 1);
			else
				__dtld_do_task(&qp->comp.task);
			dtld_run_task(&qp->req.task, 1);
		}
	}
}

/* move the qp to the error state */
void dtld_qp_error(struct dtld_qp *qp)
{
	qp->req.state = QP_STATE_ERROR;
	qp->resp.state = QP_STATE_ERROR;
	qp->attr.qp_state = IB_QPS_ERR;

	/* drain work and packet queues */
	dtld_run_task(&qp->resp.task, 1);

	if (qp_type(qp) == IB_QPT_RC)
		dtld_run_task(&qp->comp.task, 1);
	else
		__dtld_do_task(&qp->comp.task);
	dtld_run_task(&qp->req.task, 1);
}

/* called by the modify qp verb */
int dtld_qp_from_attr(struct dtld_qp *qp, struct ib_qp_attr *attr, int mask,
		     struct ib_udata *udata)
{
	int err;

	if (mask & IB_QP_MAX_QP_RD_ATOMIC) {
		int max_rd_atomic = attr->max_rd_atomic ?
			roundup_pow_of_two(attr->max_rd_atomic) : 0;

		qp->attr.max_rd_atomic = max_rd_atomic;
		atomic_set(&qp->req.rd_atomic, max_rd_atomic);
	}

	if (mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		int max_dest_rd_atomic = attr->max_dest_rd_atomic ?
			roundup_pow_of_two(attr->max_dest_rd_atomic) : 0;

		qp->attr.max_dest_rd_atomic = max_dest_rd_atomic;

		free_rd_atomic_resources(qp);

		err = alloc_rd_atomic_resources(qp, max_dest_rd_atomic);
		if (err)
			return err;
	}

	if (mask & IB_QP_CUR_STATE)
		qp->attr.cur_qp_state = attr->qp_state;

	if (mask & IB_QP_EN_SQD_ASYNC_NOTIFY)
		qp->attr.en_sqd_async_notify = attr->en_sqd_async_notify;

	if (mask & IB_QP_ACCESS_FLAGS)
		qp->attr.qp_access_flags = attr->qp_access_flags;

	if (mask & IB_QP_PKEY_INDEX)
		qp->attr.pkey_index = attr->pkey_index;

	if (mask & IB_QP_PORT)
		qp->attr.port_num = attr->port_num;

	if (mask & IB_QP_QKEY)
		qp->attr.qkey = attr->qkey;

	if (mask & IB_QP_AV)
		dtld_init_av(&attr->ah_attr, &qp->pri_av);

	if (mask & IB_QP_ALT_PATH) {
		dtld_init_av(&attr->alt_ah_attr, &qp->alt_av);
		qp->attr.alt_port_num = attr->alt_port_num;
		qp->attr.alt_pkey_index = attr->alt_pkey_index;
		qp->attr.alt_timeout = attr->alt_timeout;
	}

	if (mask & IB_QP_PATH_MTU) {
		qp->attr.path_mtu = attr->path_mtu;
		qp->mtu = ib_mtu_enum_to_int(attr->path_mtu);
	}

	if (mask & IB_QP_TIMEOUT) {
		qp->attr.timeout = attr->timeout;
		if (attr->timeout == 0) {
			qp->qp_timeout_jiffies = 0;
		} else {
			/* According to the spec, timeout = 4.096 * 2 ^ attr->timeout [us] */
			int j = nsecs_to_jiffies(4096ULL << attr->timeout);

			qp->qp_timeout_jiffies = j ? j : 1;
		}
	}

	if (mask & IB_QP_RETRY_CNT) {
		qp->attr.retry_cnt = attr->retry_cnt;
		qp->comp.retry_cnt = attr->retry_cnt;
		pr_debug("qp#%d set retry count = %d\n", qp_num(qp),
			 attr->retry_cnt);
	}

	if (mask & IB_QP_RNR_RETRY) {
		qp->attr.rnr_retry = attr->rnr_retry;
		qp->comp.rnr_retry = attr->rnr_retry;
		pr_debug("qp#%d set rnr retry count = %d\n", qp_num(qp),
			 attr->rnr_retry);
	}

	if (mask & IB_QP_RQ_PSN) {
		qp->attr.rq_psn = (attr->rq_psn & BTH_PSN_MASK);
		qp->resp.psn = qp->attr.rq_psn;
		pr_debug("qp#%d set resp psn = 0x%x\n", qp_num(qp),
			 qp->resp.psn);
	}

	if (mask & IB_QP_MIN_RNR_TIMER) {
		qp->attr.min_rnr_timer = attr->min_rnr_timer;
		pr_debug("qp#%d set min rnr timer = 0x%x\n", qp_num(qp),
			 attr->min_rnr_timer);
	}

	if (mask & IB_QP_SQ_PSN) {
		qp->attr.sq_psn = (attr->sq_psn & BTH_PSN_MASK);
		qp->req.psn = qp->attr.sq_psn;
		qp->comp.psn = qp->attr.sq_psn;
		pr_debug("qp#%d set req psn = 0x%x\n", qp_num(qp), qp->req.psn);
	}

	if (mask & IB_QP_PATH_MIG_STATE)
		qp->attr.path_mig_state = attr->path_mig_state;

	if (mask & IB_QP_DEST_QPN)
		qp->attr.dest_qp_num = attr->dest_qp_num;

	if (mask & IB_QP_STATE) {
		qp->attr.qp_state = attr->qp_state;

		switch (attr->qp_state) {
		case IB_QPS_RESET:
			pr_debug("qp#%d state -> RESET\n", qp_num(qp));
			dtld_qp_reset(qp);
			break;

		case IB_QPS_INIT:
			pr_debug("qp#%d state -> INIT\n", qp_num(qp));
			qp->req.state = QP_STATE_INIT;
			qp->resp.state = QP_STATE_INIT;
			break;

		case IB_QPS_RTR:
			pr_debug("qp#%d state -> RTR\n", qp_num(qp));
			qp->resp.state = QP_STATE_READY;
			break;

		case IB_QPS_RTS:
			pr_debug("qp#%d state -> RTS\n", qp_num(qp));
			qp->req.state = QP_STATE_READY;
			break;

		case IB_QPS_SQD:
			pr_debug("qp#%d state -> SQD\n", qp_num(qp));
			dtld_qp_drain(qp);
			break;

		case IB_QPS_SQE:
			pr_warn("qp#%d state -> SQE !!?\n", qp_num(qp));
			/* Not possible from modify_qp. */
			break;

		case IB_QPS_ERR:
			pr_debug("qp#%d state -> ERR\n", qp_num(qp));
			dtld_qp_error(qp);
			break;
		}
	}

	return 0;
}

// /* called by the query qp verb */
// int dtld_qp_to_attr(struct dtld_qp *qp, struct ib_qp_attr *attr, int mask)
// {
// 	*attr = qp->attr;

// 	attr->rq_psn				= qp->resp.psn;
// 	attr->sq_psn				= qp->req.psn;

// 	attr->cap.max_send_wr			= qp->sq.max_wr;
// 	attr->cap.max_send_sge			= qp->sq.max_sge;
// 	attr->cap.max_inline_data		= qp->sq.max_inline;

// 	if (!qp->srq) {
// 		attr->cap.max_recv_wr		= qp->rq.max_wr;
// 		attr->cap.max_recv_sge		= qp->rq.max_sge;
// 	}

// 	dtld_av_to_attr(&qp->pri_av, &attr->ah_attr);
// 	dtld_av_to_attr(&qp->alt_av, &attr->alt_ah_attr);

// 	if (qp->req.state == QP_STATE_DRAIN) {
// 		attr->sq_draining = 1;
// 		/* applications that get this state
// 		 * typically spin on it. yield the
// 		 * processor
// 		 */
// 		cond_resched();
// 	} else {
// 		attr->sq_draining = 0;
// 	}

// 	pr_debug("attr->sq_draining = %d\n", attr->sq_draining);

// 	return 0;
// }

// int dtld_qp_chk_destroy(struct dtld_qp *qp)
// {
// 	/* See IBA o10-2.2.3
// 	 * An attempt to destroy a QP while attached to a mcast group
// 	 * will fail immediately.
// 	 */
// 	if (atomic_read(&qp->mcg_num)) {
// 		pr_debug("Attempt to destroy QP while attached to multicast group\n");
// 		return -EBUSY;
// 	}

// 	return 0;
// }

/* called when the last reference to the qp is dropped */
static void dtld_qp_do_cleanup(struct work_struct *work)
{
	struct dtld_qp *qp = container_of(work, typeof(*qp), cleanup_work.work);

	qp->valid = 0;
	qp->qp_timeout_jiffies = 0;
	dtld_cleanup_task(&qp->resp.task);

	if (qp_type(qp) == IB_QPT_RC) {
		del_timer_sync(&qp->retrans_timer);
		del_timer_sync(&qp->rnr_nak_timer);
	}

	dtld_cleanup_task(&qp->req.task);
	dtld_cleanup_task(&qp->comp.task);

	/* flush out any receive wr's or pending requests */
	__dtld_do_task(&qp->req.task);
	if (qp->sq.queue) {
		__dtld_do_task(&qp->comp.task);
		__dtld_do_task(&qp->req.task);
	}

	if (qp->sq.queue)
		dtld_queue_cleanup(qp->sq.queue);

	if (qp->srq)
		dtld_put(qp->srq);

	if (qp->rq.queue)
		dtld_queue_cleanup(qp->rq.queue);

	atomic_dec(&qp->scq->num_wq);
	if (qp->scq)
		dtld_put(qp->scq);

	atomic_dec(&qp->rcq->num_wq);
	if (qp->rcq)
		dtld_put(qp->rcq);

	if (qp->pd)
		dtld_put(qp->pd);

	if (qp->resp.mr)
		dtld_put(qp->resp.mr);

	// if (qp_type(qp) == IB_QPT_RC)
	// 	sk_dst_reset(qp->sk->sk);

	free_rd_atomic_resources(qp);

	// kernel_sock_shutdown(qp->sk, SHUT_RDWR);
	// sock_release(qp->sk);
}

/* called when the last reference to the qp is dropped */
void dtld_qp_cleanup(struct dtld_pool_elem *elem)
{
	struct dtld_qp *qp = container_of(elem, typeof(*qp), elem);

	execute_in_process_context(dtld_qp_do_cleanup, &qp->cleanup_work);
}
