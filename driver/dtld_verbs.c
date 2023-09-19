// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "asm-generic/errno-base.h"
#include "asm/page_types.h"
#include "linux/gfp.h"
#include "linux/slab.h"
#include "rdma/ib_verbs.h"
#include "rdma/ib_user_ioctl_verbs.h"
#include <linux/dma-mapping.h>
#include <net/addrconf.h>
#include <rdma/uverbs_ioctl.h>

#include "dtld.h"
#include "dtld_verbs.h"


static int dtld_query_device(struct ib_device *dev,
			    struct ib_device_attr *attr,
			    struct ib_udata *uhw)
{
	struct dtld_dev *dtld = dtld_from_ibdev(dev);

	if (uhw->inlen || uhw->outlen)
		return -EINVAL;

	*attr = dtld->attr;
	return 0;
}

static int dtld_query_port(struct ib_device *dev,
			  u32 port_num, struct ib_port_attr *attr)
{
	// struct dtld_dev *rxe = dtld_from_ibdev(dev);
	// int rc;

	// /* *attr being zeroed by the caller, avoid zeroing it here */
	// *attr = rxe->port.attr;

	// mutex_lock(&rxe->usdev_lock);
	// rc = ib_get_eth_speed(dev, port_num, &attr->active_speed,
	// 		      &attr->active_width);

	// if (attr->state == IB_PORT_ACTIVE)
		attr->state = IB_PORT_ACTIVE;
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	// else if (dev_get_flags(rxe->ndev) & IFF_UP)
	// 	attr->phys_state = IB_PORT_PHYS_STATE_POLLING;
	// else
	// 	attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;

	// mutex_unlock(&rxe->usdev_lock);

	// return rc;
	return 0;
}

// static int dtld_query_pkey(struct ib_device *device,
// 			  u32 port_num, u16 index, u16 *pkey)
// {
// 	if (index > 0)
// 		return -EINVAL;

// 	*pkey = IB_DEFAULT_PKEY_FULL;
// 	return 0;
// }

// static int dtld_modify_device(struct ib_device *dev,
// 			     int mask, struct ib_device_modify *attr)
// {
// 	struct dtld_dev *rxe = dtld_from_ibdev(dev);

// 	if (mask & ~(IB_DEVICE_MODIFY_SYS_IMAGE_GUID |
// 		     IB_DEVICE_MODIFY_NODE_DESC))
// 		return -EOPNOTSUPP;

// 	if (mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID)
// 		rxe->attr.sys_image_guid = cpu_to_be64(attr->sys_image_guid);

// 	if (mask & IB_DEVICE_MODIFY_NODE_DESC) {
// 		memcpy(rxe->ib_dev.node_desc,
// 		       attr->node_desc, sizeof(rxe->ib_dev.node_desc));
// 	}

// 	return 0;
// }

// static int dtld_modify_port(struct ib_device *dev,
// 			   u32 port_num, int mask, struct ib_port_modify *attr)
// {
// 	struct dtld_dev *rxe = dtld_from_ibdev(dev);
// 	struct dtld_port *port;

// 	port = &rxe->port;

// 	port->attr.port_cap_flags |= attr->set_port_cap_mask;
// 	port->attr.port_cap_flags &= ~attr->clr_port_cap_mask;

// 	if (mask & IB_PORT_RESET_QKEY_CNTR)
// 		port->attr.qkey_viol_cntr = 0;

// 	return 0;
// }

static enum rdma_link_layer dtld_get_link_layer(struct ib_device *dev,
					       u32 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

static int dtld_alloc_ucontext(struct ib_ucontext *ibuc, struct ib_udata *udata)
{
	struct dtld_dev *rxe = dtld_from_ibdev(ibuc->device);
	struct dtld_ucontext *uc = to_dtld_uc(ibuc);

	return dtld_add_to_pool(&rxe->uc_pool, uc);

	return 0;
}

static void dtld_dealloc_ucontext(struct ib_ucontext *ibuc)
{
	// struct dtld_ucontext *uc = to_ruc(ibuc);

	// dtld_put(uc);
}

static int dtld_port_immutable(struct ib_device *dev, u32 port_num,
			      struct ib_port_immutable *immutable)
{
	// int err;
	// struct ib_port_attr attr;

	// immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;

	// err = ib_query_port(dev, port_num, &attr);
	// if (err)
	// 	return err;

	// immutable->pkey_tbl_len = attr.pkey_tbl_len;
	// immutable->gid_tbl_len = attr.gid_tbl_len;
	// immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

static int dtld_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct dtld_dev *dtld = dtld_from_ibdev(ibpd->device);
	struct dtld_pd *pd = to_dtld_pd(ibpd);

	return dtld_add_to_pool(&dtld->pd_pool, pd);

}

static int dtld_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct dtld_pd *pd = to_dtld_pd(ibpd);

	dtld_put(pd);
	return 0;
}

// static int dtld_create_ah(struct ib_ah *ibah,
// 			 struct rdma_ah_init_attr *init_attr,
// 			 struct ib_udata *udata)

// {
// 	struct dtld_dev *rxe = dtld_from_ibdev(ibah->device);
// 	struct dtld_ah *ah = to_rah(ibah);
// 	struct dtld_create_ah_resp __user *uresp = NULL;
// 	int err;

// 	if (udata) {
// 		/* test if new user provider */
// 		if (udata->outlen >= sizeof(*uresp))
// 			uresp = udata->outbuf;
// 		ah->is_user = true;
// 	} else {
// 		ah->is_user = false;
// 	}

// 	err = dtld_av_chk_attr(rxe, init_attr->ah_attr);
// 	if (err)
// 		return err;

// 	err = dtld_add_to_pool(&rxe->ah_pool, ah);
// 	if (err)
// 		return err;

// 	/* create index > 0 */
// 	ah->ah_num = ah->elem.index;

// 	if (uresp) {
// 		/* only if new user provider */
// 		err = copy_to_user(&uresp->ah_num, &ah->ah_num,
// 					 sizeof(uresp->ah_num));
// 		if (err) {
// 			dtld_put(ah);
// 			return -EFAULT;
// 		}
// 	} else if (ah->is_user) {
// 		/* only if old user provider */
// 		ah->ah_num = 0;
// 	}

// 	dtld_init_av(init_attr->ah_attr, &ah->av);
// 	return 0;
// }

// static int dtld_modify_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr)
// {
// 	int err;
// 	struct dtld_dev *rxe = dtld_from_ibdev(ibah->device);
// 	struct dtld_ah *ah = to_rah(ibah);

// 	err = dtld_av_chk_attr(rxe, attr);
// 	if (err)
// 		return err;

// 	dtld_init_av(attr, &ah->av);
// 	return 0;
// }

// static int dtld_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr)
// {
// 	struct dtld_ah *ah = to_rah(ibah);

// 	memset(attr, 0, sizeof(*attr));
// 	attr->type = ibah->type;
// 	dtld_av_to_attr(&ah->av, attr);
// 	return 0;
// }

// static int dtld_destroy_ah(struct ib_ah *ibah, u32 flags)
// {
// 	struct dtld_ah *ah = to_rah(ibah);

// 	dtld_put(ah);
// 	return 0;
// }

static int post_one_recv(struct dtld_rq *rq, const struct ib_recv_wr *ibwr)
{
	int err;
	int i;
	u32 length;
	struct dtld_recv_wqe *recv_wqe;
	int num_sge = ibwr->num_sge;
	int full;

	full = queue_full(rq->queue, QUEUE_TYPE_TO_DRIVER);
	if (unlikely(full)) {
		err = -ENOMEM;
		goto err1;
	}

	if (unlikely(num_sge > rq->max_sge)) {
		err = -EINVAL;
		goto err1;
	}

	length = 0;
	for (i = 0; i < num_sge; i++)
		length += ibwr->sg_list[i].length;

	recv_wqe = queue_producer_addr(rq->queue, QUEUE_TYPE_TO_DRIVER);
	recv_wqe->wr_id = ibwr->wr_id;
	recv_wqe->num_sge = num_sge;

	memcpy(recv_wqe->dma.sge, ibwr->sg_list,
	       num_sge * sizeof(struct ib_sge));

	recv_wqe->dma.length		= length;
	recv_wqe->dma.resid		= length;
	recv_wqe->dma.num_sge		= num_sge;
	recv_wqe->dma.cur_sge		= 0;
	recv_wqe->dma.sge_offset	= 0;

	queue_advance_producer(rq->queue, QUEUE_TYPE_TO_DRIVER);

	return 0;

err1:
	return err;
}

// static int dtld_create_srq(struct ib_srq *ibsrq, struct ib_srq_init_attr *init,
// 			  struct ib_udata *udata)
// {
// 	int err;
// 	struct dtld_dev *rxe = dtld_from_ibdev(ibsrq->device);
// 	struct dtld_pd *pd = to_rpd(ibsrq->pd);
// 	struct dtld_srq *srq = to_rsrq(ibsrq);
// 	struct dtld_create_srq_resp __user *uresp = NULL;

// 	if (udata) {
// 		if (udata->outlen < sizeof(*uresp))
// 			return -EINVAL;
// 		uresp = udata->outbuf;
// 	}

// 	if (init->srq_type != IB_SRQT_BASIC)
// 		return -EOPNOTSUPP;

// 	err = dtld_srq_chk_init(rxe, init);
// 	if (err)
// 		return err;

// 	err = dtld_add_to_pool(&rxe->srq_pool, srq);
// 	if (err)
// 		return err;

// 	dtld_get(pd);
// 	srq->pd = pd;

// 	err = dtld_srq_from_init(rxe, srq, init, udata, uresp);
// 	if (err)
// 		goto err_put;

// 	return 0;

// err_put:
// 	dtld_put(srq);
// 	return err;
// }

// static int dtld_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
// 			  enum ib_srq_attr_mask mask,
// 			  struct ib_udata *udata)
// {
// 	int err;
// 	struct dtld_srq *srq = to_rsrq(ibsrq);
// 	struct dtld_dev *rxe = dtld_from_ibdev(ibsrq->device);
// 	struct dtld_modify_srq_cmd ucmd = {};

// 	if (udata) {
// 		if (udata->inlen < sizeof(ucmd))
// 			return -EINVAL;

// 		err = ib_copy_from_udata(&ucmd, udata, sizeof(ucmd));
// 		if (err)
// 			return err;
// 	}

// 	err = dtld_srq_chk_attr(rxe, srq, attr, mask);
// 	if (err)
// 		return err;

// 	err = dtld_srq_from_attr(rxe, srq, attr, mask, &ucmd, udata);
// 	if (err)
// 		return err;
// 	return 0;
// }

// static int dtld_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr)
// {
// 	struct dtld_srq *srq = to_rsrq(ibsrq);

// 	if (srq->error)
// 		return -EINVAL;

// 	attr->max_wr = srq->rq.queue->buf->index_mask;
// 	attr->max_sge = srq->rq.max_sge;
// 	attr->srq_limit = srq->limit;
// 	return 0;
// }

// static int dtld_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata)
// {
// 	struct dtld_srq *srq = to_rsrq(ibsrq);

// 	dtld_put(srq);
// 	return 0;
// }

// static int dtld_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
// 			     const struct ib_recv_wr **bad_wr)
// {
// 	int err = 0;
// 	struct dtld_srq *srq = to_rsrq(ibsrq);
// 	unsigned long flags;

// 	spin_lock_irqsave(&srq->rq.producer_lock, flags);

// 	while (wr) {
// 		err = post_one_recv(&srq->rq, wr);
// 		if (unlikely(err))
// 			break;
// 		wr = wr->next;
// 	}

// 	spin_unlock_irqrestore(&srq->rq.producer_lock, flags);

// 	if (err)
// 		*bad_wr = wr;

// 	return err;
// }

static int dtld_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init,
			 struct ib_udata *udata)
{
	int err;
	struct dtld_dev *dtld = dtld_from_ibdev(ibqp->device);
	struct dtld_pd *pd = to_dtld_pd(ibqp->pd);
	struct dtld_qp *qp = to_dtld_qp(ibqp);
	struct dtld_uresp_create_qp __user *uresp = NULL;

	if (udata) {
		if (udata->outlen < sizeof(*uresp))
			return -EINVAL;
		uresp = udata->outbuf;
	}

	if (init->create_flags)
		return -EOPNOTSUPP;

	err = dtld_qp_chk_init(dtld, init);
	if (err)
		return err;

	if (udata) {
		if (udata->inlen)
			return -EINVAL;
	}

	err = dtld_add_to_pool(&dtld->qp_pool, qp);
	if (err)
		return err;

	err = dtld_qp_from_init(dtld, qp, pd, init, uresp, ibqp->pd, udata);
	if (err)
		goto qp_init;

	return 0;

qp_init:
	dtld_put(qp);
	return err;
}

static int dtld_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int mask, struct ib_udata *udata)
{
	int err;
	struct dtld_dev *rxe = dtld_from_ibdev(ibqp->device);
	struct dtld_qp *qp = to_dtld_qp(ibqp);

	if (mask & ~IB_QP_ATTR_STANDARD_BITS)
		return -EOPNOTSUPP;

	err = dtld_qp_chk_attr(rxe, qp, attr, mask);
	if (err)
		goto err1;

	err = dtld_qp_from_attr(qp, attr, mask, udata);
	if (err)
		goto err1;

	// if ((mask & IB_QP_AV) && (attr->ah_attr.ah_flags & IB_AH_GRH))
	// 	qp->src_port = rdma_get_udp_sport(attr->ah_attr.grh.flow_label,
	// 					  qp->ibqp.qp_num,
	// 					  qp->attr.dest_qp_num);

	return 0;

err1:
	return err;
}

static int dtld_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			int mask, struct ib_qp_init_attr *init)
{
	struct dtld_qp *qp = to_dtld_qp(ibqp);

	dtld_qp_to_init(qp, init);
	dtld_qp_to_attr(qp, attr, mask);

	return 0;
}

static int dtld_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct dtld_qp *qp = to_dtld_qp(ibqp);
	int ret;

	ret = dtld_qp_chk_destroy(qp);
	if (ret)
		return ret;

	dtld_put(qp);
	return 0;
}

static int validate_send_wr(struct dtld_qp *qp, const struct ib_send_wr *ibwr,
			    unsigned int mask, unsigned int length)
{
	int num_sge = ibwr->num_sge;
	struct dtld_sq *sq = &qp->sq;

	if (unlikely(num_sge > sq->max_sge))
		goto err1;

	if (unlikely(mask & WR_ATOMIC_MASK)) {
		if (length < 8)
			goto err1;

		if (atomic_wr(ibwr)->remote_addr & 0x7)
			goto err1;
	}

	if (unlikely((ibwr->send_flags & IB_SEND_INLINE) &&
		     (length > sq->max_inline)))
		goto err1;

	return 0;

err1:
	return -EINVAL;
}

static void init_send_wr(struct dtld_qp *qp, struct dtld_send_wr *wr,
			 const struct ib_send_wr *ibwr)
{
	wr->wr_id = ibwr->wr_id;
	wr->num_sge = ibwr->num_sge;
	wr->opcode = ibwr->opcode;
	wr->send_flags = ibwr->send_flags;

	if (qp_type(qp) == IB_QPT_UD ||
	    qp_type(qp) == IB_QPT_GSI) {
		struct ib_ah *ibah = ud_wr(ibwr)->ah;

		wr->wr.ud.remote_qpn = ud_wr(ibwr)->remote_qpn;
		wr->wr.ud.remote_qkey = ud_wr(ibwr)->remote_qkey;
		wr->wr.ud.ah_num = to_dtld_ah(ibah)->ah_num;
		if (qp_type(qp) == IB_QPT_GSI)
			wr->wr.ud.pkey_index = ud_wr(ibwr)->pkey_index;
		if (wr->opcode == IB_WR_SEND_WITH_IMM)
			wr->ex.imm_data = ibwr->ex.imm_data;
	} else {
		switch (wr->opcode) {
		case IB_WR_RDMA_WRITE_WITH_IMM:
			wr->ex.imm_data = ibwr->ex.imm_data;
			fallthrough;
		case IB_WR_RDMA_READ:
		case IB_WR_RDMA_WRITE:
			wr->wr.rdma.remote_addr = rdma_wr(ibwr)->remote_addr;
			wr->wr.rdma.rkey	= rdma_wr(ibwr)->rkey;
			break;
		case IB_WR_SEND_WITH_IMM:
			wr->ex.imm_data = ibwr->ex.imm_data;
			break;
		case IB_WR_SEND_WITH_INV:
			wr->ex.invalidate_rkey = ibwr->ex.invalidate_rkey;
			break;
		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			wr->wr.atomic.remote_addr =
				atomic_wr(ibwr)->remote_addr;
			wr->wr.atomic.compare_add =
				atomic_wr(ibwr)->compare_add;
			wr->wr.atomic.swap = atomic_wr(ibwr)->swap;
			wr->wr.atomic.rkey = atomic_wr(ibwr)->rkey;
			break;
		case IB_WR_LOCAL_INV:
			wr->ex.invalidate_rkey = ibwr->ex.invalidate_rkey;
		break;
		case IB_WR_REG_MR:
			wr->wr.reg.mr = reg_wr(ibwr)->mr;
			wr->wr.reg.key = reg_wr(ibwr)->key;
			wr->wr.reg.access = reg_wr(ibwr)->access;
		break;
		default:
			break;
		}
	}
}

static void copy_inline_data_to_wqe(struct dtld_send_wqe *wqe,
				    const struct ib_send_wr *ibwr)
{
	struct ib_sge *sge = ibwr->sg_list;
	u8 *p = wqe->dma.inline_data;
	int i;

	for (i = 0; i < ibwr->num_sge; i++, sge++) {
		memcpy(p, (void *)(uintptr_t)sge->addr, sge->length);
		p += sge->length;
	}
}

static void init_send_wqe(struct dtld_qp *qp, const struct ib_send_wr *ibwr,
			 unsigned int mask, unsigned int length,
			 struct dtld_send_wqe *wqe)
{
	int num_sge = ibwr->num_sge;

	init_send_wr(qp, &wqe->wr, ibwr);

	/* local operation */
	if (unlikely(mask & WR_LOCAL_OP_MASK)) {
		wqe->mask = mask;
		wqe->state = wqe_state_posted;
		return;
	}

	if (unlikely(ibwr->send_flags & IB_SEND_INLINE))
		copy_inline_data_to_wqe(wqe, ibwr);
	else
		memcpy(wqe->dma.sge, ibwr->sg_list,
		       num_sge * sizeof(struct ib_sge));

	wqe->iova = mask & WR_ATOMIC_MASK ? atomic_wr(ibwr)->remote_addr :
		mask & WR_READ_OR_WRITE_MASK ? rdma_wr(ibwr)->remote_addr : 0;
	wqe->mask		= mask;
	wqe->dma.length		= length;
	wqe->dma.resid		= length;
	wqe->dma.num_sge	= num_sge;
	wqe->dma.cur_sge	= 0;
	wqe->dma.sge_offset	= 0;
	wqe->state		= wqe_state_posted;
	wqe->ssn		= atomic_add_return(1, &qp->ssn);
}

static int post_one_send(struct dtld_qp *qp, const struct ib_send_wr *ibwr,
			 unsigned int mask, u32 length)
{
	int err;
	struct dtld_sq *sq = &qp->sq;
	struct dtld_send_wqe *send_wqe;
	unsigned long flags;
	int full;

	err = validate_send_wr(qp, ibwr, mask, length);
	if (err)
		return err;

	spin_lock_irqsave(&qp->sq.sq_lock, flags);

	full = queue_full(sq->queue, QUEUE_TYPE_TO_DRIVER);

	if (unlikely(full)) {
		spin_unlock_irqrestore(&qp->sq.sq_lock, flags);
		return -ENOMEM;
	}

	send_wqe = queue_producer_addr(sq->queue, QUEUE_TYPE_TO_DRIVER);
	init_send_wqe(qp, ibwr, mask, length, send_wqe);

	queue_advance_producer(sq->queue, QUEUE_TYPE_TO_DRIVER);

	spin_unlock_irqrestore(&qp->sq.sq_lock, flags);

	return 0;
}

static int dtld_post_send_kernel(struct dtld_qp *qp, const struct ib_send_wr *wr,
				const struct ib_send_wr **bad_wr)
{
	int err = 0;
	unsigned int mask;
	unsigned int length = 0;
	int i;
	struct ib_send_wr *next;

	while (wr) {
		mask = wr_opcode_mask(wr->opcode, qp);
		if (unlikely(!mask)) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}

		if (unlikely((wr->send_flags & IB_SEND_INLINE) &&
			     !(mask & WR_INLINE_MASK))) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}

		next = wr->next;

		length = 0;
		for (i = 0; i < wr->num_sge; i++)
			length += wr->sg_list[i].length;

		err = post_one_send(qp, wr, mask, length);

		if (err) {
			*bad_wr = wr;
			break;
		}
		wr = next;
	}

	dtld_run_task(&qp->req.task, 1);
	if (unlikely(qp->req.state == QP_STATE_ERROR))
		dtld_run_task(&qp->comp.task, 1);

	return err;
}

static int dtld_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			 const struct ib_send_wr **bad_wr)
{
	struct dtld_qp *qp = to_dtld_qp(ibqp);

	if (unlikely(!qp->valid)) {
		*bad_wr = wr;
		return -EINVAL;
	}

	if (unlikely(qp->req.state < QP_STATE_READY)) {
		*bad_wr = wr;
		return -EINVAL;
	}

	return 0;
}

static int dtld_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
			 const struct ib_recv_wr **bad_wr)
{
	int err = 0;
	struct dtld_qp *qp = to_dtld_qp(ibqp);
	struct dtld_rq *rq = &qp->rq;
	unsigned long flags;

	if (unlikely((qp_state(qp) < IB_QPS_INIT) || !qp->valid)) {
		*bad_wr = wr;
		err = -EINVAL;
		goto err1;
	}

	if (unlikely(qp->srq)) {
		*bad_wr = wr;
		err = -EINVAL;
		goto err1;
	}

	spin_lock_irqsave(&rq->producer_lock, flags);

	while (wr) {
		err = post_one_recv(rq, wr);
		if (unlikely(err)) {
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}

	spin_unlock_irqrestore(&rq->producer_lock, flags);

	if (qp->resp.state == QP_STATE_ERROR)
		dtld_run_task(&qp->resp.task, 1);

err1:
	return err;
}

static int get_cq_ucmd(struct dtld_dev *dtld, struct ib_udata *udata,
		       struct dtld_ureq_create_cq *ucmd)
{
	struct ib_device *ib_dev = &dtld->ib_dev;
	int ret;

	ret = ib_copy_from_udata(ucmd, udata, min(udata->inlen, sizeof(*ucmd)));
	if (ret) {
		ibdev_err(ib_dev, "failed to copy CQ udata, ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static int dtld_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
			 struct ib_udata *udata)
{
	int err;
	struct ib_device *dev = ibcq->device;
	struct dtld_dev *dtld = dtld_from_ibdev(dev);
	struct dtld_cq *cq = to_dtld_cq(ibcq);
	struct dtld_ureq_create_cq ucmd = {};
	struct dtld_uresp_create_cq uresp = {};

	if (udata) {
		err = get_cq_ucmd(dtld, udata, &ucmd);
		if (err)
			return err;
		if (udata->outlen < sizeof(uresp))
			return -EINVAL;
	}

	if (attr->flags)
		return -EOPNOTSUPP;


	err = dtld_cq_chk_attr(dtld, NULL, attr->cqe, attr->comp_vector);
	if (err)
		return err;

	err = dtld_add_to_pool(&dtld->cq_pool, cq);
	if (err) 
		return err;

	err = dtld_cq_from_init(dtld, cq, attr->cqe, attr->comp_vector, udata,
			       &uresp);
	if (err){
		goto err_init_cq;
	}

	err = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
	if (err)
		goto err_copy_data_back_to_user;

	return 0;

err_copy_data_back_to_user:
	rdma_user_mmap_entry_remove(&cq->ummap_ent->rdma_entry);

err_init_cq:
	dtld_put(cq);

	return err;
}

static int dtld_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	struct dtld_cq *cq = to_dtld_cq(ibcq);

	/* See IBA C11-17: The CI shall return an error if this Verb is
	 * invoked while a Work Queue is still associated with the CQ.
	 */
	if (atomic_read(&cq->num_wq))
		return -EINVAL;

	dtld_cq_disable(cq);

	dtld_put(cq);
	return 0;
}

// static int dtld_resize_cq(struct ib_cq *ibcq, int cqe, struct ib_udata *udata)
// {
// 	int err;
// 	struct dtld_cq *cq = to_rcq(ibcq);
// 	struct dtld_dev *rxe = dtld_from_ibdev(ibcq->device);
// 	struct dtld_resize_cq_resp __user *uresp = NULL;

// 	if (udata) {
// 		if (udata->outlen < sizeof(*uresp))
// 			return -EINVAL;
// 		uresp = udata->outbuf;
// 	}

// 	err = dtld_cq_chk_attr(rxe, cq, cqe, 0);
// 	if (err)
// 		goto err1;

// 	err = dtld_cq_resize_queue(cq, cqe, uresp, udata);
// 	if (err)
// 		goto err1;

// 	return 0;

// err1:
// 	return err;
// }

static int dtld_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	int i;
	struct dtld_cq *cq = to_dtld_cq(ibcq);
	struct dtld_cqe *cqe;
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);
	for (i = 0; i < num_entries; i++) {
		cqe = queue_head(cq->queue, QUEUE_TYPE_FROM_DRIVER);
		if (!cqe)
			break;

		memcpy(wc++, &cqe->ibwc, sizeof(*wc));
		queue_advance_consumer(cq->queue, QUEUE_TYPE_FROM_DRIVER);
	}
	spin_unlock_irqrestore(&cq->cq_lock, flags);

	return i;
}

static int dtld_peek_cq(struct ib_cq *ibcq, int wc_cnt)
{
	struct dtld_cq *cq = to_dtld_cq(ibcq);
	int count;

	count = queue_count(cq->queue, QUEUE_TYPE_FROM_DRIVER);

	return (count > wc_cnt) ? wc_cnt : count;
}

// static int dtld_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
// {
// 	struct dtld_cq *cq = to_rcq(ibcq);
// 	int ret = 0;
// 	int empty;
// 	unsigned long irq_flags;

// 	spin_lock_irqsave(&cq->cq_lock, irq_flags);
// 	if (cq->notify != IB_CQ_NEXT_COMP)
// 		cq->notify = flags & IB_CQ_SOLICITED_MASK;

// 	empty = queue_empty(cq->queue, QUEUE_TYPE_FROM_DRIVER);

// 	if ((flags & IB_CQ_REPORT_MISSED_EVENTS) && !empty)
// 		ret = 1;

// 	spin_unlock_irqrestore(&cq->cq_lock, irq_flags);

// 	return ret;
// }

// static struct ib_mr *dtld_get_dma_mr(struct ib_pd *ibpd, int access)
// {
// 	struct dtld_dev *rxe = dtld_from_ibdev(ibpd->device);
// 	struct dtld_pd *pd = to_rpd(ibpd);
// 	struct dtld_mr *mr;

// 	mr = dtld_alloc(&rxe->mr_pool);
// 	if (!mr)
// 		return ERR_PTR(-ENOMEM);

// 	dtld_get(pd);
// 	dtld_mr_init_dma(pd, access, mr);

// 	return &mr->ibmr;
// }

static struct ib_mr *dtld_reg_user_mr(struct ib_pd *ibpd,
				     u64 start,
				     u64 length,
				     u64 iova,
				     int access, struct ib_udata *udata)
{
	int err;
	struct dtld_dev *rxe = dtld_from_ibdev(ibpd->device);
	struct dtld_pd *pd = to_dtld_pd(ibpd);
	struct dtld_mr *mr;

	mr = dtld_alloc(&rxe->mr_pool);
	if (!mr) {
		err = -ENOMEM;
		goto err2;
	}


	dtld_get(pd);

	err = dtld_mr_init_user(pd, start, length, iova, access, mr);
	if (err)
		goto err3;

	return &mr->ibmr;

err3:
	dtld_put(pd);
	dtld_put(mr);
err2:
	return ERR_PTR(err);
}

// static struct ib_mr *dtld_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type,
// 				  u32 max_num_sg)
// {
// 	struct dtld_dev *dtld = dtld_from_ibdev(ibpd->device);
// 	struct dtld_pd *pd = to_dtld_pd(ibpd);
// 	struct dtld_mr *mr;
// 	int err;

// 	if (mr_type != IB_MR_TYPE_MEM_REG)
// 		return ERR_PTR(-EINVAL);

// 	mr = dtld_alloc(&dtld->mr_pool);
// 	if (!mr) {
// 		err = -ENOMEM;
// 		goto err1;
// 	}

// 	dtld_get(pd);

// 	err = dtld_mr_init_fast(pd, max_num_sg, mr);
// 	if (err)
// 		goto err2;

// 	return &mr->ibmr;

// err2:
// 	dtld_put(pd);
// 	dtld_put(mr);
// err1:
// 	return ERR_PTR(err);
// }

// /* build next_map_set from scatterlist
//  * The IB_WR_REG_MR WR will swap map_sets
//  */
// static int dtld_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
// 			 int sg_nents, unsigned int *sg_offset)
// {
// 	struct dtld_mr *mr = to_rmr(ibmr);
// 	struct dtld_map_set *set = mr->next_map_set;
// 	int n;

// 	set->nbuf = 0;

// 	n = ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, dtld_mr_set_page);

// 	set->va = ibmr->iova;
// 	set->iova = ibmr->iova;
// 	set->length = ibmr->length;
// 	set->page_shift = ilog2(ibmr->page_size);
// 	set->page_mask = ibmr->page_size - 1;
// 	set->offset = set->iova & set->page_mask;

// 	return n;
// }

// static ssize_t parent_show(struct device *device,
// 			   struct device_attribute *attr, char *buf)
// {
// 	struct dtld_dev *rxe =
// 		rdma_device_to_drv_device(device, struct dtld_dev, ib_dev);

// 	return sysfs_emit(buf, "%s\n", dtld_parent_name(rxe, 1));
// }

// static DEVICE_ATTR_RO(parent);

// static struct attribute *dtld_dev_attributes[] = {
// 	&dev_attr_parent.attr,
// 	NULL
// };

// static const struct attribute_group dtld_attr_group = {
// 	.attrs = dtld_dev_attributes,
// };

// static int dtld_enable_driver(struct ib_device *ib_dev)
// {
// 	struct dtld_dev *rxe = container_of(ib_dev, struct dtld_dev, ib_dev);

// 	dtld_set_port_state(rxe);
// 	dev_info(&rxe->ib_dev.dev, "added %s\n", netdev_name(rxe->ndev));
// 	return 0;
// }

int dtld_mmap(struct ib_ucontext *context, struct vm_area_struct *vma) {
	int err;
	struct rdma_user_mmap_entry *ummap_ent;
	struct dtld_rdma_user_mmap_entry *dtld_ummap_ent;
	pgprot_t prot;

	ummap_ent = rdma_user_mmap_entry_get(context, vma);
	if (!ummap_ent)
		return -EINVAL;
	dtld_ummap_ent = to_dtld_mmap_entry(ummap_ent);

	prot = pgprot_device(vma->vm_page_prot);
	err = rdma_user_mmap_io(context, vma, PFN_DOWN(dtld_ummap_ent->address), PAGE_SIZE,
				prot, ummap_ent);

	return err;
}

static const struct ib_device_ops dtld_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_UNKNOWN,  // TODO: Change this to ourselves' when we have one.
	.uverbs_abi_ver = DTLD_UVERBS_ABI_VERSION,

	// .alloc_hw_port_stats = dtld_ib_alloc_hw_port_stats,
	// .alloc_mr = dtld_alloc_mr,
	// .alloc_mw = dtld_alloc_mw,
	.alloc_pd = dtld_alloc_pd,
	.alloc_ucontext = dtld_alloc_ucontext,
	// .attach_mcast = dtld_attach_mcast,
	// .create_ah = dtld_create_ah,
	.create_cq = dtld_create_cq,
	.create_qp = dtld_create_qp,
	// .create_srq = dtld_create_srq,
	// .create_user_ah = dtld_create_ah,
	// .dealloc_driver = dtld_dealloc,
	// .dealloc_mw = dtld_dealloc_mw,
	.dealloc_pd = dtld_dealloc_pd,
	.dealloc_ucontext = dtld_dealloc_ucontext,
	.dereg_mr = dtld_dereg_mr,
	// .destroy_ah = dtld_destroy_ah,
	.destroy_cq = dtld_destroy_cq,
	.destroy_qp = dtld_destroy_qp,
	// .destroy_srq = dtld_destroy_srq,
	// .detach_mcast = dtld_detach_mcast,
	// .device_group = &dtld_attr_group,
	// .enable_driver = dtld_enable_driver,
	// .get_dma_mr = dtld_get_dma_mr,
	// .get_hw_stats = dtld_ib_get_hw_stats,
	.get_link_layer = dtld_get_link_layer,
	.get_port_immutable = dtld_port_immutable,
	// .map_mr_sg = dtld_map_mr_sg,
	.mmap = dtld_mmap,
	// .modify_ah = dtld_modify_ah,
	// .modify_device = dtld_modify_device,
	// .modify_port = dtld_modify_port,
	.modify_qp = dtld_modify_qp,
	// .modify_srq = dtld_modify_srq,
	.peek_cq = dtld_peek_cq,
	.poll_cq = dtld_poll_cq,
	.post_recv = dtld_post_recv,
	.post_send = dtld_post_send,
	// .post_srq_recv = dtld_post_srq_recv,
	// .query_ah = dtld_query_ah,
	.query_device = dtld_query_device,
	// .query_pkey = dtld_query_pkey,
	.query_port = dtld_query_port,
	.query_qp = dtld_query_qp,
	// .query_srq = dtld_query_srq,
	.reg_user_mr = dtld_reg_user_mr,
	// .req_notify_cq = dtld_req_notify_cq,
	// .resize_cq = dtld_resize_cq,

	INIT_RDMA_OBJ_SIZE(ib_ah, dtld_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, dtld_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, dtld_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_qp, dtld_qp, ibqp),
	// INIT_RDMA_OBJ_SIZE(ib_srq, dtld_srq, ibsrq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, dtld_ucontext, ibuc),
	// INIT_RDMA_OBJ_SIZE(ib_mw, dtld_mw, ibmw),
};

int dtld_register_device(struct dtld_dev *dtld, const char *ibdev_name)
{
	int err;
	struct ib_device *dev = &dtld->ib_dev;

	dev->phys_port_cnt = 1;
	dev->num_comp_vectors = num_possible_cpus();

	ib_set_device_ops(dev, &dtld_dev_ops);

	// After running this line, an new entry will show in user cmd: `rdma link show`
	err = ib_register_device(dev, ibdev_name, NULL);
	if (err)
		pr_warn("%s failed with error %d\n", __func__, err);

	return err;
}


void dtld_unregister_device(struct dtld_dev *dtld)
{
	ib_unregister_device(&dtld->ib_dev);
	ib_dealloc_device(&dtld->ib_dev);
	
}