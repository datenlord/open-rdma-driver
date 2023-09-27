// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "asm-generic/errno-base.h"
#include "asm/page_types.h"
#include "linux/errno.h"
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
	struct dtld_dev *rxe = dtld_from_ibdev(dev);
	

	/* *attr being zeroed by the caller, avoid zeroing it here */
	*attr = rxe->port.attr;


	// TODO: port state should be changed according to real hardware status, not hardcoded.

	// TODO: need lock here?

	attr->state = IB_PORT_ACTIVE;
	attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;

	return 0;
}

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
	struct dtld_ucontext *uc = to_dtld_uc(ibuc);
	dtld_put(uc);
}

static int dtld_port_immutable(struct ib_device *dev, u32 port_num,
			      struct ib_port_immutable *immutable)
{
	int err;
	struct ib_port_attr attr;

	// TODO: check if this flag is right
	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;

	err = ib_query_port(dev, port_num, &attr);
	if (err)
		return err;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

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

static int get_qp_ucmd(struct dtld_dev *dtld, struct ib_udata *udata,
		       struct dtld_ureq_create_qp *ucmd)
{
	struct ib_device *ib_dev = &dtld->ib_dev;
	int ret;

	ret = ib_copy_from_udata(ucmd, udata, min(udata->inlen, sizeof(*ucmd)));
	if (ret) {
		ibdev_err(ib_dev, "failed to copy QP udata, ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static int dtld_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init,
			 struct ib_udata *udata)
{
	int err;
	struct dtld_dev *dtld = dtld_from_ibdev(ibqp->device);
	struct dtld_pd *pd = to_dtld_pd(ibqp->pd);
	struct dtld_qp *qp = to_dtld_qp(ibqp);
	struct dtld_ureq_create_qp ucmd = {};
	struct dtld_uresp_create_qp uresp = {};

	if (udata) {
		err = get_qp_ucmd(dtld, udata, &ucmd);
		if (err)
			return err;
		if (udata->outlen < sizeof(uresp))
			return -EINVAL;
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

	err = dtld_qp_from_init(dtld, qp, pd, ibqp->pd, init, udata, &uresp);
	if (err)
		goto qp_init;

	err = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
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

	// TODO: figure out the relationship between RoCE port and UDP port

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

static int dtld_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			 const struct ib_send_wr **bad_wr)
{
	// TODO: not supported in kernel now, support when our userspace driver is stable.
	return 0;
}


static int dtld_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
			 const struct ib_recv_wr **bad_wr)
{
	// TODO: not supported in kernel now, support when our userspace driver is stable.
	return 0;
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


static int dtld_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	// TODO: not supported in kernel now, support when our userspace driver is stable.
	return -ENOTSUPP;
}

static int dtld_peek_cq(struct ib_cq *ibcq, int wc_cnt)
{
	// TODO: not supported in kernel now, support when our userspace driver is stable.
	return -ENOTSUPP;
}

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