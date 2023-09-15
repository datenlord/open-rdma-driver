// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */
#include <linux/vmalloc.h>
#include <rdma/uverbs_ioctl.h>
#include "dtld.h"
#include "dtld_loc.h"
#include "dtld_queue.h"
#include "rdma/ib_verbs.h"

int dtld_cq_chk_attr(struct dtld_dev *dtld, struct dtld_cq *cq,
		    int cqe, int comp_vector)
{
	int count;

	if (cqe <= 0) {
		pr_warn("cqe(%d) <= 0\n", cqe);
		goto err1;
	}

	if (cqe > dtld->attr.max_cqe) {
		pr_warn("cqe(%d) > max_cqe(%d)\n",
			cqe, dtld->attr.max_cqe);
		goto err1;
	}

	if (cq) {
		count = queue_count(cq->queue, QUEUE_TYPE_TO_CLIENT);
		if (cqe < count) {
			pr_warn("cqe(%d) < current # elements in queue (%d)",
				cqe, count);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

static void dtld_send_complete(struct tasklet_struct *t)
{
	struct dtld_cq *cq = from_tasklet(cq, t, comp_task);
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);
	if (cq->is_dying) {
		spin_unlock_irqrestore(&cq->cq_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&cq->cq_lock, flags);

	cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
}

int dtld_cq_from_init(struct dtld_dev *dtld, struct dtld_cq *cq, int cqe,
		     int comp_vector, struct ib_udata *udata,
		     struct dtld_uresp_create_cq *uresp)
{
	int err;
	struct dtld_ucontext *ctx = rdma_udata_to_drv_context(udata, struct dtld_ucontext, ibuc);
	struct dtld_rdma_user_mmap_entry *ummap_ent;
	void *fake_dev_mem;
	u64 mmap_offset;


	// TODO, only for debug usage now, will be replace to mmio bar address in the future. there is memory leak now, i didn't free it.
	fake_dev_mem = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!fake_dev_mem) 
		return -ENOMEM;

	ummap_ent = kzalloc(sizeof(*ummap_ent), GFP_KERNEL);
	if (!ummap_ent) 
		return -ENOMEM;
	cq->ummap_ent = ummap_ent;

	ummap_ent->address = (u64)virt_to_phys(fake_dev_mem);

	err = rdma_user_mmap_entry_insert(&ctx->ibuc, &ummap_ent->rdma_entry, PAGE_SIZE);
	if (err) {
		kfree(ummap_ent);
		return err;
	}

	mmap_offset = rdma_user_mmap_get_offset(&ummap_ent->rdma_entry);

	// TODO: the hardcoded is only for test, fix me
	uresp->q_offset = mmap_offset;
	uresp->q_length = PAGE_SIZE;
	uresp->num_cqe = 2;
	uresp->cq_id = cq->elem.index;


	// cq->is_dying = false;
	// tasklet_setup(&cq->comp_task, dtld_send_complete);

	spin_lock_init(&cq->cq_lock);
	cq->ibcq.cqe = cqe;
	return 0;
}

// int dtld_cq_resize_queue(struct dtld_cq *cq, int cqe,
// 			struct dtld_resize_cq_resp __user *uresp,
// 			struct ib_udata *udata)
// {
// 	int err;

// 	err = dtld_queue_resize(cq->queue, (unsigned int *)&cqe,
// 			       sizeof(struct dtld_cqe), udata,
// 			       uresp ? &uresp->mi : NULL, NULL, &cq->cq_lock);
// 	if (!err)
// 		cq->ibcq.cqe = cqe;

// 	return err;
// }

// int dtld_cq_post(struct dtld_cq *cq, struct dtld_cqe *cqe, int solicited)
// {
// 	struct ib_event ev;
// 	int full;
// 	void *addr;
// 	unsigned long flags;

// 	spin_lock_irqsave(&cq->cq_lock, flags);

// 	full = queue_full(cq->queue, QUEUE_TYPE_TO_CLIENT);
// 	if (unlikely(full)) {
// 		spin_unlock_irqrestore(&cq->cq_lock, flags);
// 		if (cq->ibcq.event_handler) {
// 			ev.device = cq->ibcq.device;
// 			ev.element.cq = &cq->ibcq;
// 			ev.event = IB_EVENT_CQ_ERR;
// 			cq->ibcq.event_handler(&ev, cq->ibcq.cq_context);
// 		}

// 		return -EBUSY;
// 	}

// 	addr = queue_producer_addr(cq->queue, QUEUE_TYPE_TO_CLIENT);
// 	memcpy(addr, cqe, sizeof(*cqe));

// 	queue_advance_producer(cq->queue, QUEUE_TYPE_TO_CLIENT);

// 	spin_unlock_irqrestore(&cq->cq_lock, flags);

// 	if ((cq->notify == IB_CQ_NEXT_COMP) ||
// 	    (cq->notify == IB_CQ_SOLICITED && solicited)) {
// 		cq->notify = 0;
// 		tasklet_schedule(&cq->comp_task);
// 	}

// 	return 0;
// }

void dtld_cq_disable(struct dtld_cq *cq)
{
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);
	cq->is_dying = true;
	spin_unlock_irqrestore(&cq->cq_lock, flags);
}

void dtld_cq_cleanup(struct dtld_pool_elem *elem)
{
	struct dtld_cq *cq = container_of(elem, typeof(*cq), elem);

	if (cq->queue)
		dtld_queue_cleanup(cq->queue);
}
