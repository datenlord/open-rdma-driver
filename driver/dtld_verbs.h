#ifndef DTLD_VERBS_H
#define DTLD_VERBS_H

#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include "rdma/rdma_user_dtld.h"
#include "dtld_pool.h"


struct dtld_port {
	struct ib_port_attr	attr;
	__be64			port_guid;
	__be64			subnet_prefix;
	spinlock_t		port_lock; /* guard port */
	unsigned int		mtu_cap;
	/* special QPs */
	u32			qp_gsi_index;
};

struct dtld_dev {
	struct ib_device	ib_dev;
	struct ib_device_attr	attr;
	struct dtld_port		port;

	struct dtld_pool		cq_pool;
	struct dtld_pool		pd_pool;
	struct dtld_pool		mr_pool;
};

struct dtld_ucontext {
	struct ib_ucontext ibuc;
	struct dtld_pool_elem	elem;
};

struct dtld_pd {
	struct ib_pd            ibpd;
	struct dtld_pool_elem	elem;
};

struct dtld_cqe {
	union {
		struct ib_wc		ibwc;
		struct ib_uverbs_wc	uibwc;
	};
};

struct dtld_cq {
	struct ib_cq		ibcq;
	struct dtld_pool_elem	elem;
	struct dtld_queue	*queue;
	spinlock_t		cq_lock;
	u8			notify;
	bool			is_dying;
	bool			is_user;
	struct tasklet_struct	comp_task;
	atomic_t		num_wq;
};

enum dtld_mr_state {
	DTLD_MR_STATE_INVALID,
	DTLD_MR_STATE_FREE,
	DTLD_MR_STATE_VALID,
};

struct dtld_mr {
	struct dtld_pool_elem	elem;
	struct ib_mr		ibmr;

	struct ib_umem		*umem;

	u32			lkey;
	u32			rkey;
	enum dtld_mr_state	state;
	enum ib_mr_type		type;
	int			access;

	// int			map_shift;
	// int			map_mask;

	u32			num_buf;

	u32			max_buf;
	u32			num_map;

	atomic_t		num_mw;

	struct dtld_map_set	*cur_map_set;
	struct dtld_map_set	*next_map_set;
};

static inline struct dtld_cq *to_dtld_cq(struct ib_cq *cq)
{
	return cq ? container_of(cq, struct dtld_cq, ibcq) : NULL;
}

static inline struct dtld_pd *to_dtld_pd(struct ib_pd *pd)
{
	return pd ? container_of(pd, struct dtld_pd, ibpd) : NULL;
}

static inline struct dtld_dev *dtld_from_ibdev(struct ib_device *dev)
{
	return dev ? container_of(dev, struct dtld_dev, ib_dev) : NULL;
}

int dtld_register_device(struct dtld_dev *dtld, const char *ibdev_name);
void dtld_unregister_device(struct dtld_dev *dtld);

#endif