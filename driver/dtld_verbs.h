#ifndef DTLD_VERBS_H
#define DTLD_VERBS_H

#include <rdma/ib_verbs.h>


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
};

struct dtld_ucontext {
	struct ib_ucontext ibuc;
	// struct rxe_pool_elem	elem;
};

static inline struct dtld_dev *dtld_from_ibdev(struct ib_device *dev)
{
	return dev ? container_of(dev, struct dtld_dev, ib_dev) : NULL;
}

int dtld_register_device(struct dtld_dev *dtld, const char *ibdev_name);
void dtld_unregister_device(struct dtld_dev *dtld);

#endif