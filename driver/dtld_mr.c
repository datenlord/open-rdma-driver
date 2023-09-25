// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "dtld.h"
#include "dtld_loc.h"

/* Return a random 8 bit key value that is
 * different than the last_key. Set last_key to -1
 * if this is the first key for an MR or MW
 */
u8 dtld_get_next_key(u32 last_key)
{
	u8 key;

	do {
		get_random_bytes(&key, 1);
	} while (key == last_key);

	return key;
}

#define IB_ACCESS_REMOTE	(IB_ACCESS_REMOTE_READ		\
				| IB_ACCESS_REMOTE_WRITE	\
				| IB_ACCESS_REMOTE_ATOMIC)

static void dtld_mr_init(int access, struct dtld_mr *mr)
{
	u32 lkey = mr->elem.index << 8 | dtld_get_next_key(-1);
	u32 rkey = (access & IB_ACCESS_REMOTE) ? lkey : 0;

	/* set ibmr->l/rkey and also copy into private l/rkey
	 * for user MRs these will always be the same
	 * for cases where caller 'owns' the key portion
	 * they may be different until REG_MR WQE is executed.
	 */
	mr->lkey = mr->ibmr.lkey = lkey;
	mr->rkey = mr->ibmr.rkey = rkey;

	mr->state = DTLD_MR_STATE_INVALID;
	// mr->map_shift = ilog2(DTLD_BUF_PER_MAP);
}

static void dtld_mr_free_map_set(int num_map, struct dtld_map_set *set)
{
	int i;

	for (i = 0; i < num_map; i++)
		kfree(set->map[i]);

	kfree(set->map);
	kfree(set);
}


int dtld_mr_init_user(struct dtld_pd *pd, u64 start, u64 length, u64 iova,
		     int access, struct dtld_mr *mr)
{
	struct dtld_map_set	*set;
	struct dtld_map		**map;
	struct dtld_phys_buf	*buf = NULL;
	struct ib_umem		*umem;
	struct sg_page_iter	sg_iter;
	int			num_buf;
	void			*vaddr;
	int err;

	umem = ib_umem_get(pd->ibpd.device, start, length, access);
	if (IS_ERR(umem)) {
		pr_warn("%s: Unable to pin memory region err = %d\n",
			__func__, (int)PTR_ERR(umem));
		err = PTR_ERR(umem);
		goto err_out;
	}

	num_buf = ib_umem_num_pages(umem);

	dtld_mr_init(access, mr);


	mr->ibmr.pd = &pd->ibpd;
	mr->umem = umem;
	mr->access = access;
	mr->state = DTLD_MR_STATE_VALID;
	mr->type = IB_MR_TYPE_USER;

	return 0;

err_release_umem:
	ib_umem_release(umem);
err_out:
	return err;
}


int dtld_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct dtld_mr *mr = to_dtld_mr(ibmr);

	/* See IBA 10.6.7.2.6 */
	if (atomic_read(&mr->num_mw) > 0)
		return -EINVAL;

	dtld_put(mr);

	return 0;
}

void dtld_mr_cleanup(struct dtld_pool_elem *elem)
{
	struct dtld_mr *mr = container_of(elem, typeof(*mr), elem);

	dtld_put(dtld_mr_pd(mr));

	ib_umem_release(mr->umem);

	if (mr->cur_map_set)
		dtld_mr_free_map_set(mr->num_map, mr->cur_map_set);

	if (mr->next_map_set)
		dtld_mr_free_map_set(mr->num_map, mr->next_map_set);
}
