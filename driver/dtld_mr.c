// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "dtld.h"
#include "dtld_loc.h"

#define IB_ACCESS_REMOTE                                                       \
    (IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_ATOMIC)

#define DTLD_MR_KEYTBL_SIZE 64
#define DTLD_MR_PGTBL_SIZE 1024

struct dtld_mr_keytbl_item {
    int offset;
    int size;
    int pg_size;
    void* base_va;
};

struct dtld_mr_pgtbl_free_blk {
    int offset;
    int size;
    struct dtld_mr_pgtbl_free_blk* next;
    struct dtld_mr_pgtbl_free_blk* prev;
};

struct dtld_mr_keytbl_item dtld_mr_keytbl[DTLD_MR_KEYTBL_SIZE];
void* dtld_mr_pgtbl[DTLD_MR_PGTBL_SIZE];
struct dtld_mr_pgtbl_free_blk* dtld_mr_pgtbl_free_blk_list = NULL;

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

static int dtld_mr_pgtbl_alloc(int size) {
    struct dtld_mr_pgtbl_free_blk* curr = dtld_mr_pgtbl_free_blk_list;

    while (curr) {
        if (curr->size >= size) {
            int offset = curr->offset;

            curr->offset += size;
            curr->size -= size;

            if (curr->size == 0) {
                if (curr->prev) {
                    curr->prev->next = curr->next;
                } else {
                    dtld_mr_pgtbl_free_blk_list = curr->next;
                }
                if (curr->next) {
                    curr->next->prev = curr->prev;
                }
                kfree(curr);
            }

            return offset;
        }

        curr = curr->next;
    }

    return -1;
}

static void dtld_mr_pgtbl_dealloc(int offset, int size) {
    struct dtld_mr_pgtbl_free_blk* last = NULL;
    struct dtld_mr_pgtbl_free_blk* curr = dtld_mr_pgtbl_free_blk_list;

    while (curr) {
        if (curr->offset > offset) break;
        last = curr;
        curr = curr->next;
    }

    struct dtld_mr_pgtbl_free_blk* new = (struct dtld_mr_pgtbl_free_blk*)kmalloc(sizeof(struct dtld_mr_pgtbl_free_blk), GFP_KERNEL);
    new->offset = offset;
    new->size = size;
    new->prev = last;
    new->next = curr;

    if (new->prev) {
        new->prev->next = new;
    } else {
        dtld_mr_pgtbl_free_blk_list = new;
    }

    if (new->next) {
        new->next->prev = new;
    }

    while (new->prev) {
        if (new->prev->offset + new->prev->size != new->offset) break;

        new->offset = new->prev->offset;
        new->size += new->prev->size;

        struct dtld_mr_pgtbl_free_blk* new_prev = new->prev->prev;
        kfree(new->prev);

        if (new_prev) {
            new_prev->next = new;
        } else {
            dtld_mr_pgtbl_free_blk_list = new;
        }

        new->prev = new_prev;
    }

    while (new->next) {
        if (new->next->offset != new->offset + new->size) break;

        new->size += new->next->size;

        struct dtld_mr_pgtbl_free_blk* new_next = new->next->next;
        kfree(new->next);

        if (new_next) {
            new_next->prev = new;
        }

        new->next = new_next;
    }
}

static void dtld_mr_pgtbl_map(int offset, void* address, int pg_cnt, int pg_size) {
    for (int i = 0; i < pg_cnt; i++) {
        dtld_mr_pgtbl[offset + i] = virt_to_phys(address + i * pg_size);
    }
}

static int dtld_mr_init(struct dtld_mr *mr, struct ib_umem *umem, u64 length,
                        u64 iova, int access)
{
    /* check if the page table is initialized */
    if (!dtld_mr_pgtbl_free_blk_list) {
        struct dtld_mr_pgtbl_free_blk* init = (struct dtld_mr_pgtbl_free_blk*)kmalloc(sizeof(struct dtld_mr_pgtbl_free_blk), GFP_KERNEL);
        init->offset = 0;
        init->size = DTLD_MR_PGTBL_SIZE;
        init->next = NULL;
        init->prev = NULL;
        dtld_mr_pgtbl_free_blk_list = init;
    }

    unsigned int pgsz = ib_umem_find_best_pgsz(umem, SZ_2G - SZ_4K, iova);
    if (!pgsz)
        return -EINVAL;

    size_t pg_cnt = ib_umem_num_dma_blocks(umem, pgsz);

    int offset = dtld_mr_pgtbl_alloc(pg_cnt);
    if (offset == -1)
        return -ENOMEM;

    dtld_mr_pgtbl_map(offset, (void*)umem->address, pg_cnt, pgsz);

    // TODO: this item should somehow be inserted into dtld_mr_keytbl
    struct dtld_mr_keytbl_item item = {
        .offset = offset,
        .size = pg_cnt,
        .pg_size = pgsz,
        .base_va = (void*)umem->address,
    };

    u32 lkey = mr->elem.index << 8 | dtld_get_next_key(-1);
    u32 rkey = (access & IB_ACCESS_REMOTE) ? lkey : 0;

    /* set ibmr->l/rkey and also copy into private l/rkey
   * for user MRs these will always be the same
   * for cases where caller 'owns' the key portion
   * they may be different until REG_MR WQE is executed.
   */
    mr->lkey = mr->ibmr.lkey = lkey;
    mr->rkey = mr->ibmr.rkey = rkey;

    mr->type = mr->ibmr.type = IB_MR_TYPE_USER;

    mr->ibmr.iova = iova;
    mr->ibmr.length = length;
    mr->ibmr.page_size = pgsz;

    mr->state = DTLD_MR_STATE_INVALID;
    // mr->map_shift = ilog2(DTLD_BUF_PER_MAP);

    mr->access = access;
    mr->state = DTLD_MR_STATE_VALID;

    mr->umem = umem;

    return 0;
}

int dtld_mr_init_user(struct dtld_pd *pd, u64 start, u64 length, u64 iova,
                      int access, struct dtld_mr *mr)
{
    int err;
    struct ib_umem *umem = ib_umem_get(pd->ibpd.device, start, length, access);

    if (IS_ERR(umem)) {
        pr_warn("%s: Unable to pin memory region err = %d\n", __func__,
                (int)PTR_ERR(umem));
        err = PTR_ERR(umem);
        goto err_out;
    }

    mr->ibmr.pd = &pd->ibpd;

    err = dtld_mr_init(mr, umem, length, iova, access);

    if (err)
        goto err_release_umem;

    return 0;

err_release_umem:
    ib_umem_release(umem);
err_out:
    return err;
}

int dtld_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
    struct dtld_mr *mr = to_dtld_mr(ibmr);

    // TODO: the keytbl item index should be somehow retrieved from the key
    int key_tbl_idx = 0;
    struct dtld_mr_keytbl_item* item = &dtld_mr_keytbl[key_tbl_idx];

    dtld_mr_pgtbl_dealloc(item->offset, item->size);
    *item = (struct dtld_mr_keytbl_item){0};

    /* See IBA 10.6.7.2.6 */
    // if (atomic_read(&mr->num_mw) > 0)
    // 	return -EINVAL;

    dtld_put(mr);

    return 0;
}

void dtld_mr_cleanup(struct dtld_pool_elem *elem)
{
    struct dtld_mr *mr = container_of(elem, typeof(*mr), elem);

    dtld_put(dtld_mr_pd(mr));

    ib_umem_release(mr->umem);

    struct dtld_mr_pgtbl_free_blk* curr = dtld_mr_pgtbl_free_blk_list;

    while (curr) {
        struct dtld_mr_pgtbl_free_blk* next = curr->next;
        kfree(curr);
        curr = next;
    }

    // if (mr->cur_map_set)
    // 	dtld_mr_free_map_set(mr->num_map, mr->cur_map_set);

    // if (mr->next_map_set)
    // 	dtld_mr_free_map_set(mr->num_map, mr->next_map_set);
}
