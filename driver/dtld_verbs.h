#ifndef DTLD_VERBS_H
#define DTLD_VERBS_H

#include "dtld_pool.h"
#include "dtld_task.h"
#include "dtld_queue.h"

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

	int			max_inline_data;

	struct dtld_pool		uc_pool;
	struct dtld_pool		ah_pool;
	struct dtld_pool		qp_pool;
	struct dtld_pool		cq_pool;
	struct dtld_pool		pd_pool;
	struct dtld_pool		mr_pool;
};

enum dtld_qp_state {
	QP_STATE_RESET,
	QP_STATE_INIT,
	QP_STATE_READY,
	QP_STATE_DRAIN,		/* req only */
	QP_STATE_DRAINED,	/* req only */
	QP_STATE_ERROR
};

struct dtld_req_info {
	enum dtld_qp_state	state;
	int			wqe_index;
	u32			psn;
	int			opcode;
	atomic_t		rd_atomic;
	int			wait_fence;
	int			need_rd_atomic;
	int			wait_psn;
	int			need_retry;
	int			noack_pkts;
	struct dtld_task		task;
};

struct dtld_comp_info {
	u32			psn;
	int			opcode;
	int			timeout;
	int			timeout_retry;
	int			started_retry;
	u32			retry_cnt;
	u32			rnr_retry;
	struct dtld_task		task;
};

enum rdatm_res_state {
	rdatm_res_state_next,
	rdatm_res_state_new,
	rdatm_res_state_replay,
};

struct dtld_resp_info {
	enum dtld_qp_state	state;
	u32			msn;
	u32			psn;
	u32			ack_psn;
	int			opcode;
	int			drop_msg;
	int			goto_error;
	int			sent_psn_nak;
	enum ib_wc_status	status;
	u8			aeth_syndrome;

	/* Receive only */
	struct dtld_recv_wqe	*wqe;

	/* RDMA read / atomic only */
	u64			va;
	u64			offset;
	struct dtld_mr		*mr;
	u32			resid;
	u32			rkey;
	u32			length;
	u64			atomic_orig;

	/* SRQ only */
	struct {
		struct dtld_recv_wqe	wqe;
		struct ib_sge		sge[DTLD_MAX_SGE];
	} srq_wqe;

	/* Responder resources. It's a circular list where the oldest
	 * resource is dropped first.
	 */
	struct resp_res		*resources;
	unsigned int		res_head;
	unsigned int		res_tail;
	struct resp_res		*res;
	struct dtld_task		task;
};


struct dtld_ucontext {
	struct ib_ucontext ibuc;
	struct dtld_pool_elem	elem;
};

struct dtld_pd {
	struct ib_pd            ibpd;
	struct dtld_pool_elem	elem;
};

struct dtld_ah {
	struct ib_ah		ibah;
	struct dtld_pool_elem	elem;
	struct dtld_av		av;
	bool			is_user;
	int			ah_num;
};

enum wqe_state {
	wqe_state_posted,
	wqe_state_processing,
	wqe_state_pending,
	wqe_state_done,
	wqe_state_error,
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

struct dtld_sq {
	int			max_wr;
	int			max_sge;
	int			max_inline;
	spinlock_t		sq_lock; /* guard queue */
	struct dtld_queue	*queue;
};

struct dtld_rq {
	int			max_wr;
	int			max_sge;
	spinlock_t		producer_lock; /* guard queue producer */
	spinlock_t		consumer_lock; /* guard queue consumer */
	struct dtld_queue	*queue;
};

struct dtld_srq {
	struct ib_srq		ibsrq;
	struct dtld_pool_elem	elem;
	struct dtld_pd		*pd;
	struct dtld_rq		rq;
	u32			srq_num;

	int			limit;
	int			error;
};

struct resp_res {
	int			type;
	int			replay;
	u32			first_psn;
	u32			last_psn;
	u32			cur_psn;
	enum rdatm_res_state	state;

	union {
		struct {
			struct sk_buff	*skb;
		} atomic;
		struct {
			u64		va_org;
			u32		rkey;
			u32		length;
			u64		va;
			u32		resid;
		} read;
	};
};

struct dtld_qp {
	struct ib_qp		ibqp;
	struct dtld_pool_elem	elem;
	struct ib_qp_attr	attr;
	unsigned int		valid;
	unsigned int		mtu;
	bool			is_user;

	struct dtld_pd		*pd;
	struct dtld_srq		*srq;
	struct dtld_cq		*scq;
	struct dtld_cq		*rcq;

	enum ib_sig_type	sq_sig_type;

	struct dtld_sq		sq;
	struct dtld_rq		rq;

	// struct socket		*sk;  // seems related to simulated nic
	u32			dst_cookie;
	// u16			src_port;   // seems related to simulated nic

	struct dtld_av		pri_av;
	struct dtld_av		alt_av;

	atomic_t		mcg_num;

	// struct sk_buff_head	req_pkts;
	// struct sk_buff_head	resp_pkts;

	struct dtld_req_info	req;
	struct dtld_comp_info	comp;
	struct dtld_resp_info	resp;

	atomic_t		ssn;
	atomic_t		skb_out;
	int			need_req_skb;

	/* Timer for retranmitting packet when ACKs have been lost. RC
	 * only. The requester sets it when it is not already
	 * started. The responder resets it whenever an ack is
	 * received.
	 */
	struct timer_list retrans_timer;
	u64 qp_timeout_jiffies;

	/* Timer for handling RNR NAKS. */
	struct timer_list rnr_nak_timer;

	spinlock_t		state_lock; /* guard requester and completer */

	struct execute_work	cleanup_work;
};

#define DTLD_BUF_PER_MAP		(PAGE_SIZE / sizeof(struct dtld_phys_buf))

struct dtld_phys_buf {
	u64      addr;
	u64      size;
};

struct dtld_map {
	struct dtld_phys_buf	buf[DTLD_BUF_PER_MAP];
};

struct dtld_map_set {
	struct dtld_map		**map;
	u64			va;
	u64			iova;
	size_t			length;
	u32			offset;
	u32			nbuf;
	int			page_shift;
	int			page_mask;
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

static inline struct dtld_ucontext *to_dtld_uc(struct ib_ucontext *uc)
{
	return uc ? container_of(uc, struct dtld_ucontext, ibuc) : NULL;
}

static inline struct dtld_ah *to_dtld_ah(struct ib_ah *ah)
{
	return ah ? container_of(ah, struct dtld_ah, ibah) : NULL;
}

static inline struct dtld_qp *to_dtld_qp(struct ib_qp *qp)
{
	return qp ? container_of(qp, struct dtld_qp, ibqp) : NULL;
}

static inline struct dtld_srq *to_dtld_srq(struct ib_srq *srq)
{
	return srq ? container_of(srq, struct dtld_srq, ibsrq) : NULL;
}

static inline struct dtld_cq *to_dtld_cq(struct ib_cq *cq)
{
	return cq ? container_of(cq, struct dtld_cq, ibcq) : NULL;
}

static inline struct dtld_mr *to_dtld_mr(struct ib_mr *mr)
{
	return mr ? container_of(mr, struct dtld_mr, ibmr) : NULL;
}

static inline struct dtld_pd *to_dtld_pd(struct ib_pd *pd)
{
	return pd ? container_of(pd, struct dtld_pd, ibpd) : NULL;
}

static inline struct dtld_dev *dtld_from_ibdev(struct ib_device *dev)
{
	return dev ? container_of(dev, struct dtld_dev, ib_dev) : NULL;
}

static inline struct dtld_pd *dtld_mr_pd(struct dtld_mr *mr)
{
	return to_dtld_pd(mr->ibmr.pd);
}

static inline struct dtld_pd *dtld_ah_pd(struct dtld_ah *ah)
{
	return to_dtld_pd(ah->ibah.pd);
}


int dtld_register_device(struct dtld_dev *dtld, const char *ibdev_name);
void dtld_unregister_device(struct dtld_dev *dtld);

#endif