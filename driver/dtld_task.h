/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef DTLD_TASK_H
#define DTLD_TASK_H

enum {
	TASK_STATE_START	= 0,
	TASK_STATE_BUSY		= 1,
	TASK_STATE_ARMED	= 2,
};

/*
 * data structure to describe a 'task' which is a short
 * function that returns 0 as long as it needs to be
 * called again.
 */
struct dtld_task {
	void			*obj;
	struct tasklet_struct	tasklet;
	int			state;
	spinlock_t		state_lock; /* spinlock for task state */
	void			*arg;
	int			(*func)(void *arg);
	int			ret;
	char			name[16];
	bool			destroyed;
};

/*
 * init dtld_task structure
 *	arg  => parameter to pass to fcn
 *	func => function to call until it returns != 0
 */
int dtld_init_task(void *obj, struct dtld_task *task,
		  void *arg, int (*func)(void *), char *name);

/* cleanup task */
void dtld_cleanup_task(struct dtld_task *task);

/*
 * raw call to func in loop without any checking
 * can call when tasklets are disabled
 */
int __dtld_do_task(struct dtld_task *task);

/*
 * common function called by any of the main tasklets
 * If there is any chance that there is additional
 * work to do someone must reschedule the task before
 * leaving
 */
void dtld_do_task(struct tasklet_struct *t);

/* run a task, else schedule it to run as a tasklet, The decision
 * to run or schedule tasklet is based on the parameter sched.
 */
void dtld_run_task(struct dtld_task *task, int sched);

/* keep a task from scheduling */
void dtld_disable_task(struct dtld_task *task);

/* allow task to run */
void dtld_enable_task(struct dtld_task *task);

#endif /* DTLD_TASK_H */
