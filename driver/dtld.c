#include <rdma/rdma_netlink.h>
#include <net/addrconf.h>
#include <linux/pci.h>
#include "linux/container_of.h"
#include "xdma.h"
#include "dtld.h"

MODULE_AUTHOR("Eli Cohen <eli@mellanox.com>");
MODULE_DESCRIPTION("Mellanox 5th generation network adapters (ConnectX series) IB driver");
MODULE_LICENSE("Dual BSD/GPL");

static const struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(0x10ee, 0x903f), }, // XDMA
	{0,}
};

MODULE_DEVICE_TABLE(pci, pci_ids);

/* initialize dtld device parameters */
static void dtld_init_device_param(struct dtld_dev *dtld)
{
	dtld->attr.vendor_id			= DTLD_VENDOR_ID;
	dtld->attr.max_mr_size			= DTLD_MAX_MR_SIZE;
	dtld->attr.page_size_cap			= DTLD_PAGE_SIZE_CAP;
	dtld->attr.max_qp			= DTLD_MAX_QP;
	dtld->attr.max_qp_wr			= DTLD_MAX_QP_WR;
	dtld->attr.device_cap_flags		= DTLD_DEVICE_CAP_FLAGS;
	dtld->attr.kernel_cap_flags		= IBK_ALLOW_USER_UNREG;
	dtld->attr.max_send_sge			= DTLD_MAX_SGE;
	dtld->attr.max_recv_sge			= DTLD_MAX_SGE;
	dtld->attr.max_sge_rd			= DTLD_MAX_SGE_RD;
	dtld->attr.max_cq			= DTLD_MAX_CQ;
	dtld->attr.max_cqe			= (1 << DTLD_MAX_LOG_CQE) - 1;
	dtld->attr.max_mr			= DTLD_MAX_MR;
	dtld->attr.max_mw			= DTLD_MAX_MW;
	dtld->attr.max_pd			= DTLD_MAX_PD;
	dtld->attr.max_qp_rd_atom		= DTLD_MAX_QP_RD_ATOM;
	dtld->attr.max_res_rd_atom		= DTLD_MAX_RES_RD_ATOM;
	dtld->attr.max_qp_init_rd_atom		= DTLD_MAX_QP_INIT_RD_ATOM;
	dtld->attr.atomic_cap			= IB_ATOMIC_HCA;
	dtld->attr.max_mcast_grp			= DTLD_MAX_MCAST_GRP;
	dtld->attr.max_mcast_qp_attach		= DTLD_MAX_MCAST_QP_ATTACH;
	dtld->attr.max_total_mcast_qp_attach	= DTLD_MAX_TOT_MCAST_QP_ATTACH;
	dtld->attr.max_ah			= DTLD_MAX_AH;
	dtld->attr.max_srq			= DTLD_MAX_SRQ;
	dtld->attr.max_srq_wr			= DTLD_MAX_SRQ_WR;
	dtld->attr.max_srq_sge			= DTLD_MAX_SRQ_SGE;
	dtld->attr.max_fast_reg_page_list_len	= DTLD_MAX_FMR_PAGE_LIST_LEN;
	dtld->attr.max_pkeys			= DTLD_MAX_PKEYS;
	dtld->attr.local_ca_ack_delay		= DTLD_LOCAL_CA_ACK_DELAY;
	// addrconf_addr_eui48((unsigned char *)&dtld->attr.sys_image_guid,
	// 		dtld->ndev->dev_addr);

	// dtld->max_ucontext			= DTLD_MAX_UCONTEXT;
}

/* init pools of managed objects */
static void dtld_init_pools(struct dtld_dev *dtld)
{
	dtld_pool_init(dtld, &dtld->uc_pool, DTLD_TYPE_UC);
	dtld_pool_init(dtld, &dtld->pd_pool, DTLD_TYPE_PD);
	dtld_pool_init(dtld, &dtld->ah_pool, DTLD_TYPE_AH);
	// dtld_pool_init(dtld, &dtld->srq_pool, DTLD_TYPE_SRQ);
	dtld_pool_init(dtld, &dtld->qp_pool, DTLD_TYPE_QP);
	dtld_pool_init(dtld, &dtld->cq_pool, DTLD_TYPE_CQ);
	dtld_pool_init(dtld, &dtld->mr_pool, DTLD_TYPE_MR);
	// dtld_pool_init(dtld, &dtld->mw_pool, DTLD_TYPE_MW);
}

/* initialize port attributes */
static void dtld_init_port_param(struct dtld_port *port)
{
	// TODO: change these attrs according to real hardware
	
	// port->attr.state		= IB_PORT_DOWN;
	// port->attr.max_mtu		= IB_MTU_4096;
	// port->attr.active_mtu		= IB_MTU_256;
	// port->attr.gid_tbl_len		= DTLD_PORT_GID_TBL_LEN;
	// port->attr.port_cap_flags	= DTLD_PORT_PORT_CAP_FLAGS;
	// port->attr.max_msg_sz		= DTLD_PORT_MAX_MSG_SZ;
	// port->attr.bad_pkey_cntr	= DTLD_PORT_BAD_PKEY_CNTR;
	// port->attr.qkey_viol_cntr	= DTLD_PORT_QKEY_VIOL_CNTR;
	// port->attr.pkey_tbl_len		= DTLD_PORT_PKEY_TBL_LEN;
	// port->attr.lid			= DTLD_PORT_LID;
	// port->attr.sm_lid		= DTLD_PORT_SM_LID;
	// port->attr.lmc			= DTLD_PORT_LMC;
	// port->attr.max_vl_num		= DTLD_PORT_MAX_VL_NUM;
	// port->attr.sm_sl		= DTLD_PORT_SM_SL;
	// port->attr.subnet_timeout	= DTLD_PORT_SUBNET_TIMEOUT;
	// port->attr.init_type_reply	= DTLD_PORT_INIT_TYPE_REPLY;
	// port->attr.active_width		= DTLD_PORT_ACTIVE_WIDTH;
	// port->attr.active_speed		= DTLD_PORT_ACTIVE_SPEED;
	// port->attr.phys_state		= DTLD_PORT_PHYS_STATE;
	// port->mtu_cap			= ib_mtu_enum_to_int(IB_MTU_256);
	// port->subnet_prefix		= cpu_to_be64(DTLD_PORT_SUBNET_PREFIX);
}

static void dtld_init_ports(struct dtld_dev *dtld)
{
	struct dtld_port *port = &dtld->port;

	dtld_init_port_param(port);
	// addrconf_addr_eui48((unsigned char *)&port->port_guid,
	// 		    dtld->ndev->dev_addr);
	spin_lock_init(&port->port_lock);
}


static int dtld_dev_init_xdma(struct pci_dev *pdev, const struct pci_device_id *id, struct xdma_dev **xdev)
{
	int rv = 0;
	struct xdma_pci_dev *xpdev = NULL;
	void *hndl;
	pr_info("dtld probe one");

	// TODO: why not move xpdev alloc into `xdma_device_open` and make it an atomic one?
	// and why multi xdev may bind to the same pdev? I think we should refactor it soon.
	xpdev = xpdev_alloc(pdev);
	if (!xpdev)
		return -ENOMEM;

	hndl = xdma_device_open("xdma", pdev);
	if (!hndl) {
		rv = -EINVAL;
		goto err_out;
	}

	/* make sure no duplicate */
	*xdev = xdev_find_by_pdev(pdev);
	if (!*xdev) {
		pr_warn("NO xdev found!\n");
		rv =  -EINVAL;
		goto err_out;
	}

	if (hndl != *xdev) {
		pr_err("xdev handle mismatch\n");
		kfree(hndl);
		rv =  -EINVAL;
		goto err_out;
	}

	xpdev->xdev = hndl;

	dev_set_drvdata(&pdev->dev, xpdev);
	return 0;

err_out:
	xpdev_free(xpdev);
	return rv;
}

static int dtld_dev_init_rdma(struct xdma_dev *xdev)
{
	int err;

	struct dtld_dev *dtld = NULL;

	dtld = ib_alloc_device(dtld_dev, ib_dev);

	dtld->xdev = xdev;
	xdev->dtld = dtld;

	dtld_init_pools(dtld);

	dtld_init_device_param(dtld);
	dtld_init_ports(dtld);

	err = dtld_register_device(dtld, "dtld-dev");

	if (err){
		pr_warn("%s failed with error %d\n", __func__, err);
		ib_dealloc_device(&dtld->ib_dev);
	}

	return err;
}

static int probe_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int err;
	struct xdma_dev *xdev = NULL;

	err = dtld_dev_init_xdma(pdev, id, &xdev);
	if (err)
		return err;

	err = dtld_dev_init_rdma(xdev);
	if (err)
		return err;

	return 0;
}

static void remove_one(struct pci_dev *pdev)
{
	struct xdma_pci_dev *xpdev;

	if (!pdev)
		return;

	xpdev = dev_get_drvdata(&pdev->dev);
	if (!xpdev)
		return;
	
	dtld_unregister_device(xpdev->xdev->dtld);
	

	xpdev_free(xpdev);
	dev_set_drvdata(&pdev->dev, NULL);
}

static struct pci_driver pci_driver = {
	.name = "dtld",
	.id_table = pci_ids,
	.probe = probe_one,
	.remove = remove_one,
};

static int __init dtld_ib_init(void)
{
	return pci_register_driver(&pci_driver);
}

static void __exit dtld_ib_cleanup(void)
{
	pci_unregister_driver(&pci_driver);
}

module_init(dtld_ib_init);
module_exit(dtld_ib_cleanup);
