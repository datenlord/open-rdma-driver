
#include <linux/slab.h>
#include <linux/bug.h>
#include "xdma.h"

static int xpdev_cnt;

struct xdma_pci_dev *xpdev_alloc(struct pci_dev *pdev)
{
	struct xdma_pci_dev *xpdev = kmalloc(sizeof(*xpdev), GFP_KERNEL);

	if (!xpdev)
		return NULL;
	memset(xpdev, 0, sizeof(*xpdev));

	xpdev->magic = MAGIC_DEVICE;
	xpdev->pdev = pdev;

	xpdev_cnt++;
	return xpdev;
}