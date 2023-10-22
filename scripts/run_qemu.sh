#!/bin/env bash

set -x

GIT_DIR=$(cd $(dirname $0)/..; pwd)
BUILD_DIR=${GIT_DIR}/.build

PCIE_ROOT_SLOT_NUM="1"
RP_PCIE_SLOT_NUM="0"
RP_CHAN_NUM="0"

:"${BDF:=02:00.0}"
:"${KERNEL_IMG:=/linux-src/arch/x86_64/boot/bzImage}"

CUR_USER=${USER:-root}

sh -c 'echo "10ee 903f" > /sys/bus/pci/drivers/vfio-pci/new_id'

group_number=$(readlink /sys/bus/pci/devices/0000:$BDF/iommu_group | awk -F'/' '{print $NF}')

sh -c "chown $CUR_USER /dev/vfio/$group_number"

qemu_args=""
qemu_args="$qemu_args -m 4G -smp 4 -display none -enable-kvm -cpu host"
qemu_args="$qemu_args -M q35,accel=kvm,kernel-irqchip=split"
qemu_args="$qemu_args -device intel-iommu,intremap=on,device-iotlb=on"
qemu_args="$qemu_args -kernel $KERNEL_IMG"
qemu_args="$qemu_args -append \"root=/dev/sda rootwait console=tty1 console=ttyS0 intel_iommu=on ip=10.0.2.15::10.0.2.1:255.255.255.0 nokaslr\""
qemu_args="$qemu_args -drive file=/rootfs.qcow2"
qemu_args="$qemu_args -fsdev local,security_model=passthrough,id=fsdev0,multidevs=remap,path=/"
qemu_args="$qemu_args -device virtio-9p-pci,fsdev=fsdev0,mount_tag=hostshare"
qemu_args="$qemu_args -netdev user,id=n1 -device virtio-net-pci,netdev=n1"
qemu_args="$qemu_args -machine-path ${BUILD_DIR}"
qemu_args="$qemu_args -device ioh3420,id=rootport1,slot=${PCIE_ROOT_SLOT_NUM}"
qemu_args="$qemu_args -device remote-port-pci-adaptor,bus=rootport1,id=rp0"
qemu_args="$qemu_args -device remote-port-pcie-root-port,id=rprootport,slot=${RP_PCIE_SLOT_NUM},rp-adaptor0=rp,rp-chan0=${RP_CHAN_NUM}"
qemu_args="$qemu_args -serial mon:stdio"
qemu_args="$qemu_args -s"

if [ -n "$ATTACH_PCI" ]; then
   qemu_args="$qemu_args -device vfio-pci,host=$BDF,multifunction=on"
fi

killall -u ${USER} xdma-demo qemu-system-x86_64 &>/dev/null || true

LD_LIBRARY_PATH=${BUILD_DIR}/systemc-2.3.3/lib-linux64/ ${BUILD_DIR}/xdma-demo unix:${BUILD_DIR}/qemu-rport-_machine_peripheral_rp0_rp 10000 & disown;
sleep 1
eval qemu-system-x86_64 $qemu_args
