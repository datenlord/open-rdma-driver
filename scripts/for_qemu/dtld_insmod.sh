#!/bin/env bash

# make -C /host/linux-src INSTALL_MOD_PATH=/ modules_install

GIT_DIR=$(cd $(dirname $0)/../..; pwd)

modprobe ib_core
modprobe ib_uverbs
insmod ${GIT_DIR}/driver/dtld_ib.ko
