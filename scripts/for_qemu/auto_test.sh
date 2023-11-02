#!/bin/env bash

set -o pipefail

if [ -e "/workspaces/open-rdma-driver/.build/non_interactive" ]; then
    rm -rf /workspaces/open-rdma-driver/.build/non_interactive
    rm -rf /workspaces/open-rdma-driver/.build/qemu.log

    bash /workspaces/open-rdma-driver/scripts/for_qemu/dtld_insmod.sh

    for file in /workspaces/open-rdma-driver/scripts/for_qemu/tests/*.sh; do
        if [ -f "$file" ]; then
            echo "testing $file" >> /workspaces/open-rdma-driver/.build/qemu.log
            bash "$file" 2>&1 | tee -a /workspaces/open-rdma-driver/.build/qemu.log
            echo "" >> /workspaces/open-rdma-driver/.build/qemu.log
        fi
    done

    poweroff
fi
