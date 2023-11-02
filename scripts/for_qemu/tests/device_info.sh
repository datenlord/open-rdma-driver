#!/bin/env bash

output=$(/workspaces/open-rdma-driver/rdma-core/build/bin/ibv_devinfo)

echo "$output"

if echo "$output" | grep -q "dtld-dev"; then
    echo "RDMA device dtld-dev found"
    exit 0
else
    echo "RDMA device dtld-dev not found"
    exit 1
fi
