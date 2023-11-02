#!/bin/env bash

set -o errexit
set -o nounset

GIT_DIR=$(cd $(dirname $0)/..; pwd)
BUILD_DIR=${GIT_DIR}/.build
mkdir -p ${BUILD_DIR}

cd ${BUILD_DIR}

if [ ! -d "${BUILD_DIR}/systemc-2.3.3" ]; then
    wget -q https://www.accellera.org/images/downloads/standards/systemc/systemc-2.3.3.tar.gz && tar xzf systemc-2.3.3.tar.gz
    cd systemc-2.3.3
    ./configure --prefix=${BUILD_DIR}/systemc-2.3.3
    make -j
    make install
fi

pushd ${GIT_DIR}/DistroSim
cat <<EOF > .config.mk
SYSTEMC=${BUILD_DIR}/systemc-2.3.3
EOF
cat .config.mk
make pcie/versal/xdma-demo
mv pcie/versal/xdma-demo ${BUILD_DIR}/
popd
