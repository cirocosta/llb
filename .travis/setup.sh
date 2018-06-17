#!/bin/bash

set -o errexit
set -o xtrace

main() {
  setup_apt_deps
  setup_iproute2
}

setup_apt_deps() {
  sudo apt install -y \
    bc \
    binutils-dev \
    bison \
    clang \
    flex \
    gcc \
    gcc-multilib \
    git \
    libcap-dev \
    libelf-dev \
    libncurses5-dev \
    libssl-dev \
    llvm \
    make \
    pkg-config
}

setup_iproute2() {
  pushd .
  git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git
  cd ./iproute2
  sudo install -m 0644 ./include/bpf_api.h /usr/include/iproute2
  popd
}

main
