#!/bin/bash

set -o errexit
set -o xtrace

main() {
  setup_llvm_repo
  setup_apt_deps
  setup_iproute2
}

setup_llvm_repo() {
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

  echo "# 6.0
deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-6.0 main
deb-src http://apt.llvm.org/trusty/ llvm-toolchain-trusty-6.0 main
deb http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu trusty main" |
    sudo tee --append /etc/apt/sources.list
}

setup_apt_deps() {
  sudo apt update -y
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
