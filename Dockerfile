FROM ubuntu:bionic

RUN set -x && \
        apt update -y && \
        apt install -y \
                make \
                gcc \
                libssl-dev \
                bc \
                libelf-dev \
                libcap-dev \
                clang \
                gcc-multilib \
                llvm \
                libncurses5-dev \
                git \
                pkg-config \
                bison \
                flex

RUN set -x && \
        git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git && \
        cd ./iproute2 && \
        ./configure && \
        make install
