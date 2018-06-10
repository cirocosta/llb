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
