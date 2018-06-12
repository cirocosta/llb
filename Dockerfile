FROM golang:1.10-stretch

RUN set -x && \
        apt update -y && \
        apt install -y \
                bc \
                bison \
                clang \
                flex \
                gcc \
                gcc-multilib \
                git \
                libbfd \
                libcap-dev \
                libelf-dev \
                libncurses5-dev \
                libssl-dev \
                llvm \
                make \
                pkg-config


RUN set -x && \
        git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git && \
        cd ./iproute2 && \
        ./configure && \
        make install && \
        install -m 0644 ./include/bpf_api.h /usr/include/iproute2

ADD ./ /go/src/github.com/cirocosta/llb/
WORKDIR /go/src/github.com/cirocosta/llb/

RUN set -x && \
        make
