#!/bin/bash

set -o errexit
set -o xtrace

main() {
  case $1 in
  setup)
    setup
    ;;

  clean)
    clean
    ;;

  *)
    echo "Usage: ./setup-routing.sh (setup|clean)"
    exit 1
    ;;
  esac
}

clean() {
  ip -all netns delete
  ip link delete br1 || true
}

setup() {
  ip netns add namespace1
  ip netns add namespace2

  ip link add veth1 type veth peer name br-veth1
  ip link add veth2 type veth peer name br-veth2

  ip link set veth1 netns namespace1
  ip link set veth2 netns namespace2

  ip netns exec namespace1 \
    ip addr add 192.168.1.11/24 dev veth1

  ip netns exec namespace2 \
    ip addr add 192.168.1.12/24 dev veth2

  ip link add name br1 type bridge
  ip link set br1 up

  ip link set br-veth1 up
  ip link set br-veth2 up

  ip netns exec namespace1 \
    ip link set veth1 up
  ip netns exec namespace2 \
    ip link set veth2 up

  ip link set br-veth1 master br1
  ip link set br-veth2 master br1

  ip addr add 192.168.1.10/24 brd + dev br1
}

main "$@"
