#!/bin/bash

NUM_NODES=$1

CLUSTER_STRING=""
for i in $(seq ${NUM_NODES}); do
    node=$(( $i - 1 ))
    if (( $node != 0 )); then
	CLUSTER_STRING="${CLUSTER_STRING},"
    fi
    CLUSTER_STRING="${CLUSTER_STRING}\${NODE${node}_NAME}=http://\${NODE${node}_IP}:2380"
done

cat <<EOF
name: sheepdog-etcd
services:
  sheep:
    image: sheepdog
    build:
      context: ../
      dockerfile: Dockerfile.sheepdog
    command: echo sheep container ready
  ioutgt-build:
    image: ioutgt-sheepdog
    build: https://github.com/hreinecke/ioutgt.git#sheepdog
EOF

for i in $(seq ${NUM_NODES}); do
    node=$(( $i - 1 ))
    port=$(( $node + 7000 ))
    disc_port=$(( $node + 8000 ))
    echo "  sheep${node}:"
    echo "    image: sheepdog"
    echo "    hostname: \${SHEEP${node}_NAME}"
    echo "    mac_address: \${SHEEP${node}_MAC}"
    echo "    init: true"
    echo "    networks:"
    echo "      etcd-br:"
    echo "        ipv4_address: \${SHEEP${node}_IP}"
    echo "      sheep-br:"
    echo "    volumes:"
    echo "      - sheep${node}-data:\${SHEEP_STORE}"
    echo "    ports:"
    echo "      - \"127.0.0.1:${port}:7000\""
    echo "      - \"127.0.0.1:${disc_port}:${disc_port}\""
    echo "    environment:"
    echo "      - SHEEP_CLUSTER_DRIVER=etcd:\${NODE${node}_IP}"
    echo "      - SHEEP_LOGGING=level=debug,dst=stdout"
    echo "      - SHEEP_BASE_DIR=\${SHEEP_BASE_DIR}"
    echo "      - SHEEP_ADDR=\${SHEEP${node}_IP}"
    echo "      - SHEEP_VNODES=\${SHEEP_VNODES}"
    echo "      - SHEEP_ZONE=\${SHEEP_ZONE:-${node}}"
    echo "      - SHEEP_JOURNAL=\${SHEEP_JOURNAL}"
    echo "      - VALGRIND=\${VALGRIND}"
    echo "    command: \${VALGRIND} /usr/sbin/sheep -f"
    echo "  target${node}:"
    echo "    image: ioutgt-sheepdog"
    echo "    network_mode: service:sheep${node}"
    echo "    security_opt:"
    echo "      - seccomp=unconfined"
    echo "    command: /usr/sbin/ioutgt-nvme-tcp --io-threads 4 --listen 0.0.0.0:${disc_port} --backend sheepdog:\${SHEEP${node}_IP}:7000"
done

echo
echo "volumes:"
for i in $(seq ${NUM_NODES}); do
    node=$(( $i - 1 ))
    echo "  sheep${node}-data:"
done

cat <<EOF

networks:
  etcd-br:
    external: true
    name: "etcd-internal"
  sheep-br:
    driver: bridge
EOF
