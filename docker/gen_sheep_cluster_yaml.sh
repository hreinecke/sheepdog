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
EOF

for i in $(seq ${NUM_NODES}); do
    node=$(( $i - 1 ))
    port=$(( $node + 7000 ))
    echo "  sheep${node}:"
    echo "    image: sheepdog"
    echo "    hostname: \${SHEEP${node}_NAME}"
    echo "    init: true"
    echo "    networks:"
    echo "      etcd-br:"
    echo "        ipv4_address: \${SHEEP${node}_IP}"
    echo "      sheep-br:"
    echo "    volumes:"
    echo "      - sheep${node}-data:/var/lib/sheep"
    echo "    ports:"
    echo "      - \"127.0.0.1:${port}:7000\""
    echo "    environment:"
    echo "      - SHEEP_CLUSTER_DRIVER=etcd:\${NODE${node}_IP}"
    echo "      - SHEEP_LOGGING=level=debug,dst=stdout"
    echo "      - SHEEP_BASE_DIR=/var/lib/sheep"
    echo "      - SHEEP_ADDR=\${SHEEP${node}_IP}"
    echo "      - SHEEP_VNODES=\${SHEEP_VNODES}"
    echo "      - SHEEP_ZONE=${node}"
    echo "      - VALGRIND=\${VALGRIND}"
    echo "    command: \${VALGRIND} /usr/sbin/sheep -f"
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
