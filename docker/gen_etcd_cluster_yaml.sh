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

echo "name: sheepdog-etcd"
echo "services:"

for i in $(seq ${NUM_NODES}); do
    node=$(( $i - 1 ))
    echo "  etcd${node}:"
    echo "    image: gcr.io/etcd-development/etcd:v3.6.0"
    echo "    hostname: \${NODE${node}_NAME}"
    echo "    networks:"
    echo "      etcd-br:"
    echo "        ipv4_address: \${NODE${node}_IP}"
    echo "    volumes:"
    echo "      - etcd${node}-data:/var/lib/etcd"
    echo "    expose:"
    echo "      - \"2379\""
    echo "      - \"2380\""
    echo "    environment:"
    echo "      - ETCD_DATA_DIR=/var/lib/etcd"
    echo "      - ETCD_NAME=\${NODE${node}_NAME}"
    echo "      - ETCD_INITIAL_ADVERTISE_PEER_URLS=http://\${NODE${node}_IP}:2380"
    echo "      - ETCD_LISTEN_PEER_URLS=http://\${NODE${node}_IP}:2380,http://127.0.0.1:2380"
    echo "      - ETCD_ADVERTISE_CLIENT_URLS=http://\${NODE${node}_IP}:2379"
    echo "      - ETCD_LISTEN_CLIENT_URLS=http://\${NODE${node}_IP}:2379,http://127.0.0.1:2379"
    echo "      - ETCD_INITIAL_CLUSTER_TOKEN=\${CLUSTER_TOKEN}"
    echo "      - ETCD_INITIAL_CLUSTER_STATE=\${CLUSTER_STATE}"
    echo "      - ETCD_INITIAL_CLUSTER=${CLUSTER_STRING}"
done

echo
echo "volumes:"
for i in $(seq ${NUM_NODES}); do
    node=$(( $i - 1 ))
    echo "  etcd${node}-data:"
done

cat <<EOF

networks:
  etcd-br:
    name: "etcd-internal"
    driver: bridge
    attachable: true
    internal: true
    ipam:
      config:
        - subnet: \${CLUSTER_IP}
EOF
