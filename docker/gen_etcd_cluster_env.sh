#!/bin/bash

NUM_NODES=$1
NETWORK="192.168.122"
ETCD_IP_OFFSET=20
SHEEP_IP_OFFSET=40

echo "CLUSTER_STATE=new"
echo "CLUSTER_TOKEN=etcd-cluster"
echo "CLUSTER_IP=${NETWORK}.0/24"
echo "SHEEP_VNODES="
echo "VALGRIND="

for i in $(seq ${NUM_NODES}); do
    node=$(( $i - 1 ))
    IP=$(( $node + $ETCD_IP_OFFSET ))
    echo "NODE${node}_NAME=etcd${node}"
    echo "NODE${node}_IP=${NETWORK}.${IP}"
done

for i in $(seq ${NUM_NODES}); do
    node=$(( $i - 1 ))
    IP=$(( $node + $SHEEP_IP_OFFSET ))
    echo "SHEEP${node}_NAME=sheep${node}"
    echo "SHEEP${node}_IP=${NETWORK}.${IP}"
done
