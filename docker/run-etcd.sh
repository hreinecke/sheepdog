ETCD_VERSION=v3.6.0
REGISTRY=quay.io/coreos/etcd
# available from v3.2.5
REGISTRY=gcr.io/etcd-development/etcd

CLUSTER_STATE=new
CLUSTER_TOKEN=etcd-cluster-1

NODE1_IP=192.168.122.21
NODE1_NAME=etcd1
NODE1_DIR=etcd-${NODE1_NAME}-data

NODE2_IP=192.168.122.22
NODE2_NAME=etcd2
NODE2_DIR=etcd-${NODE2_NAME}-data

NODE3_IP=192.168.122.23
NODE3_NAME=etcd3
NODE3_DIR=etcd-${NODE3_NAME}-data

NODE4_IP=192.168.122.24
NODE4_NAME=etcd4
NODE4_DIR=etcd-${NODE4_NAME}-data

run_etcd()
{
    local NODE_NAME=$1
    local NODE_IP=$2
    local NODE_DIR=$3
    docker run -d \
	   -p 2379:2379 \
	   -p 2380:2380 \
	   --network etcd-br \
	   --hostname ${NODE_NAME} \
	   --ip ${NODE_IP} \
	   --volume ${NODE_DIR}:/etcd-data \
	   --name ${NODE_NAME} ${REGISTRY}:${ETCD_VERSION} \
	   /usr/local/bin/etcd \
	   --data-dir=/etcd-data --name ${NODE_NAME} \
	   --initial-advertise-peer-urls http://${NODE_IP}:2380 \
	   --listen-peer-urls http://${NODE_IP}:2380,http://127.0.0.1:2380 \
	   --advertise-client-urls http://${NODE_IP}:2379 \
	   --listen-client-urls http://${NODE_IP}:2379,http://127.0.0.1:2379 \
	   --initial-cluster-token ${CLUSTER_TOKEN} \
	   --initial-cluster-state ${CLUSTER_STATE} \
	   --initial-cluster ${NODE1_NAME}=http://${NODE1_IP}:2380,${NODE2_NAME}=http://${NODE2_IP}:2380,${NODE3_NAME}=http://${NODE3_IP}:2380,${NODE4_NAME}=http://${NODE4_IP}:2380
}

run_etcd ${NODE1_NAME} ${NODE1_IP} ${NODE1_DIR}

run_etcd ${NODE2_NAME} ${NODE2_IP} ${NODE2_DIR}

run_etcd ${NODE3_NAME} ${NODE3_IP} ${NODE3_DIR}

run_etcd ${NODE4_NAME} ${NODE4_IP} ${NODE4_DIR}
