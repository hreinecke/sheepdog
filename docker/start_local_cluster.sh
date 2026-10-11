#!/bin/bash -x

set_rdma_addr()
{
    local IFNAME=$1
    local TRADDR=$2
    local IPADDR

    IPADDR=$(ip addr show dev ${IFNAME} | \
		 sed -n 's/.*inet \([0-9.\/]*\) .*/\1/p')

    if [ -z "${IPADDR}" ]; then
	IPADDR="${TRADDR}"

	ip addr add dev ${IFNAME} ${IPADDR}
    fi
    echo "${IPADDR%%/*}"
}

set_rdma_link()
{
    local IFNAME=$1
    local RDMA_MODE=$2
    local IFRDMA

    IFRDMA=$(rdma dev show | sed -n "s/.*\(${IFNAME}_[a-z]*\): .*/\1/p")
    if [ -z ${IFRDMA} ] ; then
	IFRDMA="${IFNAME}_${RDMA_MODE}"
	RDMA_LINK=$(rdma dev show "${IFRDMA}")

	if [ -z "${RDMA_LINK}" ] ; then
	    rdma link add "${IFRDMA}" type ${RDMA_MODE} netdev ${IFNAME}
	fi
    fi
}

DOG=../dog/dog
SHEEP=../sheep/sheep

SHEEP_LOGGING="level=debug"
SHEEP_CLUSTER_DRIVER="local"
SHEEP_TRANSPORT="rdma"
SHEEP_TCP_TRADDR="127.0.0.1"
SHEEP_RDMA_TRADDR="192.168.122.200/24"
SHEEP_RDMA_MODE="rxe"

export SHEEP_LOGGING SHEEP_CLUSTER_DRIVER SHEEP_TRANSPORT

if [ "$SHEEP_TRANSPORT" = "rdma" ] ; then
    SHEEP_TRADDR=$(set_rdma_addr eth0 ${SHEEP_RDMA_TRADDR})
    set_rdma_link eth0 ${SHEEP_RDMA_MODE}
else
    SHEEP_TRADDR="$SHEEP_TCP_TRADDR"
fi
export SHEEP_TRADDR

[ -d /srv/sheep ] || mkdir /srv/sheep
for node in $(seq 0 4); do
    [ -d /srv/sheep/${node} ] || mkdir /srv/sheep/${node}
    cp $SHEEP /srv/sheep/${node}
    pushd /srv/sheep/${node} > /dev/null
    ./sheep /srv/sheep/${node} -p 700${node} -z ${node} -s 800${node}
    popd > /dev/null
done

$DOG cluster format -l
$DOG acl create nqn.subsys-1
$DOG vdi create nqn.ns-1 512M
$DOG vdi create nqn.ns-2 64M
$DOG acl add vdi nqn.subsys-1 nqn.ns-1
$DOG acl add vdi nqn.subsys-1 nqn.ns-2
$DOG acl add member nqn.subsys-1 $(cat /etc/nvme/hostnqn)
$DOG acl list -j | jq
