#!/bin/bash -x

ENV="etcd-cluster.env"
SHEEP="sheep-cluster.yaml"
DOG=../dog/dog

for node in $(seq 0 4); do
    docker compose --env-file ${ENV} -f ${SHEEP} up -d sheep${node}
done

$DOG cluster format -l
$DOG acl create nqn.subsys-1
$DOG vdi create nqn.ns-1 512M
$DOG vdi create nqn.ns-2 64M
$DOG acl add vdi nqn.subsys-1 nqn.ns-1
$DOG acl add vdi nqn.subsys-1 nqn.ns-2
$DOG acl add member nqn.subsys-1 $(cat /etc/nvme/hostnqn)
$DOG acl list -j | jq

