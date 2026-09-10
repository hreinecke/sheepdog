#!/bin/bash -x

DOG=../dog/dog
SHEEP=../sheep/sheep

for node in $(seq 0 4); do
    [ -d /srv/sheep/${node} ] || mkdir /srv/sheep/${node}
    $SHEEP -c local /srv/sheep/${node} -l level=debug -p 700${node} -z ${node} -t 127.0.0.1 -s 800${node}
done

$DOG cluster format -l
$DOG acl create nqn.subsys-1
$DOG vdi create nqn.ns-1 512M
$DOG vdi create nqn.ns-2 64M
$DOG acl add vdi nqn.subsys-1 nqn.ns-1
$DOG acl add vdi nqn.subsys-1 nqn.ns-2
$DOG acl add member nqn.subsys-1 $(cat /etc/nvme/hostnqn)
$DOG acl list -j | jq
