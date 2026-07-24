#!/bin/bash

ENV="etcd-cluster.env"
ETCD="etcd-cluster.yaml"
SHEEP="sheep-cluster.yaml"

docker compose --env-file $ENV -f $SHEEP down
for vol in $(docker volume ls --filter Name=sheepdog-etcd_sheep | tail -n +2 | cut -b 11-); do
    docker volume rm $vol
done
docker exec sheepdog-etcd-etcd0-1 etcdctl del --prefix sheepdog
