#!/bin/bash -x

ENV="etcd-cluster.env"
ETCD="etcd-cluster.yaml"
SHEEP="sheep-cluster.yaml"

docker compose --env-file ${ENV} -f ${ETCD} up -d
docker compose --env-file ${ENV} -f ${SHEEP} up -d
