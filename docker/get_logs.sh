#!/bin/bash

ENV="etcd-cluster.env"
ETCD="etcd-cluster.yaml"
SHEEP="sheep-cluster.yaml"

for i in $(docker ps -a --filter Name=sheepdog-etcd-sheep --format json | jq .Names); do
    img=$(eval echo $i)
    num=$(echo $img | cut -d - -f 3)
    [[ "$num" == "sheep" ]] && continue
    docker logs $img > /tmp/sheep${num##sheep}.log 2>&1
done
