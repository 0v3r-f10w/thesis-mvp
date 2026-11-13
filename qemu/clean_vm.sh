#!/bin/bash
# 方案 B：跑前清空 VM 上所有容器
echo "=== BEFORE ==="
sudo docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
echo "count: $(sudo docker ps -aq | wc -l)"

echo
echo "=== removing all containers ==="
IDS=$(sudo docker ps -aq)
if [ -n "$IDS" ]; then
    sudo docker rm -f $IDS
else
    echo "nothing to remove"
fi

echo
echo "=== AFTER ==="
echo "container count: $(sudo docker ps -aq | wc -l)"
sudo docker ps -a --format '{{.Names}}' || true

echo
echo "=== networks / volumes (should be only defaults) ==="
sudo docker network ls --format '{{.Name}}'
echo "volumes: $(sudo docker volume ls -q | wc -l)"

echo
echo "=== host residue ==="
ls -1d /tmp/vm_* /tmp/flag_out /tmp/dsh-* /var/tmp/flag_from_cron 2>/dev/null || echo "clean"
