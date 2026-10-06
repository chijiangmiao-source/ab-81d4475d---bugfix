#!/usr/bin/env bash
# verify service entrypoint: one-shot acceptance, then exit.
#
#   1. grammar engine + sealed-store unit tests
#   2. build the arbiter image (explicit, ordered after the tests)
#   3. HTTP smoke against ARBITER_BASE_URL (in Compose: the healthy
#      "arbiter" service): unique / ambiguous / non-consuming-cycle,
#      sealed replay, audit-id conflict, then restart-over-unchanged-
#      volume evidence checks and legacy-store recovery
#   4. exit 0 on full success, 1 otherwise
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

echo "================ [1/3] 文法引擎与封存存储单元测试 ================"
if ! python3 -m unittest discover -s tests -v; then
  echo "单元测试失败，终止验收"
  exit 1
fi

echo "================ [2/3] 构建 arbiter 镜像 ================"
IMAGE="forest-arbiter:local"
LOCAL_FALLBACK_ACTIVE=0
if docker info >/dev/null 2>&1; then
  if ! docker build -t "$IMAGE" -f Dockerfile .; then
    echo "镜像构建失败"
    exit 1
  fi
  docker image inspect "$IMAGE" >/dev/null && echo "镜像 $IMAGE 已就绪"
elif [ "${ALLOW_LOCAL_FALLBACK:-0}" = "1" ]; then
  echo "警告：Docker daemon 不可用，回退为本地子进程冒烟（不验证镜像构建）" >&2
  mkdir -p /tmp/arbiter-data
  ARBITER_STORE=/tmp/arbiter-data/sealed.json ARBITER_PORT=18080 \
    python3 -m app.service >/tmp/arbiter.log 2>&1 &
  echo $! > /tmp/arbiter.pid
  export ARBITER_BASE_URL="http://127.0.0.1:18080"
  # Hints so verify.py can restart the service over the same store file.
  export ARBITER_LOCAL_FALLBACK=1
  export ARBITER_LOCAL_STORE=/tmp/arbiter-data/sealed.json
  export ARBITER_LOCAL_PORT=18080
  export ARBITER_LOCAL_PIDFILE=/tmp/arbiter.pid
  LOCAL_FALLBACK_ACTIVE=1
else
  echo "无法连接 Docker daemon（/var/run/docker.sock），无法执行镜像构建" >&2
  exit 1
fi

echo "================ [3/3] HTTP 场景冒烟（唯一/歧义/无消费环/回放/冲突/重启证据完整/遗留恢复）================"
echo "目标服务：${ARBITER_BASE_URL:?需设置 ARBITER_BASE_URL}"
SKIP_UNIT_TESTS=1 python3 scripts/verify.py
rc=$?

if [ "$LOCAL_FALLBACK_ACTIVE" = "1" ]; then
  kill "$(cat /tmp/arbiter.pid 2>/dev/null)" 2>/dev/null || true
fi
exit $rc
