#!/usr/bin/env bash
# CI → 生产机部署统一账号服务（Supervisord）。
# 测试由 workflow 前置步骤保证；本脚本负责上传/原子切换/健康检查/失败回滚。
#（照抄热量日记服务的同款脚本，只改默认端口与进程名——部署形态完全一致。）
#
# 必需 env:  SERVER_HOST SERVER_USER SERVER_SSH_KEY BASE_DIR(Actions secret SERVER_BASE_DIR)
# 可选 env:  SSH_PORT(22) APP_PORT(8868) SUPERVISORCTL(supervisorctl) PROGRAM(auth) KEEP_RELEASES(5)
# 用法:      ci/deploy-server.sh <path/to/server.tar>
set -euo pipefail

: "${SERVER_HOST:?SERVER_HOST is required}" \
  "${SERVER_USER:?SERVER_USER is required}" \
  "${SERVER_SSH_KEY:?SERVER_SSH_KEY is required}" \
  "${BASE_DIR:?BASE_DIR is required}"
TAR_FILE=${1:?usage: deploy-server.sh <server.tar>}
SSH_PORT=${SSH_PORT:-22}
APP_PORT=${APP_PORT:-8868}
SUPERVISORCTL=${SUPERVISORCTL:-supervisorctl}
PROGRAM=${PROGRAM:-auth}
KEEP_RELEASES=${KEEP_RELEASES:-5}
RELEASE=$(git rev-parse --short=8 HEAD)

SSH_OPTS=(-i "$RUNNER_TEMP/deploy_key" -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new -o BatchMode=yes)
# 远端登录 shell 可能是 zsh（不分词），强制经 bash 执行以支持 $SUPERVISORCTL 等多词变量
run_ssh() { ssh "${SSH_OPTS[@]}" "$SERVER_USER@$SERVER_HOST" "bash -c $(printf '%q' "$1")"; }
run_scp() { scp -i "$RUNNER_TEMP/deploy_key" -P "$SSH_PORT" -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$1" "$SERVER_USER@$SERVER_HOST:$2"; }

cleanup_key() { rm -f "$RUNNER_TEMP/deploy_key"; }
cleanup_key
trap cleanup_key EXIT

install -m 600 /dev/null "$RUNNER_TEMP/deploy_key"
printf '%s\n' "$SERVER_SSH_KEY" > "$RUNNER_TEMP/deploy_key"

echo "== upload =="
run_ssh "mkdir -p '$BASE_DIR/releases/$RELEASE'"
run_scp "$TAR_FILE" "$BASE_DIR/releases/$RELEASE/server.tar"

echo "== extract =="
run_ssh "set -e; cd '$BASE_DIR/releases/$RELEASE' && tar -xf server.tar --strip-components=1 && rm server.tar && chmod +x bin/server"

OLD=$(run_ssh "readlink '$BASE_DIR/current' || true")
echo "current -> ${OLD:-<none>}  |  new: releases/$RELEASE"

rollback() {
  echo "::error::deploy failed, rolling back to ${OLD:-none}"
  if [ -n "$OLD" ]; then
    run_ssh "ln -sfn '$OLD' '$BASE_DIR/current' && $SUPERVISORCTL restart '$PROGRAM:*'" || true
    sleep 3
    if run_ssh "curl -fsS http://127.0.0.1:$APP_PORT/health >/dev/null" 2>/dev/null; then
      echo "rollback healthy"
    else
      echo "::warning::rollback health check failed — inspect server manually"
    fi
  else
    run_ssh "$SUPERVISORCTL stop '$PROGRAM:*'" || true
  fi
  exit 1
}
trap rollback ERR

echo "== switch & restart =="
run_ssh "ln -sfn '$BASE_DIR/releases/$RELEASE' '$BASE_DIR/current' && $SUPERVISORCTL restart '$PROGRAM:*'"
# spawn error 时拉出服务端日志，便于 CI 里直接定位
run_ssh "$SUPERVISORCTL status '$PROGRAM:*' || true"
run_ssh "tail -n 80 '$BASE_DIR/current/logs/server.log' 2>/dev/null || tail -n 80 '$BASE_DIR/current/server.log' 2>/dev/null || journalctl -u auth -n 80 --no-pager 2>/dev/null || true"

echo "== health check =="
OK=0
for _ in $(seq 1 15); do
  if run_ssh "curl -fsS http://127.0.0.1:$APP_PORT/health >/dev/null" 2>/dev/null; then OK=1; break; fi
  sleep 2
done
[ "$OK" = 1 ] || { echo "::error::health check failed after 30s"; false; }

trap - ERR
echo "== prune (keep $KEEP_RELEASES) =="
run_ssh "cd '$BASE_DIR/releases' && ls -1t | tail -n +$((KEEP_RELEASES + 1)) | xargs -r rm -rf"

echo "deployed: $RELEASE -> $BASE_DIR/current (health OK)"
