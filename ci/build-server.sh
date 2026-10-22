#!/usr/bin/env bash
#
# 构建统一账号服务并打包成 tar：tar 内首层是 server/，解压后为 server/bin/server
# 单个静态二进制——ci/deploy-server.sh 做 `tar -xf --strip-components=1` →
# `chmod +x bin/server` → 切 symlink → supervisorctl restart → curl /health。
#
# 用法：ci/build-server.sh
# 产物：dist/server.tar
set -euo pipefail

cd "$(dirname "$0")/.."

GO=${GO:-go}
command -v "$GO" >/dev/null || { echo "::error::未找到 go，请先安装（或用 actions/setup-go）"; exit 1; }

OUT_TAR="dist/server.tar"
STAGE="dist/go-stage"

echo "== web（Kotlin/Wasm 前端）=="
# wasm 产物经 go:embed 进二进制（internal/ui/wasm/）；本地没装 JDK 时给出明确报错。
if [ -f web/gradlew ]; then
  command -v java >/dev/null || { echo "::error::未找到 java（wasm 前端需要 JDK 21+）"; exit 1; }
  (cd web && ./gradlew wasmJsBrowserDistribution --console=plain)
  rm -rf internal/ui/wasm
  mkdir -p internal/ui/wasm
  cp -r web/build/dist/wasmJs/productionExecutable/. internal/ui/wasm/
  echo "wasm 产物已拷入 internal/ui/wasm/："
  ls -lh internal/ui/wasm/
fi

echo "== go test =="
# 真库测试靠 TEST_MYSQL_DSN 注入，CI 没有 MySQL 时自动 Skip，
# 限流/aud 白名单/雪花 id/verify 路由这些不依赖数据库的测试照常跑。
"$GO" test ./...

echo "== go build（CGO_ENABLED=0 出静态二进制）==="
# 关 CGO：服务器与构建机的 glibc 版本不保证一致，静态链接才能保证扔上去就能跑
rm -rf "$STAGE"
mkdir -p "$STAGE/server/bin"
CGO_ENABLED=0 "$GO" build -trimpath -ldflags "-s -w" -o "$STAGE/server/bin/server" ./cmd/server

echo "== 打包 =="
mkdir -p "$(dirname "$OUT_TAR")"
tar -cf "$OUT_TAR" -C "$STAGE" server
rm -rf "$STAGE"

echo "== 校验结构 =="
TAR_ROOTS=$(tar -tf "$OUT_TAR" | awk -F/ '{print $1}' | sort -u)
if [ "$TAR_ROOTS" != "server" ]; then
  echo "::error::tar 首层应只有 server/，实际是：$TAR_ROOTS"
  exit 1
fi
if ! tar -tf "$OUT_TAR" | grep -qx "server/bin/server"; then
  echo "::error::tar 里缺少 server/bin/server——部署脚本 chmod +x bin/server 会失败"
  exit 1
fi

echo "== 产物 =="
ls -lh "$OUT_TAR"
tar -tf "$OUT_TAR"
