#!/bin/sh
# 从仓库源码生成自包含的通用 install.sh
# 用法: tools/mkinstaller.sh [输出文件]   (默认 ./install.sh)
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$REPO/install.sh}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# 打包两套架构源码并 base64(单行)
mkdir -p "$TMP/src"
cp -r "$REPO/x86_64" "$REPO/arm" "$TMP/src/"
tar -C "$TMP/src" -czf "$TMP/payload.tgz" .
b64=$(base64 < "$TMP/payload.tgz" | tr -d '\n')

# 模板中的标记行替换为 PAYLOAD_B64="..."
awk -v b64="$b64" '
    /^#__PAYLOAD_B64__$/ { printf "PAYLOAD_B64=\"%s\"\n", b64; next }
    { print }
' "$REPO/tools/install.tmpl.sh" > "$OUT"

chmod +x "$OUT"
sh -n "$OUT" || { echo "生成物语法检查失败" >&2; exit 1; }
echo "generated: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes, payload $(printf '%s' "$b64" | wc -c | tr -d ' ') bytes b64)"
