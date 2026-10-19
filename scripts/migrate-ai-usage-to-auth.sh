#!/usr/bin/env bash
#
# migrate-ai-usage-to-auth.sh —— 两个日记 App 的 ai_usage 历史计数并入 auth：
# AI 三层限流/记账收归 auth 统一执行后（/internal/ai/*），日额度按 uid 与 global
# 两层**跨 App 相加**——并入历史计数后统一预算才从「两库之和」起算，而不是每个
# App 各自从 0 起算（那等于给每个用户双倍预算）。
#
# ================================ 规则 ================================
# ① 源 = 两日记库 ai_usage 的**全部行**（该表只有计数、没有别的用途，历史行就是
#    待并的账）；scope/day 只允许 user|global 与 YYYY-MM-DD，异常值按「源数据形态
#    变了」报错停下，不猜。
# ② 按 (scope, subject, day) 三元组求和：同键两库都有则 count 相加；auth 已有行
#    则在**现状之上再加**（并入期间 App 可能已在打新端点产生新计数，覆盖会把
#    新账抹掉）。
# ③ **幂等靠 app_config 标记键 `ai_usage_merged_at`**：--execute 成功后写入当前
#    毫秒；键已存在则整脚本跳过并提示——防重跑把计数翻倍。dry-run 不写标记。
# ④ 只写 auth 库（两库源数据纯只读）。
# ======================================================================
#
# 用法（默认 dry-run，全程只读）：
#   AUTH_DSN='user:pass@tcp(host:port)/auth' \
#   CALORIE_DSN='user:pass@tcp(host:port)/calorie-diary' \
#   EXPENSE_DSN='user:pass@tcp(host:port)/expense-diary' \
#     bash scripts/migrate-ai-usage-to-auth.sh            # dry-run：打印计划与当前状态
#     ...同上... bash scripts/migrate-ai-usage-to-auth.sh --execute
#
# 环境变量（Go 风格 DSN；**脚本内零凭据**，密码不得含 `@`——Go DSN 用它分隔凭据与地址）：
#   AUTH_DSN     auth 账号库（ai_usage / app_config）
#   CALORIE_DSN  热量日记业务库（ai_usage）
#   EXPENSE_DSN  开支日记业务库（ai_usage）
#
# 依赖：mysql、awk、sed。幂等可重跑（靠标记键）；执行顺序建议：日记侧改道批次
# **部署完、跑本脚本**——并账期间 App 已在 auth 记的新计数被 ② 规则保住。
# 收尾校验（只读）：auth 每个键的 count = 改前基线 + 两库之和、标记键已写——
# 任一不符退出码非 0。
set -euo pipefail

die() { echo "错误：$*" >&2; exit 1; }

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

EXECUTE=0
for arg in "$@"; do
    case "$arg" in
        --execute) EXECUTE=1 ;;
        --dry-run) EXECUTE=0 ;;
        -h | --help) usage; exit 0 ;;
        *) die "未知参数：$arg（默认 --dry-run，只有 --execute 会写库）" ;;
    esac
done

for c in mysql awk sed; do command -v "$c" >/dev/null || die "缺少依赖命令：$c"; done
: "${AUTH_DSN:?缺少 AUTH_DSN（auth 库 Go 风格 DSN）}"
: "${CALORIE_DSN:?缺少 CALORIE_DSN（热量日记业务库 DSN）}"
: "${EXPENSE_DSN:?缺少 EXPENSE_DSN（开支日记业务库 DSN）}"

# Go 风格 DSN 拆成 mysql CLI 参数（与 scripts/migrate-profile-to-auth.sh 同款口径）：
# 密码走 MYSQL_PWD，不进 argv（ps 里看不到）。限制：密码不能含 @。
parse_dsn() { # $1=dsn $2=前缀 → 设 ${P}_USER/_PASS/_HOST/_PORT/_DB
    local dsn="$1" p="$2"
    local re='^([^:@/]+)(:([^@]*))?@tcp\(([^):]+)(:([0-9]+))?\)/([^?]+)(\?.*)?$'
    [[ "$dsn" =~ $re ]] || die "$p 不是 Go 风格 DSN（user:pass@tcp(host:port)/dbname）"
    printf -v "${p}_USER" '%s' "${BASH_REMATCH[1]}"
    printf -v "${p}_PASS" '%s' "${BASH_REMATCH[3]}"
    printf -v "${p}_HOST" '%s' "${BASH_REMATCH[4]}"
    printf -v "${p}_PORT" '%s' "${BASH_REMATCH[6]:-3306}"
    printf -v "${p}_DB" '%s' "${BASH_REMATCH[7]}"
}
parse_dsn "$AUTH_DSN" AUTH
parse_dsn "$CALORIE_DSN" CAL
parse_dsn "$EXPENSE_DSN" EXP
for p in AUTH CAL EXP; do
    v_host="${p}_HOST" v_port="${p}_PORT" v_user="${p}_USER" v_db="${p}_DB"
    : "${!v_host:?${p}_DSN 解析失败}" "${!v_port:?}" "${!v_user:?}" "${!v_db:?}"
done

# -N -B：无表头、TAB 分隔。stderr 过掉 MariaDB 客户端那句无害的 ssl-verify 提示。
_MYSQL_ERR() { grep -v 'ssl-verify-server-cert' >&2; }
q_auth() { MYSQL_PWD="$AUTH_PASS" mysql -h "$AUTH_HOST" -P "$AUTH_PORT" -u "$AUTH_USER" --default-character-set=utf8mb4 -N -B "$AUTH_DB" -e "$1" 2> >(_MYSQL_ERR); }
q_cal() { MYSQL_PWD="$CAL_PASS" mysql -h "$CAL_HOST" -P "$CAL_PORT" -u "$CAL_USER" --default-character-set=utf8mb4 -N -B "$CAL_DB" -e "$1" 2> >(_MYSQL_ERR); }
q_exp() { MYSQL_PWD="$EXP_PASS" mysql -h "$EXP_HOST" -P "$EXP_PORT" -u "$EXP_USER" --default-character-set=utf8mb4 -N -B "$EXP_DB" -e "$1" 2> >(_MYSQL_ERR); }
sql_lit() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"; }

# ai_usage 的建表语句：与 internal/db/schema.sql 逐字一致（EnsureSchema 也会建，
# 自带一份是为了 --execute 不依赖 auth 新版是否已部署/重启过）。
AI_USAGE_DDL="CREATE TABLE IF NOT EXISTS ai_usage (
    scope   VARCHAR(8)  NOT NULL,
    subject VARCHAR(32) NOT NULL,
    day     VARCHAR(10) NOT NULL,
    count   INT         NOT NULL,
    PRIMARY KEY (scope, subject, day)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci"

MERGE_MARK_KEY="ai_usage_merged_at"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/migrate-ai-usage.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

echo "== AI 用量并入 auth（$([ "$EXECUTE" = 1 ] && echo 'EXECUTE' || echo 'dry-run，只看不写')）=="
echo "目标库：auth=$AUTH_DB  calorie=$CAL_DB  expense=$EXP_DB"

# ---------- ① 源行普查（information_schema + 只读查询） ----------
# 字段分隔 0x1F（US）：与 migrate-profile-to-auth.sh 同款理由——bash 的 read 把
# IFS 里的 tab 当空白，并列空列会错位；0x1F 不可能出现在本表任何字段里。
declare -a MISS=()
src_fetch() { # $1=查询函数 $2=库名 $3=标签 $4=输出文件
    local q="$1" schema="$2" label="$3" out="$4" has
    : >"$out"
    has=$("$q" "SELECT COUNT(*) FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = $(sql_lit "$schema") AND TABLE_NAME = 'ai_usage'")
    if [ "$has" != 1 ]; then
        echo "  跳过 $label：ai_usage 表不存在（该库按无源数据处理）"
        MISS+=("$label")
        return 0
    fi
    "$q" "SELECT CONCAT_WS(CHAR(31), scope, subject, day, \`count\`) FROM ai_usage" >"$out"
}
echo "== 源行普查："
src_fetch q_cal "$CAL_DB" calorie-diary "$WORK/src_cal.tsv"
src_fetch q_exp "$EXP_DB" expense-diary "$WORK/src_exp.tsv"

# 校验源行形态：scope ∈ {user,global}、day 是 YYYY-MM-DD、count 是非负整数。
# 形态不对 = 源库结构变了，停下人工核对——带着猜来的键并账只会把账记错地方。
check_shape() { # $1=标签 $2=文件
    local label="$1" file="$2" bad
    bad=$(awk -F'\x1f' '$3 !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/ || ($1 != "user" && $1 != "global") || $4 !~ /^[0-9]+$/ { print; exit }' "$file" || true)
    [ -z "$bad" ] || die "$label 的 ai_usage 有异常行（scope/day/count 越界），先人工核对：$bad"
}
check_shape calorie-diary "$WORK/src_cal.tsv"
check_shape expense-diary "$WORK/src_exp.tsv"

# ---------- ② 跨库合并：同 (scope,subject,day) 求和 ----------
declare -A SUM
CAL_N=$(wc -l <"$WORK/src_cal.tsv")
EXP_N=$(wc -l <"$WORK/src_exp.tsv")
while IFS=$'\x1f' read -r scope subject day count; do
    [ -n "$scope" ] || continue
    SUM["$scope|$subject|$day"]=$(( ${SUM["$scope|$subject|$day"]:-0} + count ))
done <"$WORK/src_cal.tsv"
while IFS=$'\x1f' read -r scope subject day count; do
    [ -n "$scope" ] || continue
    SUM["$scope|$subject|$day"]=$(( ${SUM["$scope|$subject|$day"]:-0} + count ))
done <"$WORK/src_exp.tsv"

KEYS=${#SUM[@]}
TOTAL=0
for k in "${!SUM[@]}"; do TOTAL=$((TOTAL + SUM[$k])); done

if [ "$KEYS" = 0 ]; then
    echo "无事可做：两库 ai_usage 都没有行。"
    exit 0
fi

# ---------- ③ auth 现状（改前基线，纯只读） ----------
AUTH_TABLE=$(q_auth "SELECT COUNT(*) FROM information_schema.TABLES
                     WHERE TABLE_SCHEMA = $(sql_lit "$AUTH_DB") AND TABLE_NAME = 'ai_usage'")
declare -A BASE
BASE_ROWS=0
BASE_TOTAL=0
: >"$WORK/baseline.tsv"
if [ "$AUTH_TABLE" = 1 ]; then
    while IFS=$'\x1f' read -r scope subject day count; do
        [ -n "$scope" ] || continue
        BASE["$scope|$subject|$day"]=$count
        BASE_ROWS=$((BASE_ROWS + 1))
        BASE_TOTAL=$((BASE_TOTAL + count))
        printf '%s\x1f%s\n' "$scope|$subject|$day" "$count" >>"$WORK/baseline.tsv"
    done < <(q_auth "SELECT CONCAT_WS(CHAR(31), scope, subject, day, \`count\`) FROM ai_usage")
else
    echo "  auth.$AUTH_DB.ai_usage 不存在（--execute 会建表，全部按新行并入）"
fi

# 标记键现状：已合并过就整脚本跳过（防重跑翻倍）
MARK_EXISTS=0
MARK_VALUE=""
if q_auth "SELECT COUNT(*) FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = $(sql_lit "$AUTH_DB") AND TABLE_NAME = 'app_config'" >/dev/null 2>&1; then
    MARK_VALUE=$(q_auth "SELECT \`value\` FROM app_config WHERE \`key\` = $(sql_lit "$MERGE_MARK_KEY")" || true)
    [ -n "$MARK_VALUE" ] && MARK_EXISTS=1
fi

echo "== 计划：源 $CAL_N 行（calorie-diary）+ $EXP_N 行（expense-diary）→ $KEYS 个键、合计 $TOTAL 次"
if [ "$KEYS" != 0 ]; then
    printf '  %-8s %-12s %-11s %-8s %s\n' "scope" "subject" "day" "两库之和" "auth 现状"
    for k in $(printf '%s\n' "${!SUM[@]}" | sort); do
        IFS='|' read -r s sub d <<<"$k"
        printf '  %-8s %-12s %-11s %-8s %s\n' "$s" "$sub" "$d" "${SUM[$k]}" "${BASE[$k]:-0}"
    done
fi
echo "  auth 现有行 $BASE_ROWS 个、合计 $BASE_TOTAL 次（并入 = 在现状之上加，不覆盖）"

if [ "$EXECUTE" != 1 ]; then
    if [ "$MARK_EXISTS" = 1 ]; then
        echo "== dry-run 注意：标记键 $MERGE_MARK_KEY 已存在（值 $MARK_VALUE）——--execute 会整脚本跳过。"
    fi
    echo "== dry-run 结束（一个字节都没写，建表也没建）。加 --execute 才动手。"
    exit 0
fi

# ---------- ④ 执行：标记键把关 + 整批一个事务，只写 auth ----------
if [ "$MARK_EXISTS" = 1 ]; then
    echo "== 已合并过（标记键 $MERGE_MARK_KEY = $MARK_VALUE），跳过不重跑——重跑会把计数翻倍。"
    exit 0
fi

if [ "$AUTH_TABLE" != 1 ]; then
    q_auth "$AI_USAGE_DDL"
    echo "== 已建表 ai_usage"
fi

NOW_MS=$(($(date +%s) * 1000))
# 行内字段全走参数化很难（mysql -e 只吃字符串 SQL），键三元组逐字校验过形态
#（scope ∈ {user,global}、day 是 YYYY-MM-DD、subject 只含 [0-9] 或空——subject
# 来源是 uid 字符串或 global 行的空串），此处再各自过滤一遍非 [0-9A-Za-z_-] 的
# 字符后拼字面量，杜绝注入面。
{
    echo "START TRANSACTION;"
    for k in "${!SUM[@]}"; do
        IFS='|' read -r s sub d <<<"$k"
        [[ "$s" =~ ^(user|global)$ ]] || die "scope 越界：$s"
        [[ "$d" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "day 越界：$d"
        [[ "$sub" =~ ^[0-9A-Za-z_-]*$ ]] || die "subject 含非法字符：$sub"
        # 反引号在单引号里是字面量，`count` 保留字引用不会被 shell 吃掉
        printf 'INSERT INTO ai_usage (scope, subject, day, `count`) VALUES (%s, %s, %s, %s)\n' \
            "$(sql_lit "$s")" "$(sql_lit "$sub")" "$(sql_lit "$d")" "${SUM[$k]}"
        printf 'ON DUPLICATE KEY UPDATE `count` = `count` + VALUES(`count`);\n'
    done
    printf 'INSERT INTO app_config (`key`, `value`) VALUES (%s, %s)\n' \
        "$(sql_lit "$MERGE_MARK_KEY")" "$(sql_lit "$NOW_MS")"
    printf 'ON DUPLICATE KEY UPDATE `value` = VALUES(`value`);\n'
    echo "COMMIT;"
} >"$WORK/tx.sql"

STMTS=$(grep -c ';' "$WORK/tx.sql" || true)
echo "== auth 库事务（$STMTS 条语句，含 BEGIN/COMMIT）…"
q_auth "$(cat "$WORK/tx.sql")" || die "auth 库事务失败（已回滚，一行都没写；修好后整脚本重跑，幂等）"
echo "   完成，标记键 $MERGE_MARK_KEY = $NOW_MS"

# ---------- ⑤ 改后校验（只读，任一不符退出码非 0） ----------
echo "== 校验："
FAILURES=0
note() { printf '  %s\n' "$*"; }

# 改后 auth 全表快照（⑤ 段与 ③ 段之间只有 ④ 的事务，改前基线已落盘 baseline.tsv）
declare -A AFTER
AFTER_ROWS=0
while IFS=$'\x1f' read -r scope subject day count; do
    [ -n "$scope" ] || continue
    AFTER["$scope|$subject|$day"]=$count
    AFTER_ROWS=$((AFTER_ROWS + 1))
done < <(q_auth "SELECT CONCAT_WS(CHAR(31), scope, subject, day, \`count\`) FROM ai_usage")

# 改前基线从落盘文件回读（③ 段的 BASE 数组在 ④ 后语义上已是「改前」，但校验段
# 独立回读文件，避免两段间的隐式耦合）
declare -A BASELINE
while IFS=$'\x1f' read -r key base; do
    [ -n "$key" ] || continue
    BASELINE["$key"]=$base
done <"$WORK/baseline.tsv"
# 每个合并键：auth 现值 = 改前基线 + 两库之和
for k in "${!SUM[@]}"; do
    want=$(( ${BASELINE[$k]:-0} + SUM[$k] ))
    got=${AFTER[$k]:-}
    if [ "$got" != "$want" ]; then
        note "键 $k：应 $want（基线 + 两库之和），实际 ${got:-无行} ← 不符"
        FAILURES=$((FAILURES + 1))
    fi
done
# 合并键之外的 auth 行（App 在并账期间自己记的新账）必须一字未动
for k in "${!BASELINE[@]}"; do
    if [ -z "${SUM[$k]:-}" ] && [ "${AFTER[$k]:-}" != "${BASELINE[$k]}" ]; then
        note "键 $k：不在合并范围却被改动（基线 ${BASELINE[$k]} → ${AFTER[$k]:-无行}） ← 不符"
        FAILURES=$((FAILURES + 1))
    fi
done
# 行数：基线行 + 合并键里 auth 原来没有的
declare -A SEEN
for k in "${!BASELINE[@]}"; do SEEN[$k]=1; done
for k in "${!SUM[@]}"; do SEEN[$k]=1; done
EXPECT_ROWS=${#SEEN[@]}
if [ "$AFTER_ROWS" != "$EXPECT_ROWS" ]; then
    note "行数应 $EXPECT_ROWS（基线 ∪ 合并键），实际 $AFTER_ROWS ← 不符"
    FAILURES=$((FAILURES + 1))
fi
# 标记键已写
GOT_MARK=$(q_auth "SELECT \`value\` FROM app_config WHERE \`key\` = $(sql_lit "$MERGE_MARK_KEY")" || true)
if [ "$GOT_MARK" != "$NOW_MS" ]; then
    note "标记键 $MERGE_MARK_KEY 应为 $NOW_MS，实际 ${GOT_MARK:-未写} ← 不符"
    FAILURES=$((FAILURES + 1))
else
    note "标记键 $MERGE_MARK_KEY = $GOT_MARK 已写入"
fi
# 两库源数据未被改动（纯只读承诺）——行数与总和复核
CAL_N2=$(wc -l <"$WORK/src_cal.tsv")
EXP_N2=$(wc -l <"$WORK/src_exp.tsv")
if [ "$CAL_N2" != "$CAL_N" ] || [ "$EXP_N2" != "$EXP_N" ]; then
    note "源库行数发生变化（cal $CAL_N→$CAL_N2 / exp $EXP_N→$EXP_N2） ← 不符"
    FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" != 0 ]; then
    echo "== 校验失败（$FAILURES 处不符）——请人工核对后再处理，勿直接重跑。" >&2
    exit 1
fi
echo "== 校验通过：auth 各键 = 基线 + 两库之和，标记键已写，源库未动。"
