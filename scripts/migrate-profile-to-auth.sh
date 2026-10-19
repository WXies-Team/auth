#!/usr/bin/env bash
#
# migrate-profile-to-auth.sh —— 两个日记 App 的档案三件套（nickname / avatar_color /
# avatar_image）并入 auth.user_profile：档案收归 auth 统一存取（OIDC UserInfo 同款思路，
# 档案归身份提供方），并入后由日记客户端改道批次去读写 GET/PUT /api/profile。
#
# ================================ 规则 ================================
# ① 源 = 两库 profiles 里「有数据」的行：nickname<>'' 或 avatar_color<>0 或
#    avatar_image 非空，且 deleted=0（与日记服务自己的读口径一致——sync 只读
#    deleted=0 的行，软删行本来就不给用户看了，也不该被搬进 auth）。
# ② 同一 uid **跨两库取 updated_at 最新的一行**，整行三个字段一起搬（不跨行拼字段）；
#    updated_at 相同时 calorie 优先（先读 calorie、只在严格更新时才被 expense 顶替）。
# ③ auth.user_profile 已有**非默认行**（昵称/颜色/头像任一非默认）→ 跳过不覆盖：
#    首跑建行、后跑不动——用户在 auth 侧改过的档案不被日记旧数据盖回去。
#    只有「全默认行」才允许就地补齐（fill）。
# ④ 三个源字段原样搬运：昵称 trim 前的原文、颜色整数、头像 **裸 base64**（无 data:
#    前缀）；updated_at 用源行的时间戳（保留日记侧的 LWW 时刻，PUT 才会改成 now）。
#    空头像（HEX 为空）落 NULL，与 auth 侧「null = 无头像」的读口径对齐。
# ======================================================================
#
# 已知数据形态（2026-10-19 生产实测，改脚本前先重跑下面的 dry-run 核对）：
#   - **expense 的 outlook 账号在 expense.profiles 没有资料行**，靠 calorie 库同 uid
#     的行补齐——跨库取最新时缺行的一侧不参与比对，自然落到账本较全的 calorie 行上；
#   - calorie 侧 4 行 / 4 uid，expense 侧 1 行 / 1 uid；两库 uid 都是 7 位且互相重合；
#   - avatar_image 是裸 base64（`/9j/…` = JPEG），最长 30,956 字符，无换行无制表符。
#
# 用法（默认 dry-run，全程只读）：
#   AUTH_DSN='user:pass@tcp(host:port)/auth' \
#   CALORIE_DSN='user:pass@tcp(host:port)/calorie-diary' \
#   EXPENSE_DSN='user:pass@tcp(host:port)/expense-diary' \
#     bash scripts/migrate-profile-to-auth.sh            # dry-run：打印计划与当前状态
#     ...同上... bash scripts/migrate-profile-to-auth.sh --execute
#
# 环境变量（Go 风格 DSN；**脚本内零凭据**，密码不得含 `@`——Go DSN 用它分隔凭据与地址）：
#   AUTH_DSN     auth 账号库（users / user_profile）
#   CALORIE_DSN  热量日记业务库（profiles）
#   EXPENSE_DSN  开支日记业务库（profiles）
#
# 依赖：mysql、awk、sed。幂等可重跑；只写 auth 库（两库源数据纯只读）。
# 收尾校验（只读）：每个有数据的 uid 在 auth 都有行、本次写入的行与源行四字段逐字一致、
# 被跳过的行与改前基线一字未动——任一不符退出码非 0。
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

# Go 风格 DSN 拆成 mysql CLI 参数（与 scripts/migrate-uid-7digit.sh 同款口径）：
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

# -N -B：无表头、TAB 分隔；--default-character-set=utf8mb4 把连接字符集钉死，
# UNHEX/字面量往返不看服务器默认值。stderr 过掉 MariaDB 客户端那句无害的
# ssl-verify 提示（每个连接一句会淹掉真输出），其余错误照旧冒出来、退出码照旧由 set -e 兜。
_MYSQL_ERR() { grep -v 'ssl-verify-server-cert' >&2; }
# 三个连接都钉死 --default-character-set=utf8mb4：昵称/头像走 HEX 出入，连接字符集
# 决定 _utf8mb4 X'…' 之外的字面量怎么读，不钉死就看服务器默认值（跨版本会漂）。
q_auth() { MYSQL_PWD="$AUTH_PASS" mysql -h "$AUTH_HOST" -P "$AUTH_PORT" -u "$AUTH_USER" --default-character-set=utf8mb4 -N -B "$AUTH_DB" -e "$1" 2> >(_MYSQL_ERR); }
q_cal() { MYSQL_PWD="$CAL_PASS" mysql -h "$CAL_HOST" -P "$CAL_PORT" -u "$CAL_USER" --default-character-set=utf8mb4 -N -B "$CAL_DB" -e "$1" 2> >(_MYSQL_ERR); }
q_exp() { MYSQL_PWD="$EXP_PASS" mysql -h "$EXP_HOST" -P "$EXP_PORT" -u "$EXP_USER" --default-character-set=utf8mb4 -N -B "$EXP_DB" -e "$1" 2> >(_MYSQL_ERR); }
# SQL 单引号字面量（库名取自 DSN、属外部输入，进查询前必须转义）
sql_lit() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"; }

# user_profile 的建表语句：与 internal/db/schema.sql 逐字一致（EnsureSchema 也会建，
# 这里自带一份是为了 --execute 不依赖 auth 新版是否已部署/重启过）。
PROFILE_DDL="CREATE TABLE IF NOT EXISTS user_profile (
    user_id      BIGINT       NOT NULL,
    nickname     VARCHAR(64)  NOT NULL DEFAULT '',
    avatar_color INT          NOT NULL DEFAULT 0,
    avatar_image MEDIUMTEXT   NULL,
    updated_at   BIGINT       NOT NULL,
    PRIMARY KEY (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci"

# 有源数据的判定（两库同一份 SQL，计划与校验共用一处，不会漂）。
# 字段分隔用 ASCII 0x1F（US）而不是 TAB：bash 的 read 对 IFS 里的 **tab 属空白字符**，
# 连续两个 tab 会被并成一个分隔符，昵称为空串的行会把后面的列整体错位（踩过才写下来）。
# 0x1F 不可能出现在 hex/整数字段里，天然无歧义。
SRC_SQL="SELECT CONCAT_WS(CHAR(31), user_id, updated_at, HEX(nickname), avatar_color, IFNULL(HEX(avatar_image), ''))
         FROM profiles
         WHERE deleted = 0
           AND (nickname <> '' OR avatar_color <> 0 OR (avatar_image IS NOT NULL AND avatar_image <> ''))"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/migrate-profile.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

echo "== 档案并入 auth（$([ "$EXECUTE" = 1 ] && echo 'EXECUTE' || echo 'dry-run，只看不写')）=="
echo "目标库：auth=$AUTH_DB  calorie=$CAL_DB  expense=$EXP_DB"

# ---------- ① 源表/列核对：缺表或缺列的库按空处理并打印 ----------
declare -a MISS=()
src_fetch() { # $1=查询函数 $2=库名 $3=标签 $4=输出文件
    local q="$1" schema="$2" label="$3" out="$4" has t
    : >"$out"
    has=$("$q" "SELECT COUNT(*) FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = $(sql_lit "$schema") AND TABLE_NAME = 'profiles'")
    if [ "$has" != 1 ]; then
        echo "  跳过 $label：profiles 表不存在（该库按无源数据处理）"
        MISS+=("$label")
        return 0
    fi
    for t in user_id updated_at deleted nickname avatar_color avatar_image; do
        has=$("$q" "SELECT COUNT(*) FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = $(sql_lit "$schema") AND TABLE_NAME = 'profiles' AND COLUMN_NAME = '$t'")
        if [ "$has" != 1 ]; then
            die "$label.profiles 缺列 $t——schema 与本脚本的假设不一致，先人工核对（没有这些列就谈不上合并档案）"
        fi
    done
    "$q" "$SRC_SQL" >"$out"
}
echo "== 源行普查（information_schema + 只读查询）："
src_fetch q_cal "$CAL_DB" calorie-diary "$WORK/src_cal.tsv"
src_fetch q_exp "$EXP_DB" expense-diary "$WORK/src_exp.tsv"

# ---------- ② 跨库合并：每 uid 取 updated_at 最新的一行 ----------
# 先读 calorie 再读 expense，且只有**严格更新**才顶替 → updated_at 相同时 calorie 胜出
#（tie 走固定优先级，重跑结果才稳定）。
declare -A SRC_DB SRC_TS SRC_NICK SRC_COLOR SRC_AVA
take_row() { # $1=db $2=uid $3=ts $4=hexnick $5=color $6=hexavatar
    local db="$1" uid="$2" ts="$3" nick="$4" color="$5" ava="$6"
    [[ "$uid" =~ ^[0-9]+$ && "$ts" =~ ^[0-9]+$ && "$color" =~ ^-?[0-9]+$ ]] ||
        die "源行字段不是整数：uid=$uid ts=$ts color=$color"
    if [ -z "${SRC_TS[$uid]:-}" ] || [ "$ts" -gt "${SRC_TS[$uid]}" ]; then
        SRC_DB[$uid]=$db SRC_TS[$uid]=$ts SRC_NICK[$uid]=$nick SRC_COLOR[$uid]=$color SRC_AVA[$uid]=$ava
    fi
}
while IFS=$'\x1f' read -r uid ts nick color ava; do
    [ -n "$uid" ] || continue
    take_row calorie-diary "$uid" "$ts" "$nick" "$color" "$ava"
done <"$WORK/src_cal.tsv"
while IFS=$'\x1f' read -r uid ts nick color ava; do
    [ -n "$uid" ] || continue
    take_row expense-diary "$uid" "$ts" "$nick" "$color" "$ava"
done <"$WORK/src_exp.tsv"

SRC_TOTAL=${#SRC_TS[@]}
ONLY_CAL=0
ONLY_EXP=0
for uid in "${!SRC_TS[@]}"; do
    case "${SRC_DB[$uid]}" in
        calorie-diary) grep -q "^$uid"$'\x1f' "$WORK/src_exp.tsv" || ONLY_CAL=$((ONLY_CAL + 1)) ;;
        expense-diary) grep -q "^$uid"$'\x1f' "$WORK/src_cal.tsv" || ONLY_EXP=$((ONLY_EXP + 1)) ;;
    esac
done

if [ "$SRC_TOTAL" = 0 ]; then
    echo "无事可做：两库 profiles 都没有 nickname/avatar_color/avatar_image 数据。"
    exit 0
fi

# ---------- ③ auth 现状（改前基线，纯只读） ----------
AUTH_TABLE=$(q_auth "SELECT COUNT(*) FROM information_schema.TABLES
                     WHERE TABLE_SCHEMA = $(sql_lit "$AUTH_DB") AND TABLE_NAME = 'user_profile'")
declare -A BASE_NICK BASE_COLOR BASE_AVA BASE_TS
BASE_TOTAL=0
if [ "$AUTH_TABLE" = 1 ]; then
    while IFS=$'\x1f' read -r uid nick color ava ts; do
        if [ -z "$uid" ]; then continue; fi
        BASE_NICK[$uid]=$nick BASE_COLOR[$uid]=$color BASE_AVA[$uid]=$ava BASE_TS[$uid]=$ts
        BASE_TOTAL=$((BASE_TOTAL + 1))
    done < <(q_auth "SELECT CONCAT_WS(CHAR(31), user_id, IFNULL(HEX(nickname), ''), avatar_color,
                                             IFNULL(HEX(avatar_image), ''), updated_at)
                     FROM user_profile")
else
    echo "  auth.$AUTH_DB.user_profile 不存在（--execute 会建表，全部按 insert 计划）"
fi

# 非默认行 = 昵称/颜色/头像任一有值：它是「用户或上一轮跑过写出来的」，一律不覆盖
is_default_row() { # $1=uid → 0=全默认(可写) 1=非默认(跳过)
    [ "${BASE_NICK[$1]:-}" = "" ] && [ "${BASE_COLOR[$1]:-0}" = "0" ] && [ "${BASE_AVA[$1]:-}" = "" ]
}

# ---------- ④ 计划：insert（无行）/ fill（全默认行补齐）/ skip（非默认，不覆盖） ----------
: >"$WORK/plan.tsv"
N_INSERT=0 N_FILL=0 N_SKIP=0
for uid in $(printf '%s\n' "${!SRC_TS[@]}" | sort -n); do
    if [ -z "${BASE_TS[$uid]:-}" ]; then
        action=insert N_INSERT=$((N_INSERT + 1))
    elif is_default_row "$uid"; then
        action=fill N_FILL=$((N_FILL + 1))
    else
        action=skip N_SKIP=$((N_SKIP + 1))
    fi
    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' \
        "$uid" "$action" "${SRC_DB[$uid]}" "${SRC_TS[$uid]}" \
        "${SRC_NICK[$uid]}" "${SRC_COLOR[$uid]}" "${SRC_AVA[$uid]}" >>"$WORK/plan.tsv"
done

# 字节数（HEX 一字符 = 半字节）：打印长度类信息，**不打印昵称与头像内容**
blen() { echo $((${#1} / 2)); }

echo "== 计划：源 $SRC_TOTAL 个 uid（insert $N_INSERT / fill $N_FILL / skip $N_SKIP；auth 现有行 $BASE_TOTAL）"
echo "   单库来源：仅 calorie $ONLY_CAL 个（expense 的 outlook 账号无资料行，由 calorie 行补齐）、仅 expense $ONLY_EXP 个"
printf '  %-10s %-7s %-14s %-14s %-8s %-6s %s\n' "uid" "动作" "源库" "updated_at" "昵称字节" "颜色" "头像字节"
while IFS=$'\x1f' read -r uid action db ts nick color ava; do
    printf '  %-10s %-7s %-14s %-14s %-8s %-6s %s\n' \
        "$uid" "$action" "$db" "$ts" "$(blen "$nick")" "$color" "$(blen "$ava")"
done <"$WORK/plan.tsv"

# 源 uid 却在 auth.users 查无此账号 → 建出的档案行没有归属（孤儿），打印警报：
# 不拦本次合并（合并规则以日记资料行为准），但这种行必须被人看见后去处理。
ALL_UIDS=$(cut -d $'\x1f' -f1 "$WORK/plan.tsv" | paste -sd, -)
declare -A AUTH_USERS=()
while IFS= read -r id; do
    if [ -n "$id" ]; then AUTH_USERS[$id]=1; fi
done < <(q_auth "SELECT id FROM users WHERE id IN ($ALL_UIDS)")
MISSING=()
for uid in $(cut -d $'\x1f' -f1 "$WORK/plan.tsv" | sort -n); do
    if [ -z "${AUTH_USERS[$uid]:-}" ]; then MISSING+=("$uid"); fi
done
if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "  警告：以下 uid 有日记资料行但 auth.users 查无此账号（孤儿，需人工核对）：${MISSING[*]}"
fi

if [ "$EXECUTE" != 1 ]; then
    echo "== dry-run 当前状态（只读；缺行/不一致正是待做的活，不算失败）："
    if [ "$AUTH_TABLE" = 1 ]; then
        while IFS=$'\x1f' read -r uid action db ts nick color ava; do
            got=$(q_auth "SELECT CONCAT_WS(';', IFNULL(HEX(nickname), ''), avatar_color,
                                   IFNULL(HEX(avatar_image), ''), updated_at)
                          FROM user_profile WHERE user_id = $uid")
            want="$nick;$color;$ava;$ts"
            if [ -z "$got" ]; then
                printf '  uid %-10s 无行 → 将 %s\n' "$uid" "$action"
            elif [ "$got" = "$want" ]; then
                printf '  uid %-10s 与源一致（已并入）\n' "$uid"
            else
                printf '  uid %-10s 有行但与源不同 → 本次按规则 %s（非默认行只 skip，不覆盖）\n' "$uid" "$action"
            fi
        done <"$WORK/plan.tsv"
    else
        echo "  表不存在 → 全部 $SRC_TOTAL 个 uid 都将按 insert 建行"
    fi
    echo "== dry-run 结束（一个字节都没写，建表也没建）。加 --execute 才动手。"
    exit 0
fi

# ---------- ⑤ 执行：只写 auth，整批一个事务 ----------
echo "== 改前基线：auth.user_profile 行数 $BASE_TOTAL"
if [ "$AUTH_TABLE" != 1 ]; then
    q_auth "$PROFILE_DDL"
    echo "== 已建表 user_profile"
fi

# 行内字段一律走 _utf8mb4 X'…'（HEX 出来的字节按 utf8mb4 解读，与连接字符集无关）；
# avatar HEX 为空 → NULL（auth 侧 null = 无头像）。
hex_lit() { if [ -z "$1" ]; then printf 'NULL'; else printf "_utf8mb4 X'%s'" "$1"; fi; }
str_lit() { printf "_utf8mb4 X'%s'" "$1"; }

{
    echo "START TRANSACTION;"
    while IFS=$'\x1f' read -r uid action db ts nick color ava; do
        case "$action" in
            insert)
                echo "INSERT INTO user_profile (user_id, nickname, avatar_color, avatar_image, updated_at)"
                echo "VALUES ($uid, $(str_lit "$nick"), $color, $(hex_lit "$ava"), $ts);"
                ;;
            fill)
                # WHERE 带全默认守卫：从计划到执行之间若有人写过这行，0 行受影响、
                # 不覆盖；事后校验按「写入的行应等于源」把这种竞态抓成失败
                echo "UPDATE user_profile SET nickname = $(str_lit "$nick"), avatar_color = $color,"
                echo "    avatar_image = $(hex_lit "$ava"), updated_at = $ts"
                echo "WHERE user_id = $uid AND nickname = '' AND avatar_color = 0"
                echo "  AND (avatar_image IS NULL OR avatar_image = '');"
                ;;
            skip) ;; # 计划阶段已判定不覆盖，不产生任何语句
        esac
    done <"$WORK/plan.tsv"
    echo "COMMIT;"
} >"$WORK/tx.sql"

STMTS=$(grep -c ';' "$WORK/tx.sql" || true)
echo "== auth 库事务（$STMTS 条语句，含 BEGIN/COMMIT）…"
q_auth "$(cat "$WORK/tx.sql")" || die "auth 库事务失败（已回滚，一行都没写；修好后整脚本重跑，幂等）"
echo "   完成"

# ---------- ⑥ 改后校验（只读，任一不符退出码非 0） ----------
echo "== 校验："
FAILURES=0
note() { printf '  %s\n' "$*"; }

while IFS=$'\x1f' read -r uid action db ts nick color ava; do
    got=$(q_auth "SELECT CONCAT_WS(';', IFNULL(HEX(nickname), ''), avatar_color,
                           IFNULL(HEX(avatar_image), ''), updated_at)
                  FROM user_profile WHERE user_id = $uid")
    want="$nick;$color;$ava;$ts"
    if [ -z "$got" ]; then
        note "uid $uid：auth 无行（源 $db） ← 不符"
        FAILURES=$((FAILURES + 1))
        continue
    fi
    case "$action" in
        insert | fill)
            if [ "$got" != "$want" ]; then
                note "uid $uid：本次写入的行与源不一致 ← 不符（got=$got want=$want）"
                FAILURES=$((FAILURES + 1))
            else
                note "uid $uid：$action 完成，四字段与源一致"
            fi
            ;;
        skip)
            bas="${BASE_NICK[$uid]};${BASE_COLOR[$uid]};${BASE_AVA[$uid]};${BASE_TS[$uid]}"
            if [ "$got" != "$bas" ]; then
                note "uid $uid：跳过的行在执行期间被改动 ← 不符（基线=$bas 现在=$got）"
                FAILURES=$((FAILURES + 1))
            elif [ "$got" != "$want" ]; then
                # 与日记源不同但与基线一致 = auth 侧用户后来改过档案：按规则本就不覆盖，
                # 不是迁移错误，打印出来让运维知道差异从哪来
                note "uid $uid：skip（auth 已有非默认行，未覆盖；与日记源的差异属 auth 侧后续改动）"
            else
                note "uid $uid：skip（已并入且与源一致）"
            fi
            ;;
    esac
done <"$WORK/plan.tsv"

# 不在本次计划里的 auth 行（用户在 auth 自己建/改的档案）：必须一字未动
for uid in "${!BASE_TS[@]}"; do
    if grep -q "^$uid"$'\x1f' "$WORK/plan.tsv"; then continue; fi
    got=$(q_auth "SELECT CONCAT_WS(';', IFNULL(HEX(nickname), ''), avatar_color,
                           IFNULL(HEX(avatar_image), ''), updated_at)
                  FROM user_profile WHERE user_id = $uid")
    bas="${BASE_NICK[$uid]};${BASE_COLOR[$uid]};${BASE_AVA[$uid]};${BASE_TS[$uid]}"
    if [ "$got" != "$bas" ]; then
        note "uid $uid：不在计划内的既有行被改动 ← 不符"
        FAILURES=$((FAILURES + 1))
    fi
done

AFTER=$(q_auth "SELECT COUNT(*) FROM user_profile")
note "auth.user_profile 行数：$BASE_TOTAL → $AFTER（计划写入 $((N_INSERT + N_FILL))、跳过 $N_SKIP）"

if [ "$FAILURES" != 0 ]; then
    die "校验未通过（$FAILURES 项）——对着上面的输出处理，修好后整脚本重跑（幂等）"
fi
echo "并入完成，校验全绿。"
