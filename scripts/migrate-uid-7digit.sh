#!/usr/bin/env bash
#
# migrate-uid-7digit.sh —— 三库（auth / calorie-diary / expense-diary）用户 uid
# 从 63 位雪花整数一次性改写成 7 位随机数（1,000,000–9,999,999）。
#
# ============================ 顺序铁律 ============================
#   ① 先部署签发 7 位 uid 的 auth 新版（新版一上线就不再产生雪花 uid，
#      本脚本的改写面从此只减不增）
#   ② 再 --execute 跑本脚本（存量数据一次改写；三库各一个事务，幂等可重跑）
#   ③ 客户端无需改造：uid 只是 JSON 数字，7 位与 63 位对客户端同形
#
# ①先于②的理由：反过来先改数据的话，还活着的旧版 auth 会继续用雪花号注册/并入，
# 新旧行立刻分裂成两套 uid。中途某库失败不回滚已提交的库——修好后直接重跑：
# old→new 映射与 auth 库改号同事务落 uid7_migration_map，重跑复用已登记的新号，
# 只补没跑完的库。
# =====================================================================
#
# 用法（默认 dry-run，全程只读）：
#   AUTH_DSN='user:pass@tcp(host:port)/auth' \
#   CALORIE_DSN='user:pass@tcp(host:port)/calorie-diary' \
#   EXPENSE_DSN='user:pass@tcp(host:port)/expense-diary' \
#     bash scripts/migrate-uid-7digit.sh             # dry-run：打印计划与当前状态
#     ...同上... bash scripts/migrate-uid-7digit.sh --execute
#
# 环境变量（Go 风格 DSN；**脚本内零凭据**，密码不得含 `@`——Go DSN 用它分隔凭据与地址）：
#   AUTH_DSN     auth 账号库（users / sessions / audit_logs / 两步与 passkey 四表 /
#                ai_usage / 既有 uid_migration_map）
#   CALORIE_DSN  热量日记业务库
#   EXPENSE_DSN  开支日记业务库（含它本地的 uid_migration_map）
#
# 依赖：mysql、od、awk、sed。
# 幂等：已是 7 位的账号跳过；没活时打印「无事可做」，有活时打印改写计数。
# 收尾校验（三库只读）：旧 uid 残留必须 0、user_id 悬空必须 0、
# auth 库 users.id 全部落在 7 位号段、各表行数与改前一致、映射表 new_uid 全部有主——
# 任一不满足退出码非 0。
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

for c in mysql od awk sed; do command -v "$c" >/dev/null || die "缺少依赖命令：$c"; done
: "${AUTH_DSN:?缺少 AUTH_DSN（auth 库 Go 风格 DSN）}"
: "${CALORIE_DSN:?缺少 CALORIE_DSN（热量日记业务库 DSN）}"
: "${EXPENSE_DSN:?缺少 EXPENSE_DSN（开支日记业务库 DSN）}"

# Go 风格 DSN 拆成 mysql CLI 参数（照抄两仓 migrate-uid.sh 的口径）：
# 密码走 MYSQL_PWD，不进 argv（ps 里看不到）。限制：密码不能含 @。
parse_dsn() { # $1=dsn $2=前缀 → 设 ${P}_USER/_PASS/_HOST/_PORT/_DB
    local dsn="$1" p="$2"
    # DSN 末尾的 ?query（charset/parseTime 等）按 Go 语法允许存在，mysql CLI 用不上，
    # 正则把它单独吃掉而不是当库名的一部分
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

# -N -B：无表头、TAB 分隔，直接进 bash 解析。
# stderr 过掉 MariaDB 客户端那句无害的 ssl-verify 提示（每个连接一句会淹掉真输出），
# 其余错误照旧冒出来，退出码也照旧由 set -e 兜住。
_MYSQL_ERR() { grep -v 'ssl-verify-server-cert' >&2; }
q_auth() { MYSQL_PWD="$AUTH_PASS" mysql -h "$AUTH_HOST" -P "$AUTH_PORT" -u "$AUTH_USER" -N -B "$AUTH_DB" -e "$1" 2> >(_MYSQL_ERR); }
q_cal() { MYSQL_PWD="$CAL_PASS" mysql -h "$CAL_HOST" -P "$CAL_PORT" -u "$CAL_USER" -N -B "$CAL_DB" -e "$1" 2> >(_MYSQL_ERR); }
q_exp() { MYSQL_PWD="$EXP_PASS" mysql -h "$EXP_HOST" -P "$EXP_PORT" -u "$EXP_USER" -N -B "$EXP_DB" -e "$1" 2> >(_MYSQL_ERR); }

# SQL 单引号字面量（库名取自 DSN、属外部输入，进查询前必须转义）
sql_lit() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"; }

UID_LO=1000000
UID_HI=9999999

WORK="$(mktemp -d "${TMPDIR:-/tmp}/migrate-uid7.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# 本脚本建的映射表（仅 --execute）：old_uid 主键，雪花 uid → 新 7 位 uid。
# 三库各一个事务、没有跨库原子性，这张表就是「跑到哪了」的落点：
# 它与 auth 库改号同事务提交，重跑时工作集直接复用已登记的新号，不重摇。
MAP_TABLE=uid7_migration_map

echo "== uid 7 位改写（$([ "$EXECUTE" = 1 ] && echo 'EXECUTE' || echo 'dry-run，只看不写')）=="
echo "目标库：auth=$AUTH_DB  calorie=$CAL_DB  expense=$EXP_DB"

# ---------- ① 外键普查：有外键就得按依赖改序，非级联的一律先停 ----------
fk_check() { # $1=查询函数 $2=库名 $3=标签
    local out
    out=$("$1" "SELECT CONCAT(k.TABLE_NAME, '.', k.COLUMN_NAME, ' -> ', k.REFERENCED_TABLE_NAME,
                    '.', k.REFERENCED_COLUMN_NAME, ' (', r.UPDATE_RULE, ')')
                FROM information_schema.KEY_COLUMN_USAGE k
                JOIN information_schema.REFERENTIAL_CONSTRAINTS r
                  ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA
                 AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
                WHERE k.TABLE_SCHEMA = $(sql_lit "$2") AND k.REFERENCED_TABLE_NAME IS NOT NULL")
    if [ -z "$out" ]; then
        echo "  $3：无外键约束 → 按『子表先、users.id 最后』改序（与两仓既有 migrate-uid.sh 同序）"
        return 0
    fi
    echo "  $3：查到外键（改序依据）："
    sed 's/^/    /' <<<"$out"
    if grep -v '(CASCADE)$' <<<"$out" | grep -q .; then
        die "$3 存在非级联外键：级联的会跟着父键走，非级联的父子同改必撞约束——先人工定改序再跑"
    fi
    echo "    全部 ON UPDATE CASCADE：父键改完子键自动跟随，子表语句届时是空操作"
}
echo "== 外键普查（信息来源 information_schema，只读）："
fk_check q_auth "$AUTH_DB" auth
fk_check q_cal "$CAL_DB" calorie-diary
fk_check q_exp "$EXP_DB" expense-diary

# ---------- ② 表/列逐个核对 information_schema，缺的跳过并打印 ----------
# 表清单以两仓既有 migrate-uid.sh 为准；calorie 侧 household 两表按实际存在与否取舍。
AUTH_SPECS=(
    "users:id"
    "sessions:user_id"
    "audit_logs:actor_uid,target_uid"
    "login_states:user_id"
    "passkeys:user_id"
    "totp_factors:user_id"
    "recovery_codes:user_id"
    "webauthn_challenges:user_id"
    "ai_usage:subject"
    "uid_migration_map:uid,new_id,new_uid"
)
CAL_SPECS=(
    "users:id"
    "profiles:user_id"
    "meal_items:user_id"
    "weight_entries:user_id"
    "user_settings:user_id"
    "water_entries:user_id"
    "delete_events:user_id"
    "push_inbox:user_id"
    "push_reminder_backup:user_id"
    "push_device_token:user_id"
    "households:owner_user_id"
    "household_members:user_id"
    "ai_usage:subject"
)
EXP_SPECS=(
    "users:id"
    "profiles:user_id"
    "transactions:user_id"
    "accounts:user_id"
    "categories:user_id"
    "budgets:user_id"
    "templates:user_id"
    "recurrences:user_id"
    "savings_goals:user_id"
    "user_settings:user_id"
    "delete_events:user_id"
    "push_device_token:user_id"
    "push_inbox:user_id"
    "push_reminder_backup:user_id"
    "households:owner_user_id"
    "household_members:user_id"
    "ai_usage:subject"
    "uid_migration_map:new_uid"
)

# resolve <查询函数> <库名> <标签> <表:列,...>... → 往 P_<库> 计划数组追加 "kind|表|列"
# kind：col（user_id 类列）/ usersid（users.id）/ subject（ai_usage 的字符串 uid）
#       / mapcol（映射表里的 uid 列）
declare -a P_AUTH=() P_CAL=() P_EXP=()
resolve() {
    local q="$1" schema="$2" label="$3" spec t cols c kind has
    shift 3
    for spec in "$@"; do
        t="${spec%%:*}"
        IFS=',' read -ra cols <<<"${spec#*:}"
        has=$("$q" "SELECT COUNT(*) FROM information_schema.TABLES
                     WHERE TABLE_SCHEMA = $(sql_lit "$schema") AND TABLE_NAME = '$t'")
        if [ "$has" != 1 ]; then
            echo "  跳过 $label.$t：表不存在"
            continue
        fi
        for c in "${cols[@]}"; do
            has=$("$q" "SELECT COUNT(*) FROM information_schema.COLUMNS
                         WHERE TABLE_SCHEMA = $(sql_lit "$schema") AND TABLE_NAME = '$t' AND COLUMN_NAME = '$c'")
            if [ "$has" != 1 ]; then
                echo "  跳过 $label.$t.$c：列不存在"
                continue
            fi
            case "$t.$c" in
                users.id) kind=usersid ;;
                ai_usage.subject) kind=subject ;;
                uid_migration_map.*) kind=mapcol ;;
                *) kind=col ;;
            esac
            case "$label" in
                auth) P_AUTH+=("$kind|$t|$c") ;;
                calorie) P_CAL+=("$kind|$t|$c") ;;
                expense) P_EXP+=("$kind|$t|$c") ;;
            esac
        done
    done
}
echo "== 表/列核对（缺的当场跳过）："
resolve q_auth "$AUTH_DB" auth "${AUTH_SPECS[@]}"
resolve q_cal "$CAL_DB" calorie "${CAL_SPECS[@]}"
resolve q_exp "$EXP_DB" expense "${EXP_SPECS[@]}"

# ---------- ③ 号段占用：三库 users.id + 各库 ai_usage 的 user 型 subject ----------
declare -A RESERVED
reserve_ids() { # $1=查询函数
    local id
    while IFS= read -r id; do
        if [[ "$id" =~ ^[0-9]+$ ]]; then RESERVED[$id]=1; fi
    done < <("$1" "SELECT id FROM users
                   UNION SELECT subject FROM ai_usage WHERE scope = 'user'")
}
reserve_ids q_auth
reserve_ids q_cal
reserve_ids q_exp

rand_uid() { # 取一个没被占用的 7 位号；1000 次拿不到就停（号段占用异常，不是可重试故障）
    local raw n i
    for ((i = 0; i < 1000; i++)); do
        raw=$(od -An -N4 -tu4 </dev/urandom | tr -d '[:space:]')
        [[ "$raw" =~ ^[0-9]+$ ]] || die "读 /dev/urandom 失败"
        n=$((raw % 9000000 + UID_LO))
        if [ -z "${RESERVED[$n]+x}" ]; then
            RESERVED[$n]=1
            printf '%s\n' "$n"
            return 0
        fi
    done
    die "连续 1000 次取不到空闲 uid（7 位号段占用异常）"
}

# ---------- ④ 待改写账号 = auth.users 里 id 不在 7 位号段的行 ----------
q_auth "SELECT id, email FROM users WHERE id < $UID_LO OR id > $UID_HI ORDER BY id" >"$WORK/pending.tsv"
TOTAL=$(grep -c . "$WORK/pending.tsv" || true)

# 既有映射表（dry-run 首跑时表不存在 = 空表处理）
declare -A MAP
map_exists=$(q_auth "SELECT COUNT(*) FROM information_schema.tables
                     WHERE table_schema = $(sql_lit "$AUTH_DB") AND table_name = '$MAP_TABLE'")
if [ "$map_exists" = 1 ]; then
    while IFS=$'\t' read -r old new; do
        if [[ "$old" =~ ^[0-9]+$ && "$new" =~ ^[0-9]+$ ]]; then MAP[$old]=$new; fi
    done < <(q_auth "SELECT old_uid, new_uid FROM $MAP_TABLE")
fi

# 工作集 = 本次待改账号 ∪ 映射表里已登记的全部行（上一轮半途而废的靠它补齐；
# 已完整迁移的行重放一遍更新是 0 行空操作，幂等）。已登记的复用原号，不重摇。
: >"$WORK/work.tsv"
: >"$WORK/newrows.tsv"
while IFS=$'\t' read -r old email; do
    [ -n "$old" ] || continue
    new="${MAP[$old]:-}"
    if [ -z "$new" ]; then
        new=$(rand_uid)
        MAP[$old]=$new
        printf '%s\t%s\n' "$old" "$new" >>"$WORK/newrows.tsv"
    fi
    printf '%s\t%s\t%s\n' "$old" "$new" "$email" >>"$WORK/work.tsv"
done <"$WORK/pending.tsv"
if [ "${#MAP[@]}" -gt 0 ]; then
    for old in "${!MAP[@]}"; do
        if ! grep -q "^$old	" "$WORK/work.tsv"; then
            printf '%s\t%s\t%s\n' "$old" "${MAP[$old]}" "(既有映射)" >>"$WORK/work.tsv"
        fi
    done
fi
WORK_TOTAL=$(grep -c . "$WORK/work.tsv" || true)

if [ "$WORK_TOTAL" = 0 ]; then
    echo "无事可做：三库没有需要改写的账号（auth.users 全部已是 7 位 uid）。"
    exit 0
fi

echo "== 待改写账号：$TOTAL 个（工作集 $WORK_TOTAL 条，含既有映射补齐）"

# ---------- ⑤ 生成各库事务体 ----------
# 子表先、users.id 最后（与两仓既有 migrate-uid.sh 同序，users 行最后改兼作行锁）。
# 业务库的占位行（sync 锁互斥行）email 里嵌着 uid：id 改了 email 得跟着改，
# 否则下一次 sync 按新 id 另建一把锁，旧串留在库里当孤儿。
build_tx() { # $1=计划数组名 $2=映射文件 $3=是否业务库(1/0) → stdout 输出事务 SQL
    local plan_name="$1" mapf="$2" biz="$3"
    local -n plan="$plan_name"
    local pass e kind t c rest old new
    echo "START TRANSACTION;"
    for pass in main last; do
        # 工作集是三列（旧号/新号/邮箱）：只写两个变量会让邮箱并进 new，
        # 下面的整数校验当场中止——第三列必须有归宿
        while IFS=$'\t' read -r old new _email; do
            [[ "$old" =~ ^[0-9]+$ && "$new" =~ ^[0-9]+$ ]] || die "映射不是整数：$old → $new"
            for e in "${plan[@]}"; do
                kind="${e%%|*}"
                rest="${e#*|}"
                t="${rest%%|*}"
                c="${rest#*|}"
                if { [ "$pass" = last ] && [ "$kind" != usersid ]; } ||
                    { [ "$pass" = main ] && [ "$kind" = usersid ]; }; then
                    continue
                fi
                case "$kind" in
                    col)
                        echo "UPDATE $t SET $c = $new WHERE $c = $old;"
                        ;;
                    subject)
                        echo "UPDATE $t SET $c = '$new' WHERE scope = 'user' AND $c = '$old';"
                        ;;
                    mapcol)
                        echo "UPDATE $t SET $c = $new WHERE $c = $old AND $c <> $new;"
                        ;;
                    usersid)
                        if [ "$biz" = 1 ]; then
                            echo "UPDATE users SET id = $new, email = CONCAT('sync-lock-', $new, '@placeholder.invalid') WHERE id = $old AND email LIKE 'sync-lock-%@placeholder.invalid';"
                        fi
                        echo "UPDATE users SET id = $new WHERE id = $old;"
                        ;;
                esac
            done
        done <"$mapf"
    done
    echo "COMMIT;"
}

tables_of() { # $1=计划数组名 → 去重后的表名
    local -n plan="$1"
    local e rest t
    for e in "${plan[@]}"; do
        rest="${e#*|}"
        t="${rest%%|*}"
        printf '%s\n' "$t"
    done | sort -u
}

capture_counts() { # $1=查询函数 $2=计划数组名 $3=输出文件（表名 → 改前行数）
    local t
    : >"$3"
    while IFS= read -r t; do
        printf '%s\t%s\n' "$t" "$("$1" "SELECT COUNT(*) FROM $t")" >>"$3"
    done < <(tables_of "$2")
}

# show_counts <查询函数> <计划数组名> <标签>：dry-run 打印改前基线行数
show_counts() {
    local t
    echo "  -- $3 --"
    while IFS= read -r t; do
        printf '  %-32s %s\n' "$t" "$("$1" "SELECT COUNT(*) FROM $t")"
    done < <(tables_of "$2")
}

FAILURES=0

# validate <查询函数> <标签> <计划数组名> <post(1/0)>
# post=0：只打印当前状态（dry-run 用，残留 >0 属正常）；
# post=1：残留/悬空/非 7 位任何一项非 0 都计入 FAILURES。
validate() {
    local q="$1" label="$2" plan_name="$3" post="$4"
    local -n plan="$plan_name"
    local e kind t c n rest olds oldsql
    olds=$(cut -f1 "$WORK/work.tsv" | paste -sd, -)
    oldsql=$(cut -f1 "$WORK/work.tsv" | awk '{printf "%s\x27%s\x27", (NR > 1 ? "," : ""), $1}')

    n=$("$q" "SELECT COUNT(*) FROM users WHERE id < $UID_LO OR id > $UID_HI")
    printf '  %-34s %s\n' "users.id 非 7 位" "$n"
    if [ "$post" = 1 ] && [ "$n" != 0 ]; then FAILURES=$((FAILURES + 1)); fi

    for e in "${plan[@]}"; do
        kind="${e%%|*}"
        rest="${e#*|}"
        t="${rest%%|*}"
        c="${rest#*|}"
        case "$kind" in
            subject)
                n=$("$q" "SELECT COUNT(*) FROM $t WHERE scope = 'user' AND subject IN ($oldsql)")
                ;;
            *)
                n=$("$q" "SELECT COUNT(*) FROM $t WHERE $c IN ($olds)")
                ;;
        esac
        printf '  %-34s %s\n' "$t.$c 旧值残留" "$n"
        if [ "$post" = 1 ] && [ "$n" != 0 ]; then FAILURES=$((FAILURES + 1)); fi
    done

    for e in "${plan[@]}"; do
        kind="${e%%|*}"
        rest="${e#*|}"
        t="${rest%%|*}"
        c="${rest#*|}"
        # users.id 与映射表没有「本库用户行」这个主语：前者自身就是用户行，
        # 后者的旧行允许指向已注销账号（悬挂是既有状态，不是本次改写造成的）
        if [ "$kind" = usersid ] || [ "$kind" = mapcol ]; then continue; fi
        case "$kind" in
            subject)
                n=$("$q" "SELECT COUNT(*) FROM $t WHERE scope = 'user'
                           AND subject NOT IN (SELECT CAST(id AS CHAR) FROM users)")
                ;;
            *)
                n=$("$q" "SELECT COUNT(*) FROM $t WHERE $c NOT IN (SELECT id FROM users) AND $c <> 0")
                ;;
        esac
        printf '  %-34s %s\n' "$t.$c 悬空(无主)" "$n"
        if [ "$post" = 1 ] && [ "$n" != 0 ]; then FAILURES=$((FAILURES + 1)); fi
    done
}

if [ "$EXECUTE" != 1 ]; then
    echo "== dry-run 计划（只读，不建表、不写任何库）。新旧对照（摇号随机，--execute 会重摇）："
    printf '  %-20s %-20s %s\n' "旧 uid(雪花)" "新 uid(7位)" "邮箱"
    while IFS=$'\t' read -r old new email; do
        printf '  %-20s %-20s %s\n' "$old" "$new" "$email"
    done <"$WORK/work.tsv"
    echo "== dry-run 各表行数（改前基线，--execute 会逐表比对改后是否一致）："
    show_counts q_auth P_AUTH auth
    show_counts q_cal P_CAL calorie-diary
    show_counts q_exp P_EXP expense-diary
    echo "== dry-run 当前状态（残留 >0 属正常，正是待改写的量）："
    echo "  -- auth --"
    validate q_auth auth P_AUTH 0
    echo "  -- calorie-diary --"
    validate q_cal calorie P_CAL 0
    echo "  -- expense-diary --"
    validate q_exp expense P_EXP 0
    echo "== dry-run 结束（一个字节都没写）。加 --execute 才动手。"
    exit 0
fi

# ---------- ⑥ 真改：每库一个事务，auth 先 ----------
echo "== 改写前基线行数 …"
capture_counts q_auth P_AUTH "$WORK/cnt_auth_pre.tsv"
capture_counts q_cal P_CAL "$WORK/cnt_cal_pre.tsv"
capture_counts q_exp P_EXP "$WORK/cnt_exp_pre.tsv"

if [ "$map_exists" != 1 ]; then
    q_auth "CREATE TABLE IF NOT EXISTS $MAP_TABLE (
                old_uid     BIGINT NOT NULL PRIMARY KEY,
                new_uid     BIGINT NOT NULL,
                migrated_at BIGINT NOT NULL
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci"
    echo "== 映射表 $MAP_TABLE 已建"
fi

echo "== ① auth 库事务（登记新号 + 全表改号，同事务提交）…"
{
    echo "START TRANSACTION;"
    if [ -s "$WORK/newrows.tsv" ]; then
        now=$(date +%s)000
        while IFS=$'\t' read -r old new; do
            echo "INSERT INTO $MAP_TABLE (old_uid, new_uid, migrated_at) VALUES ($old, $new, $now);"
        done <"$WORK/newrows.tsv"
    fi
    build_tx P_AUTH "$WORK/work.tsv" 0
} >"$WORK/tx_auth.sql"
q_auth "$(cat "$WORK/tx_auth.sql")" || die "auth 库事务失败（已回滚，映射与改号都没落库；修好后重跑）"
echo "   完成"

echo "== ② calorie-diary 库事务 …"
build_tx P_CAL "$WORK/work.tsv" 1 >"$WORK/tx_cal.sql"
q_cal "$(cat "$WORK/tx_cal.sql")" || die "calorie 库事务失败（已回滚；auth 已改号，重跑本脚本可幂等补齐）"
echo "   完成"

echo "== ③ expense-diary 库事务 …"
build_tx P_EXP "$WORK/work.tsv" 1 >"$WORK/tx_exp.sql"
q_exp "$(cat "$WORK/tx_exp.sql")" || die "expense 库事务失败（已回滚；重跑本脚本可幂等补齐）"
echo "   完成"

echo "== 校验（改写后：残留 / 悬空 / 非 7 位都必须是 0）："
echo "  -- auth --"
validate q_auth auth P_AUTH 1
echo "  -- calorie-diary --"
validate q_cal calorie P_CAL 1
echo "  -- expense-diary --"
validate q_exp expense P_EXP 1

echo "== 行数对照（改前 → 改后，必须一致）："
compare_counts() { # $1=查询函数 $2=改前文件
    local t before after
    while IFS=$'\t' read -r t before; do
        after=$("$1" "SELECT COUNT(*) FROM $t")
        if [ "$after" = "$before" ]; then
            printf '  %-26s %s → %s\n' "$t" "$before" "$after"
        else
            printf '  %-26s %s → %s  ← 行数变了！\n' "$t" "$before" "$after"
            FAILURES=$((FAILURES + 1))
        fi
    done <"$2"
}
compare_counts q_auth "$WORK/cnt_auth_pre.tsv"
compare_counts q_cal "$WORK/cnt_cal_pre.tsv"
compare_counts q_exp "$WORK/cnt_exp_pre.tsv"

echo "== 对照表（$MAP_TABLE）："
orphan_map=$(q_auth "SELECT COUNT(*) FROM $MAP_TABLE m LEFT JOIN users u ON u.id = m.new_uid WHERE u.id IS NULL")
still_old=$(q_auth "SELECT COUNT(*) FROM $MAP_TABLE m JOIN users u ON u.id = m.old_uid")
printf '  %-20s %-20s %s\n' "旧 uid" "新 uid" "邮箱"
q_auth "SELECT m.old_uid, m.new_uid, IFNULL(u.email, '<账号已注销>')
        FROM $MAP_TABLE m LEFT JOIN users u ON u.id = m.new_uid
        ORDER BY m.old_uid" |
    while IFS=$'\t' read -r old new email; do
        printf '  %-20s %-20s %s\n' "$old" "$new" "$email"
    done
printf '  映射 %s 条；new_uid 无主 %s；users.id 仍是旧值 %s\n' \
    "$(grep -c . "$WORK/work.tsv")" "$orphan_map" "$still_old"
if [ "$orphan_map" != 0 ]; then FAILURES=$((FAILURES + 1)); fi
if [ "$still_old" != 0 ]; then FAILURES=$((FAILURES + 1)); fi

if [ "$FAILURES" != 0 ]; then
    die "校验未通过（$FAILURES 项）——对着上面的输出处理，修好后整脚本重跑（幂等）"
fi
echo "迁移完成，校验全绿。"
