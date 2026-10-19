package auth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/WXies-Team/auth/internal/protocol"
)

// 档案三件套（昵称 / 头像色 / 头像图）收归本服务统一存取——OIDC UserInfo 同款思路：
// 档案是身份的一部分，归身份提供方；两个日记 App 的 profiles 资料列由
// scripts/migrate-profile-to-auth.sh 并入 user_profile，之后一律走本文件的读写。

const (
	// maxNicknameRunes 是昵称上限（按**字符**计），与日记库 profiles.nickname 的
	// VARCHAR(64) 同宽：校验和列宽卡在同一处，落库才不会被 MySQL 静默截断。
	maxNicknameRunes = 64

	// maxAvatarImageBytes 是头像**解码后**的字节上限（700KB）。
	//
	// 依据（2026-10-19 在生产日记两库实测 avatar_image 规模）：
	//   - calorie-diary 现存最大 30,956 个 base64 字符（JPEG，解码约 23.2KB），
	//     expense-diary 最大 10,780 字符（解码约 8KB）；
	//   - 日记客户端与服务端的现行自我上限是 avatarImage.take(200_000) / maxAvatarBytes
	//     = 200,000 个 base64 字符（解码 150,000 字节 ≈ 146KB），见两仓 sync.go；
	//   - 700KB 解码 ≈ 955,736 个 base64 字符：约为实测最大值的 31 倍、日记侧现行
	//     上限的 4.7 倍——留足换更高分辨率头像的余量，又把「拿大文件当头像」挡在门外。
	// 客户端现行上限（200,000 字符）远低于本值，所以老客户端永远撞不到 413。
	maxAvatarImageBytes = 700 * 1024
)

// profileDefault 是「库里没有这一行」时的默认回执：nickname ""、avatarColor 0、
// avatarImage nil（JSON null）、updatedAt 0。
func profileDefault() *protocol.ProfileResponse { return &protocol.ProfileResponse{} }

// GetProfile 读档案，无行回默认值（从未设置过档案的账号不该拿到 404）。
//
// avatar_image 的空串与 NULL 一律归一成 nil：日记侧「空串 = 无头像」，两侧任何一种
// 存法都要回同一个 JSON 形状（null），否则客户端拿 "" 与拿 null 会分叉处理。
func (s *Service) GetProfile(userID int64) (*protocol.ProfileResponse, error) {
	var (
		nickname string
		color    int
		avatar   sql.NullString
		updated  int64
	)
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT nickname, avatar_color, avatar_image, updated_at FROM user_profile WHERE user_id = ?",
		userID).Scan(&nickname, &color, &avatar, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return profileDefault(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("查用户档案: %w", err)
	}
	return &protocol.ProfileResponse{
		Nickname:    nickname,
		AvatarColor: color,
		AvatarImage: nonEmpty(avatar),
		UpdatedAt:   updated,
	}, nil
}

// UpdateProfile 全量替换三字段并置 updated_at=now，回写后的档案。
//
// 审计成败都记（profile.update）：detail 只放**字段名与长度类元信息**
//（nickname 字符数、avatarImage 字符数/是否携带、被拒的字段名），
// **绝不放昵称内容与头像数据**——audit_logs 本身不能成为泄密面。
func (s *Service) UpdateProfile(c Caller, req protocol.ProfileUpdateRequest) (resp *protocol.ProfileResponse, err error) {
	detail := map[string]string{
		"nickname_len":     strconv.Itoa(utf8.RuneCountInString(req.Nickname)),
		"avatar_image_set": "0",
	}
	if req.AvatarImage != nil {
		detail["avatar_image_set"] = "1"
		detail["avatar_image_len"] = strconv.Itoa(len(*req.AvatarImage))
	}
	defer func() {
		// 失败时 rejected_field 已由校验失败分支填好；detail 里只有字段名与长度类
		// 元信息，被拒的具体原因文案走 ApiError 回给调用方、不落库
		s.Audit(AuditEvent{
			Action: AuditProfileUpdate, OK: err == nil, ActorUID: uidPtr(c.UID),
			ActorEmail: maskEmail(c.Email), Meta: c.Meta, Detail: detail,
		})
	}()

	nickname, avatar, badField, err := validateProfile(req.Nickname, req.AvatarColor, req.AvatarImage)
	if err != nil {
		detail["rejected_field"] = badField
		return nil, err
	}

	updated := time.Now().UnixMilli()
	var image any
	if avatar != nil {
		image = *avatar
	}
	// upsert 而不是 update-then-insert：档案行由首个写入者创建，与「无行回默认值」
	// 的读口径配对（无行 ≠ 不存在的用户）。ON DUPLICATE KEY 走重复参数而不是
	// VALUES()——后者自 MySQL 8.0.20 起废弃。
	if _, err = s.pool.ExecContext(context.Background(),
		`INSERT INTO user_profile (user_id, nickname, avatar_color, avatar_image, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE nickname = ?, avatar_color = ?, avatar_image = ?, updated_at = ?`,
		c.UID, nickname, req.AvatarColor, image, updated,
		nickname, req.AvatarColor, image, updated); err != nil {
		return nil, fmt.Errorf("写用户档案: %w", err)
	}
	return &protocol.ProfileResponse{
		Nickname:    nickname,
		AvatarColor: req.AvatarColor,
		AvatarImage: avatar,
		UpdatedAt:   updated,
	}, nil
}

// validateProfile 校验并归一三字段，badField 是被拒时的字段名（审计 detail 用）。
//
//	nickname     trim 后按字符计 ≤64，允许空串（=未设置）；存 trim 后的值
//	avatarColor  必须落在 INT 列的取值范围内（超出范围落库会撞 1264 变 500）
//	avatarImage  nil 或空串 = 清除头像；非空必须是**标准字母表 + 带 padding 的 base64
//	             （无换行）**——与客户端 Base64.NO_WRAP 的产物逐字一致，不接受 data:
//	             前缀与 URL 变体（现行客户端不产生，收下等于替未来埋歧义）
func validateProfile(nickname string, avatarColor int, avatar *string) (string, *string, string, error) {
	nick := strings.TrimSpace(nickname)
	if utf8.RuneCountInString(nick) > maxNicknameRunes {
		return "", nil, "nickname",
			badRequest(fmt.Sprintf("昵称最多%d个字，请精简后重试", maxNicknameRunes))
	}
	if avatarColor < math.MinInt32 || avatarColor > math.MaxInt32 {
		return "", nil, "avatar_color",
			badRequest("头像颜色取值超出范围，请重新选择颜色")
	}
	if avatar == nil || *avatar == "" {
		return nick, nil, "", nil
	}
	data, err := base64.StdEncoding.DecodeString(*avatar)
	if err != nil {
		return "", nil, "avatar_image",
			badRequest("头像图片必须是 Base64 编码，请重新上传图片")
	}
	if len(data) > maxAvatarImageBytes {
		// 超限走 413 而不是 400：它不是「格式错」，重填同样的内容还是超，
		// 客户端与运维按载荷问题处理（what = 图片过大 + 上限，next = 压缩后重传）
		return "", nil, "avatar_image",
			&HTTPError{413, fmt.Sprintf("头像图片过大（上限%dKB），请压缩后重新上传", maxAvatarImageBytes/1024)}
	}
	return nick, avatar, "", nil
}

// nonEmpty 把 NULL 与空串都折成 nil（JSON null = 无头像），见 GetProfile 注释。
func nonEmpty(ns sql.NullString) *string {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	s := ns.String
	return &s
}
