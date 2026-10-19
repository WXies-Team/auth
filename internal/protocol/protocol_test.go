package protocol

import (
	"reflect"
	"testing"
)

// diaryAuthDTOSnapshot 是日记仓 AuthDtos.kt 的**字段快照**（快照式对拍）。
//
// 来源：HoratioShaw/calorie-diary
// shared/src/commonMain/kotlin/cn/horatio/caloriediary/shared/dto/AuthDtos.kt，
// 2026-10-19 快照。日记仓是**私有仓**（gh api repos/HoratioShaw/calorie-diary
// 确认 private=true），本仓 CI 的凭据跨仓读不到真文件，checkout 对拍走不通——
// 只能钉快照：日记侧改字段需来这里同步更新，漂移会被本测试当场抓住，比无约束强。
var diaryAuthDTOSnapshot = map[string][]string{
	"AuthRequest":                {"email", "password", "code", "app"},
	"AuthResponse":               {"token", "email"},
	"SendCodeRequest":            {"email", "purpose", "app"},
	"ResetPasswordRequest":       {"email", "code", "password"},
	"LoginCodeRequest":           {"email", "code", "app"},
	"SendChangeEmailCodeRequest": {"email"},
	"ChangeEmailRequest":         {"password", "email", "code"},
	"ChangePasswordRequest":      {"oldPassword", "newPassword"},
	"ChangePasswordCodeRequest":  {"code", "password"},
	"DeleteAccountRequest":       {"password"},
}

// protocolAuthDTOs 把快照里的类名对到本包的结构体（同名对应，不做别名映射）。
var protocolAuthDTOs = map[string]reflect.Type{
	"AuthRequest":                reflect.TypeOf(AuthRequest{}),
	"AuthResponse":               reflect.TypeOf(AuthResponse{}),
	"SendCodeRequest":            reflect.TypeOf(SendCodeRequest{}),
	"ResetPasswordRequest":       reflect.TypeOf(ResetPasswordRequest{}),
	"LoginCodeRequest":           reflect.TypeOf(LoginCodeRequest{}),
	"SendChangeEmailCodeRequest": reflect.TypeOf(SendChangeEmailCodeRequest{}),
	"ChangeEmailRequest":         reflect.TypeOf(ChangeEmailRequest{}),
	"ChangePasswordRequest":      reflect.TypeOf(ChangePasswordRequest{}),
	"ChangePasswordCodeRequest":  reflect.TypeOf(ChangePasswordCodeRequest{}),
	"DeleteAccountRequest":       reflect.TypeOf(DeleteAccountRequest{}),
}

// TestProtocolMatchesDiaryAuthDtos 逐类比对本包结构体的 json tag 与日记侧
// AuthDtos.kt 的字段快照（Kotlin 的属性名即序列化后的 JSON 字段名，顺序也钉住——
// 客户端序列化按声明序，字段序漂移意味着两边快照该一起看一眼）。双向比对：
// 本仓多出的类也要进快照，防止悄悄加了一个「与日记同名同概念」的 DTO 却没人知道。
func TestProtocolMatchesDiaryAuthDtos(t *testing.T) {
	for name, fields := range diaryAuthDTOSnapshot {
		typ, ok := protocolAuthDTOs[name]
		if !ok {
			t.Errorf("快照里的 %s 在 protocol 包找不到同名结构体", name)
			continue
		}
		var got []string
		for i := 0; i < typ.NumField(); i++ {
			got = append(got, typ.Field(i).Tag.Get("json"))
		}
		if !reflect.DeepEqual(got, fields) {
			t.Errorf("%s 字段与日记侧快照不一致:\n 本仓:   %v\n 日记侧: %v", name, got, fields)
		}
	}
	for name := range protocolAuthDTOs {
		if _, ok := diaryAuthDTOSnapshot[name]; !ok {
			t.Errorf("本仓新增的 %s 不在日记侧快照里——确认是新端点后补进快照", name)
		}
	}
}
