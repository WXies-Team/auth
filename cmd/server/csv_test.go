package main

import "testing"

// CSV 公式注入的中和：邮箱/UA 是用户可控字段，= + - @ 开头在 Excel 里会被当公式。
// 这条钉住前缀单引号的行为，防止有人「简化」掉。
func TestCSVCellNeutralizesFormula(t *testing.T) {
	cases := map[string]string{
		"=1+1":          "'=1+1",
		"+cmd":          "'+cmd",
		"-2+3":          "'-2+3",
		"@SUM(A1)":      "'@SUM(A1)",
		"\t=1":          "'\t=1",
		"\r=1":          "'\r=1",
		"u@example.com": "u@example.com", // @ 不在开头，不动
		"":              "",
		"normal":        "normal",
	}
	for in, want := range cases {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}
