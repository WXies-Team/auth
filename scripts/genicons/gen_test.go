package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// 生成器必须与入库的资产字节一致：任何人改了字形/配色但忘了重生，这里先红。
//（regenerate 是纯函数，PNG 编码无时间戳——同一份输入恒同一份字节。）
func TestGeneratedAssetsInSync(t *testing.T) {
	files, err := generate()
	if err != nil {
		t.Fatalf("生成资产: %v", err)
	}
	if len(files) != 6 {
		t.Fatalf("资产清单应为 6 份（3 邮件图标 + apple-touch + ico + svg），得到 %d", len(files))
	}
	for _, f := range files {
		got, err := os.ReadFile(filepath.Join("..", "..", f.rel))
		if err != nil {
			t.Errorf("缺资产 %s: %v（跑 go run ./scripts/genicons 重生）", f.rel, err)
			continue
		}
		if !bytes.Equal(got, f.data) {
			t.Errorf("%s 与生成器输出不一致（跑 go run ./scripts/genicons 重生）", f.rel)
		}
	}
}

// 三个邮件图标的 Content-ID 名必须与 internal/mail 的内嵌注册表口径一致
//（cid = 文件名 + "-icon"）——文件名拼错会让邮件里出现裂图。
func TestMailIconFilenamesMatchCIDConvention(t *testing.T) {
	want := map[string]bool{"calorie-diary.png": true, "expense-diary.png": true, "auth.png": true}
	files, err := generate()
	if err != nil {
		t.Fatalf("生成资产: %v", err)
	}
	got := map[string]bool{}
	for _, f := range files {
		if dir, name := filepath.Split(f.rel); dir == "internal/mail/icons/" {
			got[name] = true
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("缺邮件图标 %s", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("邮件图标应恰为 %v，得到 %v", want, got)
	}
}
