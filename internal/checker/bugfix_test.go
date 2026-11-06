package checker

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestClipNoPanic(t *testing.T) {
	if got := clip("network unreachable\n", 300); got != "network unreachable" {
		t.Fatalf("clip(short) = %q", got)
	}
	long := strings.Repeat("a", 400) + "\n"
	if got := clip(long, 300); len(got) != 300 {
		t.Fatalf("clip(long) len = %d, want 300", len(got))
	}
}

func TestSSBase64HostPort(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pass@1.2.3.4:8888"))
	ob, err := buildSingBoxOutbound("ss://" + payload)
	if err != nil {
		t.Fatal(err)
	}
	if ob["server"] != "1.2.3.4" || ob["server_port"] != 8888 {
		t.Fatalf("ss base64 outbound = %v, want 1.2.3.4:8888", ob)
	}
	if ob["method"] != "aes-256-gcm" || ob["password"] != "pass" {
		t.Fatalf("ss creds = %v/%v", ob["method"], ob["password"])
	}
}

func TestVmessBase64(t *testing.T) {
	js := `{"v":"2","add":"example.com","port":"443","id":"uuid-1","aid":"0","scy":"auto","net":"ws","host":"example.com","path":"/ws","tls":"tls","sni":"example.com"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
	ob, err := buildSingBoxOutbound(link)
	if err != nil {
		t.Fatal(err)
	}
	if ob["server"] != "example.com" || ob["server_port"] != 443 || ob["uuid"] != "uuid-1" {
		t.Fatalf("vmess outbound = %v", ob)
	}
	tlsCfg, _ := ob["tls"].(map[string]any)
	if tlsCfg == nil || tlsCfg["enabled"] != true || tlsCfg["server_name"] != "example.com" {
		t.Fatalf("vmess tls = %v", ob["tls"])
	}
	tr, _ := ob["transport"].(map[string]any)
	if tr == nil || tr["type"] != "ws" || tr["path"] != "/ws" {
		t.Fatalf("vmess transport = %v", ob["transport"])
	}
}

func TestRealityBlock(t *testing.T) {
	ob, err := buildSingBoxOutbound("vless://uuid@host.example:443?security=reality&pbk=PUBKEY&sid=ab12&fp=chrome&type=tcp")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, _ := ob["tls"].(map[string]any)
	reality, _ := tlsCfg["reality"].(map[string]any)
	if reality == nil || reality["public_key"] != "PUBKEY" || reality["short_id"] != "ab12" {
		t.Fatalf("reality block = %v", tlsCfg)
	}
}

func TestHysteria2Obfs(t *testing.T) {
	ob, err := buildSingBoxOutbound("hy2://pass@host.example:443?obfs=salamander&obfs-password=secret")
	if err != nil {
		t.Fatal(err)
	}
	obfs, _ := ob["obfs"].(map[string]any)
	if obfs == nil || obfs["type"] != "salamander" || obfs["password"] != "secret" {
		t.Fatalf("obfs = %v", ob["obfs"])
	}
}

func TestInvalidHostPortNoDirect(t *testing.T) {
	ok, _, errStr := checkDirect(context.Background(), "1.2.3.4:108o", "http://127.0.0.1:1", time.Second)
	if ok || errStr != "invalid host:port" {
		t.Fatalf("checkDirect(invalid) = %v, %q", ok, errStr)
	}
}

func TestConfigSelectorCycle(t *testing.T) {
	cfg := `{"outbounds":[
		{"type":"selector","tag":"a","outbounds":["b"]},
		{"type":"selector","tag":"b","outbounds":["a"]},
		{"type":"vless","tag":"v","server":"x.example","server_port":443,"uuid":"u"}
	]}`
	links := ExtractLinks(cfg)
	// главное — не зависнуть/не упасть на цикле; пустой selector-граф
	// уходит в фолбэк «все прямые outbounds», поэтому тут ровно vless
	if len(links) != 1 || !strings.HasPrefix(links[0], "vless://") {
		t.Fatalf("cycle links = %v", links)
	}
}