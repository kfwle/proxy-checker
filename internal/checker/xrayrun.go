package checker

// Xray-раннер: собирает конфиг (socks-inbound + 1 outbound из ссылки),
// запускает `xray run -c`, гоняет testURL через локальный socks.
// Поддержано: vless/vmess/ss/trojan/socks/http (+tls/reality/ws/grpc).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yzewe/proxy-checker/internal/cores"
)

func xrayBin() (string, bool) {
	bin := filepath.Join(cores.CoresDir(), xrayBinaryName())
	if st, err := os.Stat(bin); err == nil && !st.IsDir() {
		return bin, true
	}
	return "", false
}

func xrayBinaryName() string {
	if runtime.GOOS == "windows" {
		return "xray.exe"
	}
	return "xray"
}

// xrayStream строит streamSettings из ссылки.
func xrayStream(pl *parsedLink) map[string]any {
	sec := strings.ToLower(pl.q("security"))
	tlsEnabled := sec == "tls" || sec == "reality"
	if !tlsEnabled && (pl.Scheme == "trojan" || (pl.Port == 443 && (pl.Scheme == "vless" || pl.Scheme == "vmess"))) {
		tlsEnabled = true
		sec = "tls"
	}
	ss := map[string]any{"network": "tcp"}
	if tlsEnabled {
		sni := pl.sni()
		if sec == "reality" {
			rs := map[string]any{"serverName": sni}
			if v := pl.q("fp", "fingerprint"); v != "" {
				rs["fingerprint"] = v
			} else {
				rs["fingerprint"] = "chrome"
			}
			if v := pl.q("pbk", "publickey", "public-key"); v != "" {
				rs["publicKey"] = v
			}
			if v := pl.q("sid", "shortid", "short-id"); v != "" {
				rs["shortId"] = v
			}
			if v := pl.q("spx", "spiderx", "spider-x"); v != "" {
				rs["spiderX"] = v
			} else {
				rs["spiderX"] = "/"
			}
			ss["security"] = "reality"
			ss["realitySettings"] = rs
		} else {
			tlsCfg := map[string]any{"serverName": sni}
			if pl.insecure() {
				tlsCfg["insecure"] = true
			}
			if v := pl.q("fp", "fingerprint"); v != "" {
				tlsCfg["fingerprint"] = v
			}
			if v := pl.q("alpn"); v != "" {
				tlsCfg["alpn"] = strings.Split(v, ",")
			}
			ss["security"] = "tls"
			ss["tlsSettings"] = tlsCfg
		}
	}
	switch pl.transport() {
	case "ws":
		ss["network"] = "ws"
		ws := map[string]any{"path": pl.wsPath()}
		if h := pl.wsHost(); h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		ss["wsSettings"] = ws
	case "grpc":
		ss["network"] = "grpc"
		ss["grpcSettings"] = map[string]any{"serviceName": pl.q("serviceName", "service_name", "svc")}
	case "httpupgrade":
		ss["network"] = "httpupgrade"
		up := map[string]any{"path": pl.wsPath()}
		if h := pl.wsHost(); h != "" {
			up["host"] = h
		}
		ss["httpupgradeSettings"] = up
	}
	return ss
}

// buildXrayOutbound собирает outbound для xray.
func buildXrayOutbound(pl *parsedLink) (map[string]any, error) {
	switch pl.Scheme {
	case "vless":
		if pl.User == "" {
			return nil, fmt.Errorf("нет uuid в vless-ссылке")
		}
		users := map[string]any{"id": pl.User, "encryption": "none"}
		if v := pl.q("flow"); v != "" {
			users["flow"] = v
		}
		return map[string]any{
			"protocol": "vless", "tag": "out",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": pl.Host, "port": pl.Port, "users": []any{users}}}},
			"streamSettings": xrayStream(pl),
		}, nil
	case "vmess":
		if pl.User == "" {
			return nil, fmt.Errorf("нет uuid в vmess-ссылке")
		}
		alter := 0
		fmt.Sscanf(pl.q("alterId", "alterid", "aid"), "%d", &alter)
		sec := pl.q("scy", "security", "cipher")
		if sec == "" || sec == "tls" || sec == "reality" || sec == "none" {
			sec = "auto"
		}
		return map[string]any{
			"protocol": "vmess", "tag": "out",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": pl.Host, "port": pl.Port, "users": []any{map[string]any{"id": pl.User, "alterId": alter, "security": sec}}}}},
			"streamSettings": xrayStream(pl),
		}, nil
	case "ss", "shadowsocks":
		method := pl.User
		if method == "" {
			method = pl.q("method")
		}
		if method == "" {
			method = "aes-256-gcm"
		}
		return map[string]any{
			"protocol": "shadowsocks", "tag": "out",
			"settings": map[string]any{"servers": []any{map[string]any{"address": pl.Host, "port": pl.Port, "method": method, "password": pl.Password, "uot": false}}},
		}, nil
	case "trojan":
		if pl.Password == "" && pl.User == "" {
			return nil, fmt.Errorf("нет пароля в trojan-ссылке")
		}
		pw := pl.Password
		if pw == "" {
			pw = pl.User
		}
		return map[string]any{
			"protocol": "trojan", "tag": "out",
			"settings":       map[string]any{"servers": []any{map[string]any{"address": pl.Host, "port": pl.Port, "password": pw}}},
			"streamSettings": xrayStream(pl),
		}, nil
	case "socks", "socks5", "socks5h", "socks4":
		srv := map[string]any{"address": pl.Host, "port": pl.Port}
		if pl.User != "" {
			srv["users"] = []any{map[string]any{"user": pl.User, "pass": pl.Password}}
		}
		return map[string]any{
			"protocol": "socks", "tag": "out",
			"settings": map[string]any{"servers": []any{srv}},
		}, nil
	case "http", "https":
		srv := map[string]any{"address": pl.Host, "port": pl.Port}
		if pl.User != "" {
			srv["users"] = []any{map[string]any{"user": pl.User, "pass": pl.Password}}
		}
		return map[string]any{
			"protocol": "http", "tag": "out",
			"settings": map[string]any{"servers": []any{srv}},
		}, nil
	}
	return nil, fmt.Errorf("xray не умеет %s", pl.Scheme)
}

// checkViaXray поднимает xray и гоняет targetURL через локальный socks.
func checkViaXray(ctx context.Context, link, targetURL string, timeout time.Duration) (bool, int64, string) {
	body, ms, errStr := fetchViaXray(ctx, link, targetURL, timeout, true)
	if errStr != "" {
		return false, 0, errStr
	}
	_ = body
	return true, ms, ""
}

func fetchViaXray(ctx context.Context, link, targetURL string, timeout time.Duration, discard bool) ([]byte, int64, string) {
	bin, ok := xrayBin()
	if !ok {
		return nil, 0, "ERR_NO_BINARY"
	}
	pl, err := parseLink(link)
	if err != nil {
		return nil, 0, err.Error()
	}
	outbound, err := buildXrayOutbound(pl)
	if err != nil {
		return nil, 0, err.Error()
	}
	port, err := freePort()
	if err != nil {
		return nil, 0, err.Error()
	}
	cfg := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"protocol": "socks", "listen": "127.0.0.1", "port": port, "settings": map[string]any{"udp": false}}},
		"outbounds": []any{outbound, map[string]any{"protocol": "freedom", "tag": "direct"}},
	}
	tmp, err := os.CreateTemp("", "xray-*.json")
	if err != nil {
		return nil, 0, err.Error()
	}
	defer os.Remove(tmp.Name())
	_ = json.NewEncoder(tmp).Encode(cfg)
	tmp.Close()

	cctx, cancel := context.WithTimeout(ctx, timeout+15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "run", "-c", tmp.Name())
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, 0, err.Error()
	}
	exited := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(exited)
	}()
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-exited:
			return nil, 0, "xray упал на старте: " + lastLines(stderr.String(), 3)
		default:
		}
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			if s := strings.TrimSpace(stderr.String()); s != "" {
				return nil, 0, "xray inbound не поднялся: " + lastLines(s, 3)
			}
			return nil, 0, "xray inbound не поднялся за 10с"
		}
		time.Sleep(150 * time.Millisecond)
	}
	return probeSocksURL(cctx, port, targetURL, timeout, !discard)
}
