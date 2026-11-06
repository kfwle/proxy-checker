package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/yzewe/proxy-checker/internal/cores"
)

// checkViaSingBox builds a minimal sing-box config with socks inbound + one outbound
// parsed from the link, starts `sing-box run -c cfg`, probes testURL through it.
func checkViaSingBox(ctx context.Context, link string, testURL string, timeout time.Duration) (bool, int64, string) {
	_, ms, errStr := fetchViaSingBox(ctx, link, testURL, timeout, true)
	if errStr == "ERR_NO_BINARY" {
		return false, 0, errStr
	}
	if errStr != "" {
		return false, 0, errStr
	}
	return true, ms, ""
}

// fetchViaSingBox поднимает sing-box с outbound из ссылки и делает GET targetURL
// через локальный socks-inbound. Возвращает тело (до 64К), пинг, ошибку.
// discard=true — тело выкидывать (обычный чек), false — вернуть (exit-ip).
func fetchViaSingBox(ctx context.Context, link string, targetURL string, timeout time.Duration, discard bool) ([]byte, int64, string) {
	port, cleanup, errStr := startSingBox(ctx, link, timeout)
	if errStr != "" {
		return nil, 0, errStr
	}
	defer cleanup()
	return probeSocksURL(ctx, port, targetURL, timeout, !discard)
}

// startSingBox поднимает sing-box с outbound из ссылки и socks-inbound на
// свободном порту. Процесс живёт до cleanup() или отмены ctx.
func startSingBox(ctx context.Context, link string, timeout time.Duration) (int, func(), string) {
	bin := filepath.Join(cores.CoresDir(), "sing-box")
	if _, err := os.Stat(bin); err != nil {
		if _, err2 := os.Stat(bin + ".exe"); err2 != nil {
			return 0, nil, "ERR_NO_BINARY"
		} else {
			bin += ".exe"
		}
	}
	outbound, err := buildSingBoxOutbound(link)
	if err != nil {
		return 0, nil, err.Error()
	}
	// free local port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err.Error()
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := map[string]any{
		"log": map[string]any{"level": "warning"},
		"inbounds": []any{
			map[string]any{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port},
		},
		"outbounds": []any{outbound, map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": outbound["tag"]},
	}
	tmp, err := os.CreateTemp("", "sb-*.json")
	if err != nil {
		return 0, nil, err.Error()
	}
	_ = json.NewEncoder(tmp).Encode(cfg)
	tmp.Close()

	cctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cctx, bin, "run", "-c", tmp.Name())
	// stderr в буфер: если конфиг кривой, sing-box падает сразу —
	// покажем его ошибку вместо глухого "inbound не поднялся"
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(tmp.Name())
		return 0, nil, err.Error()
	}
	exited := make(chan struct{})
	go func() {
		// именно cmd.Wait, а не Process.Wait: закрывает pipe-горутины
		// (иначе они утекают) и синхронизирует запись stderr
		_ = cmd.Wait()
		close(exited)
	}()
	cleanup := func() {
		_ = cmd.Process.Kill()
		<-exited
		cancel()
		os.Remove(tmp.Name())
	}
	// wait for socks inbound
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-exited:
			msg := strings.TrimSpace(stderr.String())
			cleanup()
			if msg != "" {
				return 0, nil, "sing-box упал на старте: " + lastLines(msg, 3)
			}
			return 0, nil, "sing-box упал на старте"
		default:
		}
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			<-exited
			msg := strings.TrimSpace(stderr.String())
			cleanup()
			if msg != "" {
				return 0, nil, "sing-box inbound не поднялся: " + lastLines(msg, 3)
			}
			return 0, nil, "sing-box inbound не поднялся за 10с"
		}
		time.Sleep(150 * time.Millisecond)
	}
	return port, cleanup, ""
}

// lastLines возвращает последние n строк (sing-box пишет FATAL в конец).
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, " | ")
	if len(out) > 400 {
		out = out[:400] + "…"
	}
	return out
}

// buildSingBoxOutbound converts common link formats to sing-box outbound JSON.
// Covers: vless/vmess/ss/trojan/hysteria2/hysteria/anytls/tuic/juicity/naive/shadowtls/socks/http/mieru.
func buildSingBoxOutbound(link string) (map[string]any, error) {
	l := strings.TrimSpace(link)
	u, err := url.Parse(l)
	if err != nil || u.Scheme == "" {
		return nil, fmt.Errorf("не смог распарсить ссылку (нужен scheme://...)")
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = u.Query().Get("port")
	}
	if host == "" {
		// tg links handled elsewhere
		return nil, fmt.Errorf("пустой host")
	}
	p := 443
	if port != "" {
		fmt.Sscanf(port, "%d", &p)
	}
	q := u.Query()
	tlsEnabled := q.Get("security") == "tls" || q.Get("security") == "reality" || scheme == "trojan" || p == 443 && (scheme == "vless" || scheme == "vmess")
	tls := map[string]any{"enabled": tlsEnabled}
	if tlsEnabled {
		if sni := q.Get("sni"); sni != "" {
			tls["server_name"] = sni
		} else if hn := q.Get("host"); hn != "" {
			tls["server_name"] = hn
		} else {
			tls["server_name"] = host
		}
		if q.Get("insecure") == "1" || q.Get("allowInsecure") == "1" || q.Get("skip-cert-verify") == "1" {
			tls["insecure"] = true
		}
	}
	// REALITY: без блока reality sing-box не пройдёт хендшейк (false dead)
	if q.Get("security") == "reality" {
		pbk := q.Get("pbk")
		if pbk == "" {
			pbk = q.Get("public_key")
		}
		if pbk != "" {
			sid := q.Get("sid")
			if sid == "" {
				sid = q.Get("short_id")
			}
			tls["reality"] = map[string]any{"enabled": true, "public_key": pbk, "short_id": sid}
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": firstOr(q.Get("fp"), "chrome")}
		}
	}
	switch scheme {
	case "vless":
		uuid := strings.TrimPrefix(u.User.String(), "//")
		// url.User: username is uuid
		if u.User != nil {
			uuid = u.User.Username()
		}
		ob := map[string]any{"type": "vless", "tag": "out", "server": host, "server_port": p, "uuid": uuid, "tls": tls}
		if q.Get("flow") != "" {
			ob["flow"] = q.Get("flow")
		}
		transport := transportOf(q)
		if transport != nil {
			ob["transport"] = transport
		}
		return ob, nil
	case "vmess":
		// vmess://base64-json or vmess://uuid@host:port?params
		if pl, perr := parseVmessBase64(l); perr == nil {
			vtls := map[string]any{"enabled": false}
			sec := strings.ToLower(pl.q("security"))
			if sec == "tls" || sec == "reality" || pl.Port == 443 {
				vtls["enabled"] = true
				vtls["server_name"] = pl.sni()
				if pl.insecure() {
					vtls["insecure"] = true
				}
			}
			ob := map[string]any{"type": "vmess", "tag": "out", "server": pl.Host, "server_port": pl.Port, "uuid": pl.User, "security": firstOr(pl.q("scy"), "auto"), "tls": vtls}
			if t := transportOf(pl.Params); t != nil {
				ob["transport"] = t
			}
			return ob, nil
		}
		uuid := ""
		if u.User != nil {
			uuid = u.User.Username()
		}
		ob := map[string]any{"type": "vmess", "tag": "out", "server": host, "server_port": p, "uuid": uuid, "security": "auto", "tls": tls}
		if t := transportOf(q); t != nil {
			ob["transport"] = t
		}
		return ob, nil
	case "ss", "shadowsocks":
		// все формы (включая целиком base64) разбирает общий парсер
		method, password := "aes-256-gcm", ""
		if pl, perr := parseLink(l); perr == nil {
			// у ss://<base64> url.Parse видит host как base64-блоб — берём из парсера
			if pl.Host != "" && pl.Port > 0 {
				host, p = pl.Host, pl.Port
			}
			if pl.User != "" {
				method = pl.User
			} else if v := q.Get("method"); v != "" {
				method = v
			}
			password = pl.Password
		} else {
			method = q.Get("method")
			if u.User != nil {
				password, _ = u.User.Password()
				if password == "" {
					password = u.User.Username()
				}
				if method == "" {
					if pw, ok := u.User.Password(); ok && pw != "" {
						method = u.User.Username()
						password = pw
					}
				}
			}
			if method == "" {
				method = "aes-256-gcm"
			}
		}
		if password == "" {
			return nil, fmt.Errorf("нет пароля в ss-ссылке")
		}
		return map[string]any{"type": "shadowsocks", "tag": "out", "server": host, "server_port": p, "method": method, "password": password}, nil
	case "trojan":
		pw := ""
		if u.User != nil {
			pw = u.User.Username()
		}
		tls["enabled"] = true
		if _, ok := tls["server_name"]; !ok {
			tls["server_name"] = host
		}
		ob := map[string]any{"type": "trojan", "tag": "out", "server": host, "server_port": p, "password": pw, "tls": tls}
		if t := transportOf(q); t != nil {
			ob["transport"] = t
		}
		return ob, nil
	case "hy2", "hysteria2":
		pw, _ := u.User.Password()
		if pw == "" && u.User != nil {
			pw = u.User.Username()
		}
		tls["enabled"] = true
		if _, ok := tls["server_name"]; !ok {
			tls["server_name"] = host
		}
		if q.Get("insecure") == "1" {
			tls["insecure"] = true
		}
		ob := map[string]any{"type": "hysteria2", "tag": "out", "server": host, "server_port": p, "password": pw, "tls": tls}
		// obfs (salamander) — без него hy2 с obfs не поднимется
		if ot := q.Get("obfs"); ot != "" {
			obfs := map[string]any{"type": ot}
			if op := q.Get("obfs-password"); op != "" {
				obfs["password"] = op
			} else if op := q.Get("obfs_password"); op != "" {
				obfs["password"] = op
			}
			ob["obfs"] = obfs
		}
		return ob, nil
	case "hysteria":
		return map[string]any{"type": "hysteria", "tag": "out", "server": host, "server_port": p, "tls": tls}, nil
	case "anytls":
		pw := ""
		if u.User != nil {
			pw = u.User.Username()
		}
		// AnyTLS всегда поверх TLS (sing-box: "TLS required")
		tls["enabled"] = true
		if _, ok := tls["server_name"]; !ok {
			tls["server_name"] = host
		}
		if q.Get("insecure") == "1" || q.Get("allowInsecure") == "1" || q.Get("skip-cert-verify") == "1" {
			tls["insecure"] = true
		}
		return map[string]any{"type": "anytls", "tag": "out", "server": host, "server_port": p, "password": pw, "tls": tls}, nil
	case "tuic":
		uuid := ""
		pw := ""
		if u.User != nil {
			uuid = u.User.Username()
			pw, _ = u.User.Password()
		}
		tls["enabled"] = true
		return map[string]any{"type": "tuic", "tag": "out", "server": host, "server_port": p, "uuid": uuid, "password": pw, "tls": tls, "congestion_control": q.Get("congestion_control")}, nil
	case "naive", "naive+https", "naive+quic":
		user := ""
		pw := ""
		if u.User != nil {
			user = u.User.Username()
			pw, _ = u.User.Password()
		}
		network := "tcp"
		if strings.Contains(strings.ToLower(l), "quic") {
			network = "quic"
		}
		return map[string]any{"type": "naive", "tag": "out", "server": host, "server_port": p, "username": user, "password": pw, "network": network, "tls": map[string]any{"enabled": true, "server_name": host}}, nil
	case "shadowtls":
		// shadowtls://password@host:port?version=3&host=sni — sing-box outbound type shadowtls
		pw := ""
		if u.User != nil {
			pw = u.User.Username()
		}
		return map[string]any{"type": "shadowtls", "tag": "out", "server": host, "server_port": p, "password": pw, "tls": tls}, nil
	case "socks", "socks5", "socks5h", "socks4":
		user := ""
		pw := ""
		if u.User != nil {
			user = u.User.Username()
			pw, _ = u.User.Password()
		}
		return map[string]any{"type": "socks", "tag": "out", "server": host, "server_port": p, "username": user, "password": pw}, nil
	case "http", "https":
		user := ""
		pw := ""
		if u.User != nil {
			user = u.User.Username()
			pw, _ = u.User.Password()
		}
		return map[string]any{"type": "http", "tag": "out", "server": host, "server_port": p, "username": user, "password": pw, "tls": map[string]any{"enabled": scheme == "https"}}, nil
	case "wireguard", "wg":
		return nil, fmt.Errorf("wireguard через sing-box требует private-key — добавьте ключ в ссылку")
	}
	return nil, fmt.Errorf("протокол %s пока не собирается в sing-box outbound", scheme)
}

func transportOf(q url.Values) map[string]any {
	t := q.Get("type")
	if t == "" {
		t = q.Get("transport")
	}
	switch t {
	case "ws", "websocket":
		return map[string]any{"type": "ws", "path": firstOr(q.Get("path"), "/"), "headers": map[string]any{"Host": q.Get("host")}}
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": q.Get("serviceName")}
	case "httpupgrade":
		return map[string]any{"type": "httpupgrade", "path": firstOr(q.Get("path"), "/"), "host": q.Get("host")}
	case "quic":
		return map[string]any{"type": "quic"}
	}
	return nil
}

func firstOr(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
