package checker

// Mihomo-раннер: YAML-конфиг (mixed-port + 1 proxy из ссылки),
// запуск `mihomo -d workdir -f cfg`, URL-тест через mixed-port.
// Поддержано: ss/vmess/vless/trojan/hysteria2/hysteria/tuic/socks/http.

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yzewe/proxy-checker/internal/cores"
)

func mihomoBin() (string, bool) {
	bin := filepath.Join(cores.CoresDir(), mihomoBinaryName())
	if st, err := os.Stat(bin); err == nil && !st.IsDir() {
		return bin, true
	}
	return "", false
}

func mihomoBinaryName() string {
	if runtime.GOOS == "windows" {
		return "mihomo.exe"
	}
	return "mihomo"
}

// yamlEmit — минимальный YAML-сериализатор (строки всегда в кавычках).
func yamlEmit(v any, indent int) string {
	pad := strings.Repeat("  ", indent)
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		for _, k := range keys {
			val := t[k]
			switch val.(type) {
			case map[string]any, []any:
				sb.WriteString(pad + k + ":\n" + yamlEmit(val, indent+1))
			default:
				sb.WriteString(pad + k + ": " + yamlScalar(val) + "\n")
			}
		}
		return sb.String()
	case []any:
		var sb strings.Builder
		for _, item := range t {
			switch item.(type) {
			case map[string]any:
				m := item.(map[string]any)
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				first := true
				for _, k := range keys {
					val := m[k]
					switch val.(type) {
					case map[string]any, []any:
						if first {
							sb.WriteString(pad + "- " + k + ":\n" + yamlEmit(val, indent+2))
							first = false
						} else {
							sb.WriteString(pad + "  " + k + ":\n" + yamlEmit(val, indent+2))
						}
					default:
						if first {
							sb.WriteString(pad + "- " + k + ": " + yamlScalar(val) + "\n")
							first = false
						} else {
							sb.WriteString(pad + "  " + k + ": " + yamlScalar(val) + "\n")
						}
					}
				}
			default:
				sb.WriteString(pad + "- " + yamlScalar(item) + "\n")
			}
		}
		return sb.String()
	default:
		return pad + yamlScalar(v) + "\n"
	}
}

func yamlScalar(v any) string {
	switch t := v.(type) {
	case string:
		return strconv.Quote(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// mihomoNet возвращает network + ws/grpc-опции для mihomo-прокси.
func mihomoNet(pl *parsedLink) map[string]any {
	out := map[string]any{}
	switch pl.transport() {
	case "ws":
		out["network"] = "ws"
		ws := map[string]any{"path": pl.wsPath()}
		if h := pl.wsHost(); h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		out["ws-opts"] = ws
	case "grpc":
		out["network"] = "grpc"
		svc := pl.q("serviceName", "service_name", "svc")
		if svc == "" {
			svc = "grpc"
		}
		out["grpc-opts"] = map[string]any{"grpc-service-name": svc}
	default:
		out["network"] = "tcp"
	}
	return out
}

func mihomoTLS(pl *parsedLink, force bool) map[string]any {
	sec := strings.ToLower(pl.q("security"))
	enabled := force || sec == "tls" || sec == "reality"
	if !enabled && (pl.Scheme == "trojan" || pl.Scheme == "hysteria2" || pl.Scheme == "hysteria" || (pl.Port == 443 && (pl.Scheme == "vless" || pl.Scheme == "vmess" || pl.Scheme == "tuic"))) {
		enabled = true
	}
	if !enabled {
		return map[string]any{}
	}
	out := map[string]any{"tls": true, "sni": pl.sni(), "skip-cert-verify": pl.insecure()}
	if v := pl.q("fp", "fingerprint"); v != "" {
		out["fingerprint"] = v
	}
	if v := pl.q("alpn"); v != "" {
		out["alpn"] = strings.Split(v, ",")
	}
	return out
}

func mergeMaps(dst, src map[string]any) map[string]any {
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// buildMihomoProxy собирает mihomo proxy-dict.
func buildMihomoProxy(pl *parsedLink) (map[string]any, error) {
	base := map[string]any{"name": "out", "server": pl.Host, "port": pl.Port}
	switch pl.Scheme {
	case "ss", "shadowsocks":
		method := pl.User
		if method == "" {
			method = pl.q("method")
		}
		if method == "" {
			method = "aes-256-gcm"
		}
		base["type"] = "ss"
		base["cipher"] = method
		base["password"] = pl.Password
		return base, nil
	case "vmess":
		if pl.User == "" {
			return nil, fmt.Errorf("нет uuid в vmess-ссылке")
		}
		alter := 0
		fmt.Sscanf(pl.q("alterId", "alterid", "aid"), "%d", &alter)
		base["type"] = "vmess"
		base["uuid"] = pl.User
		base["alterId"] = alter
		base["cipher"] = "auto"
		base["udp"] = true
		mergeMaps(base, mihomoNet(pl))
		mergeMaps(base, mihomoTLS(pl, false))
		return base, nil
	case "vless":
		if pl.User == "" {
			return nil, fmt.Errorf("нет uuid в vless-ссылке")
		}
		base["type"] = "vless"
		base["uuid"] = pl.User
		base["udp"] = true
		if v := pl.q("flow"); v != "" {
			base["flow"] = v
		}
		if v := pl.q("fp", "fingerprint"); v != "" {
			base["client-fingerprint"] = v
		}
		mergeMaps(base, mihomoNet(pl))
		mergeMaps(base, mihomoTLS(pl, false))
		if pl.q("security") == "reality" {
			ro := map[string]any{}
			if v := pl.q("pbk", "publickey", "public-key"); v != "" {
				ro["public-key"] = v
			}
			if v := pl.q("sid", "shortid", "short-id"); v != "" {
				ro["short-id"] = v
			}
			if len(ro) > 0 {
				base["reality-opts"] = ro
			}
		}
		return base, nil
	case "trojan":
		pw := pl.Password
		if pw == "" {
			pw = pl.User
		}
		if pw == "" {
			return nil, fmt.Errorf("нет пароля в trojan-ссылке")
		}
		base["type"] = "trojan"
		base["password"] = pw
		mergeMaps(base, mihomoNet(pl))
		mergeMaps(base, mihomoTLS(pl, true))
		return base, nil
	case "hy2", "hysteria2":
		password := ""
		// hy2://pass@host или hysteria2://uuid@host?password / userinfo
		if pl.Password != "" {
			password = pl.Password
		} else {
			password = pl.User
		}
		if q := pl.q("password", "auth", "auth_str"); q != "" {
			password = q
		}
		if password == "" {
			return nil, fmt.Errorf("нет пароля в hysteria2-ссылке")
		}
		base["type"] = "hysteria2"
		base["password"] = password
		if v := pl.q("obfs", "obfs-password"); v != "" {
			base["obfs"] = "salamander"
			base["obfs-password"] = pl.q("obfs-password", "obfs_password")
		}
		mergeMaps(base, mihomoTLS(pl, true))
		return base, nil
	case "hysteria":
		password := pl.Password
		if password == "" {
			password = pl.User
		}
		if q := pl.q("auth", "auth_str", "password"); q != "" {
			password = q
		}
		base["type"] = "hysteria"
		base["auth_str"] = password
		base["protocol"] = pl.q("protocol")
		if base["protocol"] == "" {
			base["protocol"] = "udp"
		}
		mergeMaps(base, mihomoTLS(pl, true))
		return base, nil
	case "tuic":
		uuid := pl.User
		password := pl.Password
		if q := pl.q("password"); q != "" {
			password = q
		}
		if uuid == "" || password == "" {
			return nil, fmt.Errorf("нужны uuid и password в tuic-ссылке")
		}
		base["type"] = "tuic"
		base["uuid"] = uuid
		base["password"] = password
		if v := pl.q("congestion-controller", "congestion_controller", "cc"); v != "" {
			base["congestion-controller"] = v
		}
		mergeMaps(base, mihomoTLS(pl, true))
		return base, nil
	case "socks", "socks5", "socks5h", "socks4":
		base["type"] = "socks5"
		if pl.User != "" {
			base["username"] = pl.User
			base["password"] = pl.Password
		}
		return base, nil
	case "http", "https":
		base["type"] = "http"
		if pl.User != "" {
			base["username"] = pl.User
			base["password"] = pl.Password
		}
		if pl.Scheme == "https" {
			base["tls"] = true
		}
		return base, nil
	}
	return nil, fmt.Errorf("mihomo не умеет %s", pl.Scheme)
}

// checkViaMihomo поднимает mihomo и гоняет targetURL через mixed-port.
func checkViaMihomo(ctx context.Context, link, targetURL string, timeout time.Duration) (bool, int64, string) {
	body, ms, errStr := fetchViaMihomo(ctx, link, targetURL, timeout, true)
	if errStr != "" {
		return false, 0, errStr
	}
	_ = body
	return true, ms, ""
}

func fetchViaMihomo(ctx context.Context, link, targetURL string, timeout time.Duration, discard bool) ([]byte, int64, string) {
	port, cleanup, errStr := startMihomo(ctx, link, timeout)
	if errStr != "" {
		return nil, 0, errStr
	}
	defer cleanup()
	return probeSocksURL(ctx, port, targetURL, timeout, !discard)
}

// startMihomo поднимает mihomo с mixed-port и прокси из ссылки.
func startMihomo(ctx context.Context, link string, timeout time.Duration) (int, func(), string) {
	bin, ok := mihomoBin()
	if !ok {
		return 0, nil, "ERR_NO_BINARY"
	}
	pl, err := parseLink(link)
	if err != nil {
		return 0, nil, err.Error()
	}
	proxy, err := buildMihomoProxy(pl)
	if err != nil {
		return 0, nil, err.Error()
	}
	port, err := freePort()
	if err != nil {
		return 0, nil, err.Error()
	}
	workdir, err := os.MkdirTemp("", "mihomo-*")
	if err != nil {
		return 0, nil, err.Error()
	}
	cfg := "mixed-port: " + fmt.Sprintf("%d", port) + "\nlog-level: warning\nmode: rule\n" + yamlEmit(map[string]any{
		"proxies": []any{proxy},
		"proxy-groups": []any{map[string]any{
			"name": "sel", "type": "select", "proxies": []any{"out"},
		}},
		"rules": []any{"MATCH,sel"},
	}, 0)
	if err := os.WriteFile(filepath.Join(workdir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		os.RemoveAll(workdir)
		return 0, nil, err.Error()
	}

	cctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cctx, bin, "-d", workdir, "-f", filepath.Join(workdir, "config.yaml"))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		os.RemoveAll(workdir)
		return 0, nil, err.Error()
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	cleanup := func() {
		_ = cmd.Process.Kill()
		<-exited
		cancel()
		os.RemoveAll(workdir)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-exited:
			msg := strings.TrimSpace(stderr.String())
			cleanup()
			if msg != "" {
				return 0, nil, "mihomo упал на старте: " + lastLines(msg, 3)
			}
			return 0, nil, "mihomo упал на старте"
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
				return 0, nil, "mihomo inbound не поднялся: " + lastLines(msg, 3)
			}
			return 0, nil, "mihomo inbound не поднялся за 10с"
		}
		time.Sleep(150 * time.Millisecond)
	}
	return port, cleanup, ""
}
