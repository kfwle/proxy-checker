package checker

// Нативные раннеры juicity и mieru через официальные клиенты:
// juicity-client run -c (foreground, socks-inbound) и
// mieru replace config + start (daemon, HOME изолирован на проверку).
// Оба поднимают локальный socks5 — дальше обычный URL-тест.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yzewe/proxy-checker/internal/cores"
)

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func waitPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// probeSocksURL гоняет targetURL через socks5://127.0.0.1:port.
func probeSocksURL(ctx context.Context, port int, targetURL string, timeout time.Duration, wantBody bool) ([]byte, int64, string) {
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: (&net.Dialer{Timeout: timeout}).DialContext, TLSHandshakeTimeout: timeout}
	c := &http.Client{Transport: tr, Timeout: timeout}
	if targetURL == "" {
		targetURL = "https://www.gstatic.com/generate_204"
	}
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 500 {
		return nil, 0, fmt.Sprintf("bad status %d", resp.StatusCode)
	}
	if !wantBody {
		return nil, time.Since(start).Milliseconds(), ""
	}
	return raw, time.Since(start).Milliseconds(), ""
}

func juicityBin() (string, bool) {
	bin := filepath.Join(cores.CoresDir(), binaryName("juicity-client"))
	if st, err := os.Stat(bin); err == nil && !st.IsDir() {
		return bin, true
	}
	return "", false
}

func mieruBin() (string, bool) {
	bin := filepath.Join(cores.CoresDir(), binaryName("mieru"))
	if st, err := os.Stat(bin); err == nil && !st.IsDir() {
		return bin, true
	}
	return "", false
}

func binaryName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func isWindows() bool { return runtime.GOOS == "windows" }

// linkHostPort вытаскивает host/порт из ссылки; порт может лежать
// в query (?port=50754) — так делает mieru-диплинк mierus://user@host?port=...
func linkHostPort(link string) (host string, port int, errStr string) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Host == "" {
		// tg://proxy?server=H&port=P
		if uu, err2 := url.Parse(strings.TrimSpace(link)); err2 == nil {
			if h := uu.Query().Get("server"); h != "" {
				var p int
				fmt.Sscanf(uu.Query().Get("port"), "%d", &p)
				return h, p, ""
			}
		}
		return "", 0, "не смог распарсить ссылку"
	}
	p := u.Port()
	if p == "" {
		p = u.Query().Get("port")
	}
	var portNum int
	fmt.Sscanf(p, "%d", &portNum)
	return u.Hostname(), portNum, ""
}

// runJuicity поднимает juicity-client, возвращает порт и cleanup.
func runJuicity(ctx context.Context, link string, timeout time.Duration) (int, func(), string) {
	bin, ok := juicityBin()
	if !ok {
		return 0, nil, "ERR_NO_BINARY"
	}
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Host == "" {
		return 0, nil, "не смог распарсить juicity-ссылку"
	}
	user := ""
	pw := ""
	if u.User != nil {
		user = u.User.Username()
		pw, _ = u.User.Password()
	}
	host, serverPort, perr := linkHostPort(link)
	if perr != "" {
		return 0, nil, perr
	}
	if serverPort == 0 {
		return 0, nil, "нет порта в juicity-ссылке (ни в host, ни в ?port=)"
	}
	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("host")
	}
	if sni == "" {
		sni = host
	}
	insecure := q.Get("insecure") == "1" || q.Get("allowInsecure") == "1" || q.Get("skip-cert-verify") == "1"
	cc := q.Get("congestion_control")
	if cc == "" {
		cc = q.Get("congestion-control")
	}
	if cc == "" {
		cc = "bbr"
	}
	localPort, err := freePort()
	if err != nil {
		return 0, nil, err.Error()
	}
	cfg := map[string]any{
		"listen":             fmt.Sprintf("127.0.0.1:%d", localPort),
		"server":             fmt.Sprintf("%s:%d", host, serverPort),
		"uuid":               user,
		"password":           pw,
		"sni":                sni,
		"allow_insecure":     insecure,
		"congestion_control": cc,
		"log_level":          "warn",
	}
	tmp, err := os.CreateTemp("", "juicity-*.json")
	if err != nil {
		return 0, nil, err.Error()
	}
	_ = json.NewEncoder(tmp).Encode(cfg)
	tmp.Close()
	cctx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	cmd := exec.CommandContext(cctx, bin, "run", "-c", tmp.Name())
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(tmp.Name())
		return 0, nil, err.Error()
	}
	cleanup := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		os.Remove(tmp.Name())
	}
	if !waitPort(localPort, 12*time.Second) {
		cleanup()
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return 0, nil, "juicity-client не поднялся: " + lastLines(msg, 3)
		}
		return 0, nil, "juicity-client inbound не поднялся за 12с"
	}
	return localPort, cleanup, ""
}

// runMieru поднимает mieru-клиент с изолированным HOME.
func runMieru(ctx context.Context, link string, timeout time.Duration) (int, func(), string) {
	bin, ok := mieruBin()
	if !ok {
		return 0, nil, "ERR_NO_BINARY"
	}
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Host == "" {
		return 0, nil, "не смог распарсить mieru-ссылку"
	}
	user := ""
	pw := ""
	if u.User != nil {
		user = u.User.Username()
		pw, _ = u.User.Password()
	}
	host, serverPort, perr := linkHostPort(link)
	if perr != "" {
		return 0, nil, perr
	}
	if serverPort == 0 {
		return 0, nil, "нет порта в mieru-ссылке (ни в host, ни в ?port=)"
	}
	socksPort, err := freePort()
	if err != nil {
		return 0, nil, err.Error()
	}
	httpPort, _ := freePort()
	rpcPort, _ := freePort()
	server := map[string]any{"domainName": "", "ipAddress": host, "portBindings": []any{map[string]any{"port": serverPort, "protocol": "TCP"}}}
	if !isIP(host) {
		server = map[string]any{"domainName": host, "ipAddress": "", "portBindings": []any{map[string]any{"port": serverPort, "protocol": "TCP"}}}
	}
	cfg := map[string]any{
		"profiles": []any{map[string]any{
			"profileName": "default",
			"user":        map[string]any{"name": user, "password": pw},
			"servers":     []any{server},
		}},
		"activeProfile": "default",
		"rpcPort":       rpcPort,
		"socks5Port":    socksPort,
		"httpProxyPort": httpPort,
	}
	home, err := os.MkdirTemp("", "mieru-*")
	if err != nil {
		return 0, nil, err.Error()
	}
	cfgPath := filepath.Join(home, "cfg.json")
	b, _ := json.Marshal(cfg)
	_ = os.WriteFile(cfgPath, b, 0o600)
	env := append(os.Environ(), "HOME="+home)
	run := func(args ...string) (string, error) {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cctx, bin, args...)
		cmd.Env = env
		var out strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		return out.String(), err
	}
	// start отдельно: mieru форкает демона, который наследует stdout —
	// вывод только в файл, иначе Run повиснет на вечно открытом pipe.
	startDaemon := func(args ...string) (string, error) {
		logPath := filepath.Join(home, "start.log")
		f, err := os.Create(logPath)
		if err != nil {
			return "", err
		}
		defer f.Close()
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cctx, bin, args...)
		cmd.Env = env
		cmd.Stdout = f
		cmd.Stderr = f
		err = cmd.Run()
		b, _ := os.ReadFile(logPath)
		return string(b), err
	}
	if out, err := run("replace", "config", cfgPath); err != nil {
		os.RemoveAll(home)
		return 0, nil, "mieru replace config: " + lastLines(out, 3)
	}
	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cctx, bin, "stop")
		cmd.Env = env
		_ = cmd.Run()
		os.RemoveAll(home)
	}
	if out, err := startDaemon("start"); err != nil {
		cleanup()
		return 0, nil, "mieru start: " + lastLines(out, 3)
	}
	if !waitPort(socksPort, 12*time.Second) {
		cleanup()
		return 0, nil, "mieru inbound не поднялся за 12с"
	}
	return socksPort, cleanup, ""
}

func isIP(h string) bool {
	if h == "" {
		return false
	}
	dots := 0
	for _, c := range h {
		switch {
		case c >= '0' && c <= '9':
		case c == '.':
			dots++
		case c == ':':
			return true
		default:
			return false
		}
	}
	return dots == 3
}

func checkViaJuicity(ctx context.Context, link, testURL string, timeout time.Duration) (bool, int64, string) {
	port, cleanup, errStr := runJuicity(ctx, link, timeout)
	if errStr != "" {
		return false, 0, errStr
	}
	defer cleanup()
	_, ms, errStr := probeSocksURL(ctx, port, testURL, timeout, false)
	if errStr != "" {
		return false, 0, errStr
	}
	return true, ms, ""
}

func checkViaMieru(ctx context.Context, link, testURL string, timeout time.Duration) (bool, int64, string) {
	port, cleanup, errStr := runMieru(ctx, link, timeout)
	if errStr != "" {
		return false, 0, errStr
	}
	defer cleanup()
	_, ms, errStr := probeSocksURL(ctx, port, testURL, timeout, false)
	if errStr != "" {
		return false, 0, errStr
	}
	return true, ms, ""
}

func fetchBodyViaJuicity(ctx context.Context, link, targetURL string, timeout time.Duration) ([]byte, int64, string) {
	port, cleanup, errStr := runJuicity(ctx, link, timeout)
	if errStr != "" {
		return nil, 0, errStr
	}
	defer cleanup()
	return probeSocksURL(ctx, port, targetURL, timeout, true)
}

func fetchBodyViaMieru(ctx context.Context, link, targetURL string, timeout time.Duration) ([]byte, int64, string) {
	port, cleanup, errStr := runMieru(ctx, link, timeout)
	if errStr != "" {
		return nil, 0, errStr
	}
	defer cleanup()
	return probeSocksURL(ctx, port, targetURL, timeout, true)
}
