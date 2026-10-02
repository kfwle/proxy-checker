package checker

import (
	"bufio"
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
	"sync"
	"time"

	"github.com/yzewe/proxy-checker/internal/cores"
)

// Result is one checked proxy.
type Result struct {
	Index    int    `json:"index"`
	Link     string `json:"link"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Alive    bool   `json:"alive"`
	Latency  int64  `json:"latencyMs"`
	Core     string `json:"core"`
	Error    string `json:"error,omitempty"`
	Checked  string `json:"checkedAt"`
}

// Job options from frontend.
type Options struct {
	Concurrency int        `json:"concurrency"`
	TimeoutSec  int        `json:"timeoutSec"`
	TestURL     string     `json:"testUrl"`
	Full        bool       `json:"full"`
	Mode        string     `json:"mode"` // url | tcp | ping
	Cores       []string   `json:"cores"` // выбранные из sing-box/xray/mihomo (пусто = все)
	Rules       []CoreRule `json:"rules"` // per-протокол/транспорт/защита -> ядро
}

// CoreRule: для конкретных proto/transport/security — конкретное ядро.
// Пустые поля = wildcard.
type CoreRule struct {
	Proto     string `json:"proto"`
	Transport string `json:"transport"`
	Security  string `json:"security"`
	Core      string `json:"core"`
}

// Job holds progress + results, streamed via SSE/channel.
type Job struct {
	ID       string
	Links    []string
	Opts     Options
	mu       sync.Mutex
	Results  []Result
	Done     int
	Total    int
	Finished bool
	Started  time.Time
	Saved    []SavedFile
	SaveDir  string
	updates  chan Result
}

func NewJob(id string, links []string, opts Options) *Job {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 16
	}
	if opts.Concurrency > 128 {
		opts.Concurrency = 128
	}
	if opts.TimeoutSec <= 0 {
		opts.TimeoutSec = 8
	}
	if opts.TestURL == "" {
		opts.TestURL = "https://www.gstatic.com/generate_204"
	}
	switch opts.Mode {
	case "tcp", "ping", "icmp", "url":
		if opts.Mode == "icmp" {
			opts.Mode = "ping"
		}
	default:
		opts.Mode = "url"
	}
	return &Job{ID: id, Links: links, Opts: opts, Total: len(links), Started: time.Now(), updates: make(chan Result, 1024)}
}

func (j *Job) Updates() <-chan Result { return j.updates }

func (j *Job) push(r Result) {
	j.mu.Lock()
	j.Results = append(j.Results, r)
	j.Done++
	j.mu.Unlock()
	select {
	case j.updates <- r:
	default:
	}
}

func (j *Job) finish() {
	j.mu.Lock()
	j.Finished = true
	j.mu.Unlock()
	close(j.updates)
}

// Run executes checks with worker pool. Отмена через ctx реально останавливает
// запуск новых проверок (in-flight добивают текущий URL-тест и выходят).
func (j *Job) Run(ctx context.Context) {
	sem := make(chan struct{}, j.Opts.Concurrency)
	var wg sync.WaitGroup
loop:
	for i, link := range j.Links {
		select {
		case <-ctx.Done():
			break loop
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, l string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			r := CheckOne(ctx, idx, l, j.Opts)
			j.push(r)
		}(i, link)
	}
	wg.Wait()
	SaveJob(j)
	j.finish()
}

// CheckOne: выбор метода — url (полный тест через прокси),
// tcp (коннект к host:port), ping (ICMP через системный ping).
func CheckOne(ctx context.Context, idx int, link string, opts Options) Result {
	proto := DetectProtocol(link)
	host, port := ParseHostPort(link)
	timeout := time.Duration(opts.TimeoutSec) * time.Second
	r := Result{Index: idx, Link: link, Protocol: proto, Host: host + func() string {
		if port != "" {
			return ":" + port
		}
		return ""
	}(), Checked: time.Now().Format(time.RFC3339)}
	// juicity/mieru идут только через родные клиенты (sing-box/mihomo их выкинули).
	switch opts.Mode {
	case "tcp":
		ok, ms, errStr := checkTCP(ctx, host, port, timeout)
		r.Core = "tcp"
		r.Alive = ok
		r.Latency = ms
		r.Error = errStr
		return r
	case "ping":
		ok, ms, errStr := checkPing(ctx, host, timeout)
		r.Core = "ping"
		r.Alive = ok
		r.Latency = ms
		r.Error = errStr
		return r
	}
	for _, core := range resolveChain(proto, link, opts) {
		var alive bool
		var latency int64
		var errStr string
		switch core {
		case "direct":
			alive, latency, errStr = checkDirect(ctx, link, opts.TestURL, timeout)
		case "sing-box":
			alive, latency, errStr = checkViaSingBox(ctx, link, opts.TestURL, timeout)
		case "xray":
			alive, latency, errStr = checkViaXray(ctx, link, opts.TestURL, timeout)
		case "mihomo":
			alive, latency, errStr = checkViaMihomo(ctx, link, opts.TestURL, timeout)
		case "juicity-client":
			alive, latency, errStr = checkViaJuicity(ctx, link, opts.TestURL, timeout)
		case "mieru":
			alive, latency, errStr = checkViaMieru(ctx, link, opts.TestURL, timeout)
		case "mtproto-checker":
			alive, latency, errStr = checkViaMtproto(ctx, link, timeout, opts.Full)
		}
		// sing-box missing binary -> try next core, don't mark dead yet
		if errStr == "ERR_NO_BINARY" {
			continue
		}
		r.Core = core
		r.Alive = alive
		r.Latency = latency
		r.Error = errStr
		return r
	}
	r.Core = "none"
	r.Alive = false
	r.Error = "no core/binary available: скачайте ядра во вкладке Ядра"
	return r
}

// --- direct http/socks: только URL-тест, никакого TCP/ICMP пинга ---
// testURL гоняется через прокси, alive = HTTP-ответ < 500.
// bare host:port пробуем как http-прокси, затем как socks5 — тоже URL-тестом.

func checkDirect(ctx context.Context, link string, testURL string, timeout time.Duration) (bool, int64, string) {
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	l := strings.TrimSpace(link)
	low := strings.ToLower(l)
	// bare host:port -> пробуем как прокси через URL-тест (сначала http, потом socks5)
	if !strings.Contains(l, "://") {
		host, port, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return false, 0, "invalid host:port"
		}
		host = strings.TrimSpace(host)
		port = strings.TrimSpace(port)
		var lastErr string
		for _, scheme := range []string{"http", "socks5"} {
			proxyURL, _ := url.Parse(fmt.Sprintf("%s://%s:%s", scheme, host, port))
			ok, ms, errStr := fetchViaProxy(ctx, proxyURL, testURL, timeout)
			if ok {
				return true, ms, ""
			}
			lastErr = errStr
		}
		return false, 0, lastErr
	}
	if strings.HasPrefix(low, "tg://") || strings.Contains(low, "t.me/") {
		return false, 0, "tg-ссылка: нужен модуль mtproto-checker"
	}
	u, err := url.Parse(l)
	if err != nil {
		return false, 0, "bad url"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "socks" && scheme != "socks5" && scheme != "socks5h" && scheme != "socks4" {
		return false, 0, "direct поддерживает только http/socks, нужен sing-box"
	}
	return fetchViaProxy(ctx, u, testURL, timeout)
}

// fetchViaProxy делает единственный URL-тест через прокси.
func fetchViaProxy(ctx context.Context, proxyURL *url.URL, testURL string, timeout time.Duration) (bool, int64, string) {
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, err.Error()
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 500 {
		return false, 0, fmt.Sprintf("bad status %d", resp.StatusCode)
	}
	return true, time.Since(start).Milliseconds(), ""
}

// --- TCP: коннект к host:port сервера, без прокси-логики ---
func checkTCP(ctx context.Context, host, port string, timeout time.Duration) (bool, int64, string) {
	if strings.TrimSpace(host) == "" {
		return false, 0, "не смог вытащить host из ссылки"
	}
	if strings.TrimSpace(port) == "" {
		return false, 0, "нет порта для TCP-проверки"
	}
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(strings.TrimSpace(host), strings.TrimSpace(port)))
	if err != nil {
		return false, 0, err.Error()
	}
	c.Close()
	return true, time.Since(start).Milliseconds(), ""
}

// --- Ping: ICMP через системный ping, без root ---
func checkPing(ctx context.Context, host string, timeout time.Duration) (bool, int64, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return false, 0, "не смог вытащить host из ссылки"
	}
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	if secs > 10 {
		secs = 10
	}
	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{"-n", "1", "-w", fmt.Sprintf("%d", secs*1000), host}
	case "darwin":
		args = []string{"-c", "1", "-t", fmt.Sprintf("%d", secs), host}
	default: // linux
		args = []string{"-c", "1", "-W", fmt.Sprintf("%d", secs), host}
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(secs+2)*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ping", args...).CombinedOutput()
	text := string(out)
	ms := parsePingMs(text)
	if err != nil {
		if ms >= 0 {
			return true, ms, ""
		}
		return false, 0, strings.TrimSpace(text)[:min(300, len(text))]
	}
	if ms >= 0 {
		return true, ms, ""
	}
	// ping отработал без time= (редкий формат) — считаем живым без пинга
	return true, 0, ""
}

func parsePingMs(text string) int64 {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, "time=")
	if idx < 0 {
		idx = strings.Index(lower, "время=")
	}
	if idx < 0 {
		return -1
	}
	rest := lower[idx:]
	// вытащить первое число после =
	num := ""
	dot := false
	started := false
	for _, ch := range rest {
		if ch >= '0' && ch <= '9' {
			num += string(ch)
			started = true
		} else if ch == '.' && started && !dot {
			num += "."
			dot = true
		} else if started {
			break
		}
	}
	if num == "" {
		return -1
	}
	var f float64
	fmt.Sscanf(num, "%f", &f)
	return int64(f + 0.5)
}

func checkViaMtproto(ctx context.Context, link string, timeout time.Duration, full bool) (bool, int64, string) {
	bin := filepath.Join(cores.CoresDir(), "mtproto-checker")
	if _, err := os.Stat(bin); err != nil {
		// windows exe variant
		bin += ".exe"
		if _, err2 := os.Stat(bin); err2 != nil {
			return false, 0, "ERR_NO_BINARY"
		}
	}
	args := []string{"--format", "json", "--timeout", fmt.Sprintf("%ds", int(timeout.Seconds())), "--alive-only", "--quiet", link}
	if full {
		args = append([]string{"--full"}, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		// mtproto-checker exits 1 when no live — parse output anyway
		if out == nil {
			return false, 0, err.Error()
		}
	}
	// try parse JSON array or single
	var arr []map[string]any
	if err := json.Unmarshal(out, &arr); err != nil {
		// maybe NDJSON / lines
		alive := false
		sc := bufio.NewScanner(strings.NewReader(string(out)))
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				if s, _ := m["status"].(string); s == "LIVE" || s == "live" {
					alive = true
				}
			}
		}
		if alive {
			return true, 0, ""
		}
		return false, 0, strings.TrimSpace(string(out))[:min(300, len(out))]
	}
	if len(arr) > 0 {
		return true, 0, ""
	}
	return false, 0, "dead (mtproto-checker: no live)"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
