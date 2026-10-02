package daily

// Ежедневный прогон публичного socks5-листа:
// раз в сутки качает proxy.txt (лимит 3к строк со скользящим окном),
// чекает URL-тестом, живые раскладывает по странам, сохраняет в results/daily/.
// Анти-429: сам лист качается 1 раз в сутки, geo — только для живых + вечный кэш.

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
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const listURL = "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"

type State struct {
	Enabled   bool   `json:"enabled"`
	LastRun   string `json:"lastRun,omitempty"`
	Offset    int    `json:"offset"`
	LastTotal int    `json:"lastTotal,omitempty"`
	LastAlive int    `json:"lastAlive,omitempty"`
	Running   bool   `json:"running,omitempty"`
	LastError string `json:"lastError,omitempty"`
}

var (
	mu    sync.Mutex
	state State
)

func dataDir() string {
	if v := os.Getenv("CHECKER_DATA_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "data")
	}
	return "data"
}

func statePath() string { return filepath.Join(dataDir(), "daily.json") }

func Load() State {
	mu.Lock()
	defer mu.Unlock()
	if b, err := os.ReadFile(statePath()); err == nil {
		_ = json.Unmarshal(b, &state)
		return state
	}
	// по умолчанию включено: первый запуск сразу ставит enabled
	state = State{Enabled: true}
	saveLocked()
	return state
}

func saveLocked() {
	_ = os.MkdirAll(dataDir(), 0o755)
	b, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(statePath(), b, 0o644)
}

func Status() State {
	mu.Lock()
	defer mu.Unlock()
	return state
}

// SetEnabled включает/выключает. При включении — сразу прогон 1к (в фоне);
// если живых 0 — берёт следующие 1к (до 5 чанков), всё с дедупом.
func SetEnabled(on bool) State {
	mu.Lock()
	state.Enabled = on
	saveLocked()
	mu.Unlock()
	if on {
		go runFill(1000, 5)
	}
	return Status()
}

// RunNow ручной пуск на limit строк.
func RunNow(limit int) {
	go runFill(limit, 1)
}

func runFill(limit, maxChunks int) {
	mu.Lock()
	if state.Running {
		mu.Unlock()
		return
	}
	state.Running = true
	state.LastError = ""
	saveLocked()
	mu.Unlock()
	defer func() {
		mu.Lock()
		state.Running = false
		saveLocked()
		mu.Unlock()
	}()

	lines, err := fetchList()
	if err != nil {
		setErr(err.Error())
		return
	}
	totalAlive := 0
	totalChecked := 0
	for c := 0; c < maxChunks; c++ {
		chunk := takeChunk(lines, limit)
		alive := checkChunk(chunk)
		totalChecked += len(chunk)
		totalAlive += len(alive)
		saveDaily(alive)
		mu.Lock()
		state.LastTotal = totalChecked
		state.LastAlive = totalAlive
		state.LastRun = time.Now().Format("2006-01-02 15:04")
		saveLocked()
		mu.Unlock()
		if totalAlive > 0 {
			break
		}
	}
}

// StartScheduler тикает раз в 15 мин: если включено и сегодня ещё не бегало — прогон 3к.
func StartScheduler() {
	Load()
	go func() {
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for range t.C {
			mu.Lock()
			on := state.Enabled
			running := state.Running
			today := time.Now().Format("2006-01-02")
			done := strings.HasPrefix(state.LastRun, today)
			mu.Unlock()
			if on && !running && !done {
				runFill(3000, 1)
			}
		}
	}()
}

func setErr(msg string) {
	mu.Lock()
	state.LastError = msg
	saveLocked()
	mu.Unlock()
}

// fetchList качает лист, кэширует на сутки в data/proxy.txt.
func fetchList() ([]string, error) {
	_ = os.MkdirAll(dataDir(), 0o755)
	p := filepath.Join(dataDir(), "proxy.txt")
	if st, err := os.Stat(p); err == nil && time.Since(st.ModTime()) < 24*time.Hour {
		return readLines(p)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	req, _ := http.NewRequest("GET", listURL, nil)
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := client.Do(req)
	if err != nil {
		// нет сети — работаем с кэшем, если есть
		if _, err2 := os.Stat(p); err2 == nil {
			return readLines(p)
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		resp.Body.Close()
		// не-200 тоже откатываемся на кэш
		if _, err2 := os.Stat(p); err2 == nil {
			return readLines(p)
		}
		return nil, fmt.Errorf("socks5-лист HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(p)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(f, io.LimitReader(resp.Body, 8<<20))
	f.Close()
	if err != nil {
		return nil, err
	}
	return readLines(p)
}

func readLines(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// takeChunk берёт limit строк со скользящим окном (offset двигается по кругу).
func takeChunk(lines []string, limit int) []string {
	if len(lines) == 0 {
		return nil
	}
	mu.Lock()
	off := state.Offset % len(lines)
	mu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	for i := 0; i < len(lines) && len(out) < limit; i++ {
		l := strings.TrimSpace(lines[(off+i)%len(lines)])
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	mu.Lock()
	state.Offset = (off + limit) % len(lines)
	saveLocked()
	mu.Unlock()
	return out
}

type aliveRes struct {
	link string
	ms   int64
	ip   string
}

// checkChunk гоняет socks5 через URL-тест.
func checkChunk(chunk []string) []aliveRes {
	const workers = 32
	const timeout = 8 * time.Second
	const testURL = "https://www.gstatic.com/generate_204"
	out := []aliveRes{}
	var muOut sync.Mutex
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, l := range chunk {
		wg.Add(1)
		sem <- struct{}{}
		go func(link string) {
			defer wg.Done()
			defer func() { <-sem }()
			host := link
			if strings.Contains(link, "://") {
				if u, err := url.Parse(link); err == nil {
					host = u.Host
				}
			}
			proxyURL, err := url.Parse("socks5://" + host)
			if err != nil {
				return
			}
			tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: (&net.Dialer{Timeout: timeout}).DialContext, TLSHandshakeTimeout: timeout}
			defer tr.CloseIdleConnections()
			c := &http.Client{Transport: tr, Timeout: timeout}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			resp, err := c.Do(req)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				return
			}
			ip := host
			if h, _, err := net.SplitHostPort(host); err == nil {
				ip = h
			}
			muOut.Lock()
			out = append(out, aliveRes{link: link, ms: time.Since(start).Milliseconds(), ip: ip})
			muOut.Unlock()
		}(l)
	}
	wg.Wait()
	return out
}
