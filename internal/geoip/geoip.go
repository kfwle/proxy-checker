package geoip

// GEO через api.2ip.io (без ключа): ?ip=1.2.3.4 -> city/country/emoji/lat/lon/asn/hosting.
// Лимиты: последовательно — ок, параллельный шторм (~20) — 429.
// Поэтому: воркеры 3 + вечный локальный кэш data/geo2.json. Не долбимся.

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Info struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Code     string `json:"code"`
	Emoji    string `json:"emoji"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Timezone string `json:"timezone"`
	ASN      struct {
		ID      int    `json:"id"`
		Name    string `json:"name"`
		Hosting bool   `json:"hosting"`
	} `json:"asn"`
	Unknown bool `json:"unknown,omitempty"`
}

var (
	mu     sync.Mutex
	cache  = map[string]Info{}
	loaded bool
)

// ---- SOCKS5-ротация: 2ip лимитит по IP, поэтому ходим через живые
// socks5 из results/daily (round-robin). Пула нет — идём напрямую.

var (
	poolMu  sync.Mutex
	pool    []string
	poolAt  time.Time
	poolIdx atomic.Int64
)

func resultsRoot() string {
	if v := os.Getenv("CHECKER_RESULTS_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "results")
	}
	return "results"
}

func socksPool() []string {
	poolMu.Lock()
	defer poolMu.Unlock()
	if time.Since(poolAt) < 10*time.Minute && len(pool) > 0 {
		return pool
	}
	// самый свежий alive_all.txt из daily
	var best string
	var bestTime time.Time
	entries, _ := os.ReadDir(filepath.Join(resultsRoot(), "daily"))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(resultsRoot(), "daily", e.Name(), "alive_all.txt")
		if st, err := os.Stat(p); err == nil && st.ModTime().After(bestTime) {
			bestTime, best = st.ModTime(), p
		}
	}
	pool = nil
	if best != "" {
		if f, err := os.Open(best); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() && len(pool) < 200 {
				if l := strings.TrimSpace(sc.Text()); l != "" {
					pool = append(pool, l)
				}
			}
			f.Close()
		}
	}
	poolAt = time.Now()
	return pool
}

// PoolInfo для UI: сколько проксей в ротации.
func PoolInfo() (int, string) {
	p := socksPool()
	v := "напрямую"
	if len(p) > 0 {
		v = "через socks5"
	}
	return len(p), v
}

// PickProxies отдаёт до n разных host:port из пула со сдвигом ротации.
// Пусто — ходить напрямую.
func PickProxies(n int) []string {
	p := socksPool()
	if len(p) == 0 || n <= 0 {
		return nil
	}
	start := int(poolIdx.Add(1)) % len(p)
	var out []string
	seen := map[string]bool{}
	for i := 0; i < len(p) && len(out) < n; i++ {
		raw := p[(start+i)%len(p)]
		host := raw
		if strings.Contains(raw, "://") {
			if u, err := url.Parse(raw); err == nil && u.Host != "" {
				host = u.Host
			}
		}
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out
}

func dataDir() string {
	if v := os.Getenv("CHECKER_DATA_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "data")
	}
	return "data"
}

func path() string { return filepath.Join(dataDir(), "geo2.json") }

func load() {
	if loaded {
		return
	}
	loaded = true
	if b, err := os.ReadFile(path()); err == nil {
		var raw map[string]Info
		if json.Unmarshal(b, &raw) == nil {
			// отбраковываем отравленные записи (unknown) — переспросим вживую
			for ip, v := range raw {
				if !v.Unknown && v.Code != "" {
					cache[ip] = v
				}
			}
		}
	}
}

func save() {
	_ = os.MkdirAll(dataDir(), 0o755)
	b, _ := json.Marshal(cache)
	_ = os.WriteFile(path(), b, 0o644)
}

// Lookup один IP (кэш вечный — только для успешных; провалы не пишем,
// иначе отравим кэш насовсем при временном 429).
func Lookup(ip string) Info {
	mu.Lock()
	load()
	if v, ok := cache[ip]; ok {
		mu.Unlock()
		return v
	}
	mu.Unlock()

	info := query(ip)

	if !info.Unknown {
		mu.Lock()
		cache[ip] = info
		save()
		mu.Unlock()
	}
	return info
}

// LookupMany пачкой с воркерами 3.
func LookupMany(ips []string) map[string]Info {
	out := map[string]Info{}
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	var muOut sync.Mutex
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			info := Lookup(ip)
			muOut.Lock()
			out[ip] = info
			muOut.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}

func query(ip string) Info {
	// фолбэк-цепочка: до 3 разных socks из пула, потом напрямую.
	// Дохлый прокси в ротации больше не валит запрос.
	pool := socksPool()
	start := 0
	if len(pool) > 0 {
		start = int(poolIdx.Add(1)) % len(pool)
	}
	tried := map[string]bool{}
	// попытки: min(3, len(pool)) прокси + 1 напрямую
	for attempts := 0; attempts < 4; attempts++ {
		var proxyURL *url.URL
		if attempts < len(pool) && attempts < 3 {
			raw := pool[(start+attempts)%len(pool)]
			host := raw
			if strings.Contains(raw, "://") {
				if u, err := url.Parse(raw); err == nil && u.Host != "" {
					host = u.Host
				}
			}
			if tried[host] {
				continue
			}
			tried[host] = true
			var err error
			proxyURL, err = url.Parse("socks5://" + host)
			if err != nil {
				continue
			}
		}
		if v, ok := queryVia(ip, proxyURL); ok {
			return v
		}
	}
	return Info{IP: ip, Unknown: true}
}

func queryVia(ip string, proxyURL *url.URL) (Info, bool) {
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "https://api.2ip.io/?ip="+ip, nil)
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := c.Do(req)
	if err != nil {
		return Info{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 {
		return Info{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var v Info
	if json.Unmarshal(body, &v) != nil || v.Code == "" {
		return Info{}, false
	}
	return v, true
}
