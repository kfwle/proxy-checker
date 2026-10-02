package revdns

// Бесплатный reverse-IP без токена (аналог 2ip hosted domains):
// 1) HackerTarget reverseiplookup (free ~100/день с IP, дальше "API count exceeded");
// 2) urlscan.io search ip:X (без ключа, domains из публичных сканов).
// Только ондеманд + кэш 7 дней.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var client = &http.Client{Timeout: 20 * time.Second}

func dataDir() string {
	if v := os.Getenv("CHECKER_DATA_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "data")
	}
	return "data"
}

var (
	mu     sync.Mutex
	cache  = map[string]cacheEntry{}
	loaded bool
)

type cacheEntry struct {
	Data  Result `json:"data"`
	Until time.Time `json:"until"`
}

type Result struct {
	IP          string   `json:"ip"`
	HackerTarget []string `json:"hackertarget"`
	Urlscan     []string `json:"urlscan"`
	Cached      bool     `json:"cached,omitempty"`
}

func cachePath() string { return filepath.Join(dataDir(), "revdns.json") }

func Lookup(ip string) (Result, error) {
	mu.Lock()
	if !loaded {
		loaded = true
		if b, err := os.ReadFile(cachePath()); err == nil {
			_ = json.Unmarshal(b, &cache)
		}
	}
	if e, ok := cache[ip]; ok && time.Now().Before(e.Until) {
		r := e.Data
		r.Cached = true
		mu.Unlock()
		return r, nil
	}
	mu.Unlock()

	res := Result{IP: ip}
	ht, errHT := hackerTarget(ip)
	if errHT == nil {
		res.HackerTarget = ht
	}
	us, errUS := urlscan(ip)
	if errUS == nil {
		res.Urlscan = us
	}
	if errHT != nil && errUS != nil {
		return res, fmt.Errorf("revdns: %v / %v", errHT, errUS)
	}
	// кэшируем только полный успех: половинка без пометки врала бы 7 дней
	if errHT != nil || errUS != nil {
		return res, nil
	}
	mu.Lock()
	cache[ip] = cacheEntry{Data: res, Until: time.Now().Add(7 * 24 * time.Hour)}
	b, _ := json.Marshal(cache)
	_ = os.MkdirAll(dataDir(), 0o755)
	_ = os.WriteFile(cachePath(), b, 0o644)
	mu.Unlock()
	return res, nil
}

func getText(url string) (string, int, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(body), resp.StatusCode, nil
}

func hackerTarget(ip string) ([]string, error) {
	body, code, err := getText("https://api.hackertarget.com/reverseiplookup/?q=" + ip)
	if err != nil {
		return nil, err
	}
	if code == 429 || strings.Contains(strings.ToLower(body), "error") {
		return nil, fmt.Errorf("hackertarget: %s", firstLine(body))
	}
	out := []string{}
	for _, l := range strings.Split(body, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "error") {
			out = append(out, l)
		}
		if len(out) >= 100 {
			break
		}
	}
	return out, nil
}

func urlscan(ip string) ([]string, error) {
	body, code, err := getText("https://urlscan.io/api/v1/search/?q=ip%3A" + ip + "&size=30")
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("urlscan HTTP %d", code)
	}
	var v struct {
		Results []struct {
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
		} `json:"results"`
	}
	if json.Unmarshal([]byte(body), &v) != nil {
		return nil, fmt.Errorf("urlscan: кривой ответ")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, r := range v.Results {
		if r.Task.Domain != "" && !seen[r.Task.Domain] {
			seen[r.Task.Domain] = true
			out = append(out, r.Task.Domain)
		}
	}
	return out, nil
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i > 0 {
		return s[:i]
	}
	if len(s) > 100 {
		return s[:100]
	}
	return s
}
