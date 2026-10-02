package gping

// Глобальный пинг через Globalping (jsdelivr), БЕЗ токена:
// POST /v1/measurements {target, type:ping, limit} -> id -> poll GET.
// На пробу: страна/город/сеть + min/avg/max/loss. Онденсайд + кэш 10 мин.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yzewe/proxy-checker/internal/geoip"
)

const base = "https://api.globalping.io/v1"

// clientFor строит клиент через socks-прокси пула (429 там по IP —
// крутим прокси как и для 2ip) или напрямую.
func clientFor(proxyHost string) *http.Client {
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if proxyHost != "" {
		if u, err := url.Parse("socks5://" + proxyHost); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Transport: tr, Timeout: 25 * time.Second}
}

type ProbeRes struct {
	Probe   string  `json:"probe"`
	Country string  `json:"country"`
	City    string  `json:"city"`
	Network string  `json:"network"`
	Min     float64 `json:"min"`
	Avg     float64 `json:"avg"`
	Max     float64 `json:"max"`
	Loss    float64 `json:"loss"`
	OK      bool    `json:"ok"`
}

type Agg struct {
	Target  string     `json:"target"`
	Started time.Time  `json:"-"`
	Done    bool       `json:"done"`
	ID      string     `json:"id,omitempty"`
	Results []ProbeRes `json:"results"`
	Error   string     `json:"error,omitempty"`
	Cached  bool       `json:"cached,omitempty"`
}

var (
	mu    sync.Mutex
	jobs  = map[string]*Agg{}
	cache = map[string]*cacheEntry{}
)

type cacheEntry struct {
	agg   Agg
	until time.Time
}

func StartJob(id, target, country string) *Agg {
	mu.Lock()
	ck := "ping|" + target
	if country != "" {
		ck += "|" + country
	}
	if e, ok := cache[ck]; ok && time.Now().Before(e.until) {
		a := e.agg
		a.Cached = true
		a.Done = true
		jobs[id] = &a
		mu.Unlock()
		return &a
	}
	mu.Unlock()
	a := &Agg{Target: target, Started: time.Now()}
	mu.Lock()
	jobs[id] = a
	mu.Unlock()
	go run(id, a, country)
	return a
}

func GetJob(id string) (*Agg, bool) {
	mu.Lock()
	defer mu.Unlock()
	a, ok := jobs[id]
	if !ok {
		return nil, false
	}
	cp := *a
	cp.Results = append([]ProbeRes(nil), a.Results...)
	return &cp, true
}

func run(id string, a *Agg, country string) {
	ck := "ping|" + a.Target
	if country != "" {
		ck += "|" + country
	}
	finish := func() {
		mu.Lock()
		a.Done = true
		cp := *a
		cp.Results = append([]ProbeRes(nil), a.Results...)
		cache[ck] = &cacheEntry{agg: cp, until: time.Now().Add(10 * time.Minute)}
		mu.Unlock()
	}
	// кандидаты: до 3 socks из пула + напрямую.
	// 429/403/обрыв — следующий кандидат; только ошибки валидации стопают.
	cands := append(geoip.PickProxies(3), "")
	var lastErr error
	for _, px := range cands {
		c := clientFor(px)
		mid, err := startMeasure(c, a.Target, country)
		if err != nil {
			lastErr = err
			if isFatal(err) {
				break
			}
			continue
		}
		mu.Lock()
		a.ID = mid
		mu.Unlock()
		res, err := pollMeasure(c, mid)
		if err != nil {
			lastErr = err
			if isFatal(err) {
				break
			}
			continue
		}
		mu.Lock()
		a.Results = res
		mu.Unlock()
		finish()
		return
	}
	mu.Lock()
	if lastErr != nil {
		a.Error = lastErr.Error()
	} else {
		a.Error = "globalping: пусто"
	}
	mu.Unlock()
	finish()
}

// isFatal: только ошибки валидации (кривой таргет) — остальное
// (429, 403-бан IP, обрывы) лечится следующим кандидатом.
func isFatal(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "validation") || strings.Contains(s, "нет id")
}

func startMeasure(c *http.Client, target, country string) (string, error) {
	// лимит 50 — максимум для анонимного API (валидация режет больше)
	m := map[string]any{"target": target, "type": "ping", "limit": 50}
	if country != "" {
		m["locations"] = []any{map[string]any{"country": country}}
	}
	body, _ := json.Marshal(m)
	req, _ := http.NewRequest("POST", base+"/measurements", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == 429 {
		return "", fmt.Errorf("globalping: rate limit (429)")
	}
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return "", fmt.Errorf("globalping HTTP %d", resp.StatusCode)
	}
	var v struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &v) != nil || v.ID == "" {
		return "", fmt.Errorf("globalping: нет id")
	}
	return v.ID, nil
}

func pollMeasure(c *http.Client, id string) ([]ProbeRes, error) {
	deadline := time.Now().Add(100 * time.Second)
	for {
		req, _ := http.NewRequest("GET", base+"/measurements/"+id, nil)
		req.Header.Set("User-Agent", "proxy-checker")
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		var v struct {
			Status  string `json:"status"`
			Results []struct {
				Probe struct {
					Country string `json:"country"`
					City    string `json:"city"`
					Network string `json:"network"`
				} `json:"probe"`
				Result struct {
					Status string `json:"status"`
					Stats  struct {
						Min  float64 `json:"min"`
						Avg  float64 `json:"avg"`
						Max  float64 `json:"max"`
						Loss float64 `json:"loss"`
					} `json:"stats"`
				} `json:"result"`
			} `json:"results"`
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, fmt.Errorf("globalping: кривой ответ")
		}
		if v.Status == "finished" {
			out := []ProbeRes{}
			for _, r := range v.Results {
				pr := ProbeRes{Country: r.Probe.Country, City: r.Probe.City, Network: r.Probe.Network,
					Min: r.Result.Stats.Min, Avg: r.Result.Stats.Avg, Max: r.Result.Stats.Max, Loss: r.Result.Stats.Loss}
				pr.Probe = pr.City + ", " + pr.Country
				pr.OK = r.Result.Status == "finished" && r.Result.Stats.Loss < 100
				out = append(out, pr)
			}
			return out, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("globalping: не дождался проб")
		}
		time.Sleep(3 * time.Second)
	}
}

// Sweep чистит старые законченные задачи.
func Sweep(maxAge time.Duration, cap int) {
	cutoff := time.Now().Add(-maxAge)
	mu.Lock()
	defer mu.Unlock()
	for id, a := range jobs {
		if a.Done && a.Started.Before(cutoff) {
			delete(jobs, id)
		}
	}
	for len(jobs) > cap {
		oldest := ""
		for id, a := range jobs {
			if !a.Done {
				continue
			}
			if oldest == "" || a.Started.Before(jobs[oldest].Started) {
				oldest = id
			}
		}
		if oldest == "" {
			break
		}
		delete(jobs, oldest)
	}
}
