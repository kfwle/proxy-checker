package probe

// Живые SNI/DNS-замеры из сетей добровольцев через cheburcheck.ru:
// check -> query id -> SSE /api/v1/probe/<id>.
// Только для доменов (IP их API для SNI не берёт). Без токена.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func baseURL() string { return "https://cheburcheck.ru" }

var client = &http.Client{Timeout: 150 * time.Second} // весь SSE-стрим должен уложиться; внутри ещё свой дедлайн 100с

type ProbeVerdict struct {
	ProbeID  string   `json:"probeId"`
	Region   string   `json:"region"`
	Provider string   `json:"provider"`
	ASN      string   `json:"asn"`
	Verdicts []string `json:"verdicts"`
	// улики для детального вида: на каком прыжке DPI/цель, типы evidence по host_results
	DpiHop    *int     `json:"dpiHop,omitempty"`
	TargetHop *int     `json:"targetHop,omitempty"`
	Evidence  []string `json:"evidence,omitempty"`
}

type Agg struct {
	Target   string         `json:"target"`
	Done     bool           `json:"done"`
	Probes   []ProbeVerdict `json:"probes"`
	Totals   map[string]int `json:"totals"`
	Online   int            `json:"online"`
	Error    string         `json:"error,omitempty"`
	Cached   bool           `json:"cached,omitempty"`
	Started  time.Time      `json:"-"`
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

func StartJob(id, target string) *Agg {
	mu.Lock()
	if e, ok := cache[target]; ok && time.Now().Before(e.until) {
		a := e.agg
		a.Cached = true
		a.Done = true
		jobs[id] = &a
		mu.Unlock()
		return &a
	}
	mu.Unlock()

	a := &Agg{Target: target, Started: time.Now(), Totals: map[string]int{}}
	mu.Lock()
	jobs[id] = a
	mu.Unlock()
	go run(a)
	return a
}

func GetJob(id string) (*Agg, bool) {
	mu.Lock()
	defer mu.Unlock()
	a, ok := jobs[id]
	return a, ok
}

// Snapshot — копия под локом для безопасной отдачи в API.
func (a *Agg) Snapshot() Agg {
	mu.Lock()
	defer mu.Unlock()
	cp := Agg{Target: a.Target, Done: a.Done, Online: a.Online, Error: a.Error, Cached: a.Cached, Started: a.Started, Totals: map[string]int{}}
	for k, v := range a.Totals {
		cp.Totals[k] = v
	}
	cp.Probes = append([]ProbeVerdict(nil), a.Probes...)
	return cp
}

func run(a *Agg) {
	// 1. query id через check
	queryID, err := checkQueryID(a.Target)
	if err != nil {
		fail(a, err.Error())
		return
	}
	// 2. SSE
	if err := consumeSSE(queryID, a); err != nil {
		// частичные данные всё равно полезны
		mu.Lock()
		if len(a.Probes) == 0 {
			a.Error = err.Error()
		}
		a.Done = true
		mu.Unlock()
	} else {
		mu.Lock()
		if len(a.Probes) == 0 {
			a.Error = "пробы промолчали (пустой результат)"
		}
		a.Done = true
		mu.Unlock()
	}
	mu.Lock()
	cp := *a
	cp.Probes = append([]ProbeVerdict(nil), a.Probes...)
	cp.Totals = map[string]int{}
	for k, v := range a.Totals {
		cp.Totals[k] = v
	}
	cache[a.Target] = &cacheEntry{agg: cp, until: time.Now().Add(time.Hour)}
	mu.Unlock()
}

func fail(a *Agg, msg string) {
	mu.Lock()
	a.Error = msg
	a.Done = true
	mu.Unlock()
}

func checkQueryID(target string) (string, error) {
	c := &http.Client{Timeout: 25 * time.Second}
	req, _ := http.NewRequest("GET", baseURL()+"/api/v1/check?target="+url.QueryEscape(target), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("cheburcheck check HTTP %d", resp.StatusCode)
	}
	var v struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.ID == "" {
		return "", fmt.Errorf("cheburcheck: нет query id")
	}
	return v.ID, nil
}

func consumeSSE(queryID string, a *Agg) error {
	req, _ := http.NewRequest("GET", baseURL()+"/api/v1/probe/"+url.PathEscape(queryID), nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("probe HTTP %d", resp.StatusCode)
	}
	deadline := time.Now().Add(100 * time.Second)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 256*1024), 4<<20)
	var event string
	for sc.Scan() {
		if time.Now().After(deadline) {
			return nil // что успели — то наше
		}
		line := sc.Text()
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		var d map[string]json.RawMessage
		if json.Unmarshal([]byte(payload), &d) == nil {
			if ev, ok := d["verdicts"]; ok && event == "result" {
				var pv ProbeVerdict
				_ = json.Unmarshal(mustGet(d, "probe_id"), &pv.ProbeID)
				_ = json.Unmarshal(mustGet(d, "region"), &pv.Region)
				_ = json.Unmarshal(mustGet(d, "provider"), &pv.Provider)
				_ = json.Unmarshal(mustGet(d, "asn"), &pv.ASN)
				_ = json.Unmarshal(ev, &pv.Verdicts)
				_ = json.Unmarshal(mustGet(d, "dpi_hop"), &pv.DpiHop)
				_ = json.Unmarshal(mustGet(d, "target_hop"), &pv.TargetHop)
				// типы evidence из host_results: [{"probe_evidence":{"type":"ClientHello"}}, ...]
				var hrs []struct {
					Evidence struct {
						Type string `json:"type"`
					} `json:"probe_evidence"`
				}
				if json.Unmarshal(mustGet(d, "host_results"), &hrs) == nil {
					seen := map[string]bool{}
					for _, h := range hrs {
						if h.Evidence.Type != "" && !seen[h.Evidence.Type] {
							seen[h.Evidence.Type] = true
							pv.Evidence = append(pv.Evidence, h.Evidence.Type)
						}
					}
				}
				mu.Lock()
				a.Probes = append(a.Probes, pv)
				if len(pv.Verdicts) == 0 {
					a.Totals["clean"]++
				}
				for _, v := range pv.Verdicts {
					a.Totals[v]++
				}
				mu.Unlock()
				continue
			}
			if on, ok := d["online_probes"]; ok && event == "started" {
				var n int
				_ = json.Unmarshal(on, &n)
				mu.Lock()
				a.Online = n
				mu.Unlock()
			}
		}
		event = ""
	}
	return nil
}

func mustGet(m map[string]json.RawMessage, k string) []byte {
	if v, ok := m[k]; ok {
		return v
	}
	return []byte("null")
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
