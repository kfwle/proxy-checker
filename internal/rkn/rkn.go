package rkn

// Проверка хоста сервера прокси по cheburcheck.ru:
// заблокирован ли домен/IP в РФ (реестр РКН + CDN-диапазоны),
// плюс бесплатное обогащение: geo/ASN/организация, reverse DNS, Tranco-rank.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

func baseURL() string {
	if v := os.Getenv("CHEBURCHECK_BASE"); v != "" {
		return v
	}
	return "https://cheburcheck.ru"
}

type Geo struct {
	ASN          string `json:"asn"`
	CountryCode  string `json:"country_code"`
	Organisation string `json:"organisation"`
	Location     string `json:"location"`
}

type Whitelist struct {
	Domain string `json:"domain"`
	Rank   int    `json:"rank"`
}

type Result struct {
	Target         string            `json:"target"`
	TargetType     string            `json:"targetType"`
	Blocked        bool              `json:"blocked"`
	RknDomain      string            `json:"rknDomain,omitempty"`
	IPs            []string          `json:"ips"`
	BlockedSubnets []string          `json:"blockedSubnets"`
	CdnProviders   map[string]any    `json:"cdnProviders,omitempty"`
	Geo            Geo               `json:"geo"`
	ASNInfo        any               `json:"asnInfo,omitempty"`
	Whitelist      *Whitelist        `json:"whitelist,omitempty"`
	ReverseLookup  []string          `json:"reverseLookup"`
	Cached         bool              `json:"cached,omitempty"`
}

var client = &http.Client{Timeout: 20 * time.Second}

var (
	mu    sync.Mutex
	cache = map[string]*entry{}
)

type entry struct {
	res   Result
	until time.Time
}

func Check(target string) (Result, error) {
	mu.Lock()
	if e, ok := cache[target]; ok && time.Now().Before(e.until) {
		r := e.res
		r.Cached = true
		mu.Unlock()
		return r, nil
	}
	mu.Unlock()

	u := baseURL() + "/api/v1/check?target=" + url.QueryEscape(target)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 404 {
		return Result{}, fmt.Errorf("cheburcheck: нечего проверять (404)")
	}
	if resp.StatusCode == 429 {
		return Result{}, fmt.Errorf("cheburcheck: rate limit, попробуйте позже")
	}
	if resp.StatusCode != 200 {
		return Result{}, fmt.Errorf("cheburcheck HTTP %d", resp.StatusCode)
	}
	var raw struct {
		Target         string         `json:"target"`
		TargetType     string         `json:"target_type"`
		Blocked        bool           `json:"blocked"`
		RknDomain      *string        `json:"rkn_domain"`
		IPs            []string       `json:"ips"`
		BlockedSubnets []string       `json:"blocked_subnets"`
		CdnProviders   map[string]any `json:"cdn_providers"`
		Geo            Geo            `json:"geo"`
		ASNInfo        any            `json:"asn_info"`
		Whitelist      *Whitelist     `json:"whitelist"`
		ReverseLookup  []string       `json:"reverse_lookup"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Result{}, err
	}
	r := Result{
		Target: raw.Target, TargetType: raw.TargetType, Blocked: raw.Blocked,
		IPs: raw.IPs, BlockedSubnets: raw.BlockedSubnets, CdnProviders: raw.CdnProviders,
		Geo: raw.Geo, ASNInfo: raw.ASNInfo, Whitelist: raw.Whitelist, ReverseLookup: raw.ReverseLookup,
	}
	if raw.RknDomain != nil {
		r.RknDomain = *raw.RknDomain
	}
	mu.Lock()
	cache[target] = &entry{res: r, until: time.Now().Add(30 * time.Minute)}
	mu.Unlock()
	return r, nil
}
