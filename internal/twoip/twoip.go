package twoip

// Платные методы api.2ip.io по токену пользователя (2ip.io/free):
// abuse (10к/мес бесплатно — репутация IP + RKN-записи),
// hosted domains (10/мес), whois (100/мес), asn (100/мес).
// Без токена — только базовая геолокация (см. internal/geoip).
// Квоты месячные и мелкие — только ондеманд + кэш 7 дней, в масс-прогоны не лезем.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"path/filepath"
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

// ---- токен ----

type Settings struct {
	TwoIPToken   string `json:"twoipToken"`
	AbuseAuto    bool   `json:"abuseAuto"` // авто-abuse новых живых IP из daily
}

func settingsPath() string { return filepath.Join(dataDir(), "settings.json") }

func LoadSettings() Settings {
	var s Settings
	s.AbuseAuto = true
	if b, err := os.ReadFile(settingsPath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func SaveSettings(s Settings) {
	_ = os.MkdirAll(dataDir(), 0o755)
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(settingsPath(), b, 0o600)
}

// ---- кэш ----

var (
	mu    sync.Mutex
	cache = map[string]cacheEntry{}
	loaded bool
)

type cacheEntry struct {
	Data  json.RawMessage `json:"data"`
	Until time.Time       `json:"until"`
}

func cachePath() string { return filepath.Join(dataDir(), "twoip.json") }

func loadCache() {
	if loaded {
		return
	}
	loaded = true
	if b, err := os.ReadFile(cachePath()); err == nil {
		_ = json.Unmarshal(b, &cache)
	}
}

func saveCache() {
	b, _ := json.Marshal(cache)
	_ = os.WriteFile(cachePath(), b, 0o600)
}

// ---- типы ----

type AbuseItem struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Comment     string `json:"comment"`
	Author      string `json:"author"`
	Date        string `json:"date"`
}

type AbuseResult struct {
	Items  []AbuseItem `json:"items"`
	RKN    bool        `json:"rkn"`
	Cached bool        `json:"cached,omitempty"`
}

// Fetch делает GET к api.2ip.io с токеном и кэшем.
// Токен в ключ кэша НЕ входит (раньше светился в twoip.json на диске).
func fetch(apiPath string, out any) (bool, error) {
	t, err := needToken()
	if err != nil {
		return false, err
	}
	key := apiPath
	mu.Lock()
	loadCache()
	if e, ok := cache[key]; ok && time.Now().Before(e.Until) {
		mu.Unlock()
		_ = json.Unmarshal(e.Data, out)
		return true, nil
	}
	mu.Unlock()

sep := "?"
	if strings.Contains(apiPath, "?") {
		sep = "&"
	}
	req, _ := http.NewRequest("GET", "https://api.2ip.io/"+apiPath+sep+"token="+url.QueryEscape(t), nil)
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false, fmt.Errorf("2ip: нет доступа — проверьте токен (2ip.io/free)")
	}
	if resp.StatusCode == 429 {
		return false, fmt.Errorf("2ip: rate limit — подождите и жмите реже")
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("2ip HTTP %d: %s", resp.StatusCode, trunc(string(body), 120))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return false, fmt.Errorf("2ip: кривой ответ")
	}
	mu.Lock()
	cache[key] = cacheEntry{Data: body, Until: time.Now().Add(7 * 24 * time.Hour)}
	saveCache()
	mu.Unlock()
	return false, nil
}

func needToken() (string, error) {
	t := LoadSettings().TwoIPToken
	if t == "" {
		return "", fmt.Errorf("нужен токен 2ip.io/free — вставьте в Настройках")
	}
	return t, nil
}

// Abuse репутация IP/домена. RKN-запись приходит объектом вместо массива — обрабатываем.
func Abuse(target string) (AbuseResult, error) {
	var raw json.RawMessage
	var holder struct {
		Abuses json.RawMessage `json:"abuses"`
	}
	cached, err := fetch("abuses/"+url.PathEscape(target), &holder)
	if err != nil {
		// может, API отдало массив напрямую
		return AbuseResult{}, err
	}
	raw = holder.Abuses
	res := AbuseResult{Cached: cached}
	// вариант 1: массив
	var arr []AbuseItem
	if json.Unmarshal(raw, &arr) == nil && arr != nil {
		res.Items = arr
	} else {
		// вариант 2: объект (RKN listing)
		var single AbuseItem
		if json.Unmarshal(raw, &single) == nil && (single.Description != "" || single.Type != "") {
			res.Items = []AbuseItem{single}
		}
	}
	for _, it := range res.Items {
		if it.Author == "Roskomnadzor (RKN)" || it.Description == "RKN listing" {
			res.RKN = true
		}
	}
	return res, nil
}

// Domains список доменов на IP (квота 10/мес — только руками).
func Domains(ip string) ([]string, bool, error) {
	var v struct {
		Domains []string `json:"domains"`
	}
	cached, err := fetch("domains/"+url.PathEscape(ip), &v)
	return v.Domains, cached, err
}

// Whois сырой WHOIS (квота 100/мес).
func Whois(query string) (map[string]any, bool, error) {
	var v map[string]any
	cached, err := fetch("whois/"+url.PathEscape(query), &v)
	return v, cached, err
}

// Asn детали автономки (квота 100/мес).
func Asn(id string) (map[string]any, bool, error) {
	var v map[string]any
	cached, err := fetch("asn/"+url.PathEscape(id), &v)
	return v, cached, err
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
