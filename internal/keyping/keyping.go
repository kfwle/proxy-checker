package keyping

// Пинг с 8 точек KeyCDN (DE/NL/UK/US×2/SG/AU/IN).
// Публичного API нет: тянем страницу /ping, забираем свежий token + куки,
// POST queries/ping-query.php {location, hostname, token} по каждой точке.
// Хрупко (поменяют вёрстку — ляжет), но сейчас работает. Кэш 10 мин.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

var locations = []struct {
	ID   string
	Name string
}{
	{"defr", "Франкфурт"}, {"nlam", "Амстердам"}, {"uklo", "Лондон"},
	{"usny", "Нью-Йорк"}, {"ussf", "Сан-Франциско"}, {"sgsg", "Сингапур"},
	{"ausy", "Сидней"}, {"inba", "Бангалор"},
}

type PointRes struct {
	Loc   string  `json:"loc"`
	Name  string  `json:"name"`
	Min   float64 `json:"min"`
	Avg   float64 `json:"avg"`
	Max   float64 `json:"max"`
	Loss  float64 `json:"loss"`
	OK    bool    `json:"ok"`
	Error string  `json:"error,omitempty"`
}

type Agg struct {
	Target  string     `json:"target"`
	Started time.Time  `json:"-"`
	Done    bool       `json:"done"`
	Results []PointRes `json:"results"`
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

var tokenRe = regexp.MustCompile(`token=([a-f0-9]{32,})`)

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
	a := &Agg{Target: target, Started: time.Now()}
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
	if !ok {
		return nil, false
	}
	cp := *a
	cp.Results = append([]PointRes(nil), a.Results...)
	return &cp, true
}

func run(a *Agg) {
	res := queryAll(a.Target)
	mu.Lock()
	if len(res) == 0 {
		a.Error = "keycdn: пусто (сменили вёрстку?)"
	} else {
		a.Results = res
		cache[a.Target] = &cacheEntry{agg: Agg{Target: a.Target, Done: true, Results: res}, until: time.Now().Add(10 * time.Minute)}
	}
	a.Done = true
	mu.Unlock()
}

func queryAll(host string) []PointRes {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Timeout: 25 * time.Second, Jar: jar}
	// 1. свежая страница ради token + кук
	req, _ := http.NewRequest("GET", "https://tools.keycdn.com/ping", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36")
	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	page, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	m := tokenRe.FindSubmatch(page)
	if m == nil {
		return nil
	}
	token := string(m[1])

	// 2. точки параллельно
	out := make([]PointRes, len(locations))
	var wg sync.WaitGroup
	for i, loc := range locations {
		wg.Add(1)
		go func(i int, locID, name string) {
			defer wg.Done()
			out[i] = queryPoint(c, token, host, locID, name)
		}(i, loc.ID, loc.Name)
	}
	wg.Wait()
	res := []PointRes{}
	for _, p := range out {
		if p.OK || p.Error != "" {
			res = append(res, p)
		}
	}
	return res
}

func queryPoint(c *http.Client, token, host, locID, name string) PointRes {
	form := url.Values{"location": {locID}, "hostname": {host}, "token": {token}}
	req, _ := http.NewRequest("POST", "https://tools.keycdn.com/queries/ping-query.php", strings.NewReader(form.Encode()))
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Referer", "https://tools.keycdn.com/ping")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return PointRes{Loc: locID, Name: name, Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return parsePoint(body, locID, name)
}

func parsePoint(body []byte, locID, name string) PointRes {
	// ответ: {"result":"<td>...</td>...","avg":0.38} — сначала достаём result-поле
	var wrapper struct {
		Result string  `json:"result"`
		Avg    float64 `json:"avg"`
	}
	htmlSrc := string(body)
	if json.Unmarshal(body, &wrapper) == nil && wrapper.Result != "" {
		htmlSrc = wrapper.Result
	}
	z := html.NewTokenizer(bytes.NewReader([]byte(htmlSrc)))
	var cells []string
	var cur strings.Builder
	inTD := false
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken {
			if tn, _ := z.TagName(); string(tn) == "td" {
				inTD = true
				cur.Reset()
			}
		} else if tt == html.EndTagToken {
			if tn, _ := z.TagName(); string(tn) == "td" && inTD {
				inTD = false
				cells = append(cells, strings.TrimSpace(cur.String()))
			}
		} else if tt == html.TextToken && inTD {
			cur.Write(z.Text())
		}
	}
	// cells: [loc+ip, sent, min, avg, max, stddev, loss]
	if len(cells) < 7 {
		return PointRes{Loc: locID, Name: name, Error: "не разобрал ответ"}
	}
	num := func(s string) float64 {
		s = strings.TrimSuffix(strings.TrimSpace(s), " ms")
		s = strings.TrimSuffix(s, "%")
		var f float64
		fmt.Sscanf(s, "%f", &f)
		return f
	}
	return PointRes{Loc: locID, Name: name, Min: num(cells[2]), Avg: num(cells[3]), Max: num(cells[4]), Loss: num(cells[6]), OK: true}
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
