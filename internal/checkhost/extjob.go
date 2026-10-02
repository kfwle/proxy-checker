package checkhost

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Check — одна внешняя проверка (ping/tcp/udp/dns/http) хоста прокси.
type Check struct {
	Type          string                     `json:"type"`
	RequestID     string                     `json:"requestId,omitempty"`
	Link          string                     `json:"link,omitempty"`
	Nodes         map[string]Node            `json:"nodes,omitempty"`
	Results       map[string]json.RawMessage `json:"results,omitempty"`
	State         string                     `json:"state"` // running|done|error
	Error         string                     `json:"error,omitempty"`
	Summary       string                     `json:"summary,omitempty"`
}

// ExtJob — набор из 5 проверок одного host:port.
type ExtJob struct {
	ID       string
	Host     string
	Started  time.Time
	mu       sync.Mutex
	Checks   map[string]*Check
	Expected []string
	Done     bool
}

func (j *ExtJob) snapshot() map[string]*Check {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := map[string]*Check{}
	for k, v := range j.Checks {
		cp := *v
		out[k] = &cp
	}
	return out
}

func (j *ExtJob) isDone() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Done
}

func (j *ExtJob) setCheck(c *Check) {
	j.mu.Lock()
	j.Checks[c.Type] = c
	j.mu.Unlock()
}

func (j *ExtJob) finish() {
	j.mu.Lock()
	j.Done = true
	j.mu.Unlock()
}

// ---- реестр задач + кэш ----

var (
	mu    sync.Mutex
	jobs  = map[string]*ExtJob{}
	cache = map[string]*cached{}
)

type cached struct {
	checks map[string]*Check
	until  time.Time
}

func cacheKey(host, typ string, ru bool) string {
	if ru {
		return "ru|" + typ + "|" + host
	}
	return typ + "|" + host
}

func getCached(host string, ru bool) (map[string]*Check, bool) {
	mu.Lock()
	defer mu.Unlock()
	out := map[string]*Check{}
	hit := false
	for _, t := range []string{"ping", "tcp", "udp", "dns", "http"} {
		if c, ok := cache[cacheKey(host, t, ru)]; ok && time.Now().Before(c.until) && len(c.checks) > 0 {
			for _, v := range c.checks {
				out[t] = v
				hit = true
			}
		}
	}
	return out, hit
}

func putCache(host, typ string, c *Check, ru bool) {
	mu.Lock()
	cache[cacheKey(host, typ, ru)] = &cached{checks: map[string]*Check{typ: c}, until: time.Now().Add(10 * time.Minute)}
	mu.Unlock()
}

// StartJob запускает выбранные проверки в фоне (пусто = все).
// host — "example.com:443" или "1.2.3.4:443".
// dns идёт по голому хосту (без порта), остальные — по host:port.
// onlyRU — только российские ноды (иначе на выбор сервиса).
func StartJob(id, hostport string, types []string, onlyRU bool) *ExtJob {
	want := map[string]bool{}
	if len(types) == 0 {
		types = []string{"ping", "tcp", "udp", "dns", "http"}
	}
	for _, t := range types {
		want[t] = true
	}
	j := &ExtJob{ID: id, Host: hostport, Started: time.Now(), Checks: map[string]*Check{}, Expected: ordered(want)}
	mu.Lock()
	jobs[id] = j
	mu.Unlock()

	if cached, ok := getCached(hostport, onlyRU); ok {
		any := false
		for _, c := range cached {
			if want[c.Type] {
				j.setCheck(c)
				any = true
			}
		}
		// докачаем недостающее из выбранного
		missing := []string{}
		for t := range want {
			if _, ok := j.Checks[t]; !ok {
				missing = append(missing, t)
			}
		}
		if len(missing) == 0 && any {
			j.finish()
			return j
		}
		types = missing
		want = map[string]bool{}
		for _, t := range types {
			want[t] = true
		}
		j.Expected = ordered(want)
	}

	host := hostport
	if i := strings.LastIndex(hostport, ":"); i > 0 {
		host = hostport[:i]
	}
	isIP := isIPAddr(host)
	var pick []string
	if onlyRU {
		pick = RUNodes()
		if len(pick) == 0 {
			j.setCheck(&Check{Type: "ext", State: "error", Error: "нет RU-нод у check-host"})
			j.Expected = []string{"ext"}
			j.finish()
			return j
		}
	}

	go func() {
		// ping + tcp + udp параллельно по host:port/host
		for _, t := range []string{"ping", "tcp", "udp"} {
			if !want[t] {
				continue
			}
			target := host
			if t == "tcp" || t == "udp" {
				target = hostport
			}
			j.setCheck(&Check{Type: t, State: "running"})
			go runOne(j, t, target, pick)
		}
		// dns только для домена
		if !isIP && host != "" {
			if want["dns"] {
				j.setCheck(&Check{Type: "dns", State: "running"})
				go runOne(j, "dns", host, pick)
			}
		} else if want["dns"] {
			j.setCheck(&Check{Type: "dns", State: "done", Summary: "IP — резолвить нечего"})
		}
		// http — доступность сайта хоста снаружи
		httpTarget := host
		if !isIP {
			if want["http"] {
				j.setCheck(&Check{Type: "http", State: "running"})
				go runOne(j, "http", httpTarget, pick)
			}
		} else if want["http"] {
			j.setCheck(&Check{Type: "http", State: "done", Summary: "для IP http-проверка малоинформативна — смотрите TCP"})
		}
	}()
	return j
}

func ordered(want map[string]bool) []string {
	out := []string{}
	for _, t := range []string{"ping", "tcp", "udp", "dns", "http"} {
		if want[t] {
			out = append(out, t)
		}
	}
	return out
}

func runOne(j *ExtJob, typ, target string, pick []string) {
	n := 3
	if len(pick) > 0 {
		n = len(pick)
	}
	reqID, link, nodes, err := Start(typ, target, n, pick)
	if err != nil {
		j.setCheck(&Check{Type: typ, State: "error", Error: err.Error()})
		maybeFinish(j)
		return
	}
	j.setCheck(&Check{Type: typ, State: "running", RequestID: reqID, Link: link, Nodes: nodes})
	raw := WaitResult(reqID, 30*time.Second)
	c := &Check{Type: typ, State: "done", RequestID: reqID, Link: link, Nodes: nodes, Results: raw, Summary: summarize(typ, raw)}
	j.setCheck(c)
	putCache(j.Host, typ, c, len(pick) > 0)
	maybeFinish(j)
}

func maybeFinish(j *ExtJob) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, t := range j.Expected {
		c, ok := j.Checks[t]
		if !ok || c.State == "running" {
			return
		}
	}
	j.Done = true
}

func GetJob(id string) (*ExtJob, bool) {
	mu.Lock()
	defer mu.Unlock()
	j, ok := jobs[id]
	return j, ok
}

// ChecksPub / DonePub — для API.
func (j *ExtJob) ChecksPub() map[string]*Check { return j.snapshot() }
func (j *ExtJob) DonePub() bool                { return j.isDone() }
// summarize выжимает человекочитаемый итог из сырого результата.
func summarize(typ string, raw map[string]json.RawMessage) string {
	if len(raw) == 0 {
		return "нет данных"
	}
	okN, failN, waitN := 0, 0, 0
	var sample string
	for _, v := range raw {
		s := strings.TrimSpace(string(v))
		if s == "null" || s == "" {
			waitN++
			continue
		}
		// tcp/udp: [{"time":..}] vs [{"error":..}] vs [{"timeout":N}] (ответа нет)
		var arr []map[string]json.RawMessage
		if json.Unmarshal(v, &arr) == nil && len(arr) > 0 {
			if _, hasErr := arr[0]["error"]; hasErr {
				failN++
				if sample == "" {
					sample = trunc(s, 48)
				}
			} else if _, hasTime := arr[0]["time"]; hasTime {
				okN++
			} else {
				// нет ни error, ни time (напр. udp {"timeout":1}) — ответа не дождались
				failN++
				if sample == "" {
					sample = "таймаут (ответа нет)"
				}
			}
			continue
		}
		// ping/http/dns: [[...]] — эвристика по содержимому
		if strings.Contains(s, "TIMEOUT") || strings.Contains(s, `"error"`) || strings.Contains(s, `"A":[]`) || strings.Contains(s, "[0,") {
			failN++
		} else {
			okN++
		}
		if sample == "" {
			sample = trunc(s, 48)
		}
	}
	sum := strings.Builder{}
	if okN > 0 {
		fmt.Fprintf(&sum, "OK: %d", okN)
	}
	if failN > 0 {
		if sum.Len() > 0 {
			sum.WriteString(" · ")
		}
		fmt.Fprintf(&sum, "FAIL: %d", failN)
	}
	if waitN > 0 {
		if sum.Len() > 0 {
			sum.WriteString(" · ")
		}
		fmt.Fprintf(&sum, "жду: %d", waitN)
	}
	if sample != "" && okN == 0 {
		sum.WriteString(" (" + sample + ")")
	}
	if sum.Len() == 0 {
		return "нет данных"
	}
	return sum.String()
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func isIPAddr(h string) bool {
	if h == "" {
		return false
	}
	dots, colons := 0, 0
	for _, c := range h {
		switch {
		case c >= '0' && c <= '9' || c == '.':
			if c == '.' {
				dots++
			}
		case c == ':':
			colons++
		case (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
		default:
			return false
		}
	}
	return dots == 3 || colons >= 2
}

// Sweep чистит старые законченные задачи.
func Sweep(maxAge time.Duration, cap int) {
	cutoff := time.Now().Add(-maxAge)
	mu.Lock()
	defer mu.Unlock()
	for id, j := range jobs {
		if j.isDone() && j.Started.Before(cutoff) {
			delete(jobs, id)
		}
	}
	for len(jobs) > cap {
		oldest := ""
		for id, j := range jobs {
			if !j.isDone() {
				continue
			}
			if oldest == "" || j.Started.Before(jobs[oldest].Started) {
				oldest = id
			}
		}
		if oldest == "" {
			break
		}
		delete(jobs, oldest)
	}
}
