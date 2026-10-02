package dnscomp

// Сравнение резолвинга: один и тот же домен гоняем через разные DNS
// (Google, Cloudflare, Quad9, Yandex, Alibaba, системный + свои)
// и разными транспортами (UDP/53, TCP/53, DoT/853, DoH, DoQ).
// Расхождение с большинством = подозрение на подмену.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/yzewe/proxy-checker/internal/geoip"
)

type Transport string

const (
	TUDP Transport = "udp"
	TTCP Transport = "tcp"
	TDOT Transport = "dot"
	TDOH Transport = "doh"
	TDOQ Transport = "doq"
)

type Resolver struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Region     string   `json:"region,omitempty"`
	CC         string   `json:"cc,omitempty"`
	IP         string   `json:"ip"`
	ServerName string   `json:"serverName,omitempty"` // SNI для DoT/DoQ
	DoH        string   `json:"doh,omitempty"`        // URL для DoH
	Transports []string `json:"transports"`           // какие гонять по умолчанию
	Builtin    bool     `json:"builtin"`
	Default    bool     `json:"default"` // включён ли по умолчанию на странице
}

// Presets: IP, SNI, DoH, дефолтные транспорты.
func presets() []Resolver {
	return []Resolver{
		{ID: "google", Name: "Google", IP: "8.8.8.8", ServerName: "dns.google", DoH: "https://dns.google/dns-query", Transports: []string{"udp", "tcp", "dot", "doh"}, Builtin: true, Default: true},
		{ID: "cf", Name: "Cloudflare", IP: "1.1.1.1", ServerName: "cloudflare-dns.com", DoH: "https://cloudflare-dns.com/dns-query", Transports: []string{"udp", "tcp", "dot", "doh", "doq"}, Builtin: true, Default: true},
		{ID: "quad9", Name: "Quad9", Region: "privacy", CC: "CH", IP: "9.9.9.9", ServerName: "dns.quad9.net", DoH: "https://dns.quad9.net/dns-query", Transports: []string{"udp", "tcp", "dot", "doh"}, Builtin: true, Default: true},
		{ID: "yandex", Name: "Yandex", Region: "russia", CC: "RU", IP: "77.88.8.8", ServerName: "common.dot.dns.yandex.net", DoH: "https://common.dot.dns.yandex.net/dns-query", Transports: []string{"udp", "tcp", "dot", "doh"}, Builtin: true, Default: true},
		{ID: "ali", Name: "Alibaba", Region: "asia", CC: "CN", IP: "223.5.5.5", ServerName: "dns.alidns.com", DoH: "https://dns.alidns.com/dns-query", Transports: []string{"udp", "tcp", "dot", "doh", "doq"}, Builtin: true, Default: true},
		{ID: "system", Name: "Системный", IP: "", Transports: []string{"udp", "tcp"}, Builtin: true, Default: true},
	}
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

func customPath() string { return filepath.Join(dataDir(), "dns-resolvers.json") }

// List пресеты + свои из файла.
func List() []Resolver {
	out := append(presets(), quicBestPresets()...)
	if b, err := os.ReadFile(customPath()); err == nil {
		var custom []Resolver
		if json.Unmarshal(b, &custom) == nil {
			out = append(out, custom...)
		}
	}
	return out
}

// Add свой резолвер (IP/host + транспорты, incl. doq).
// IP/host валидируем, DoH — только http(s), иначе это SSRF-дыра.
func Add(r Resolver) ([]Resolver, error) {
	r.Name = strings.TrimSpace(r.Name)
	r.IP = strings.TrimSpace(r.IP)
	r.ServerName = strings.TrimSpace(r.ServerName)
	r.DoH = strings.TrimSpace(r.DoH)
	r.ID = "custom-" + strings.Map(func(c rune) rune {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			return c
		}
		return -1
	}, strings.ToLower(strings.TrimSpace(r.Name+"-"+r.IP)))
	if r.ID == "custom-" || r.ID == "custom--" {
		return nil, fmt.Errorf("нужны имя и IP/host")
	}
	if r.IP == "" {
		return nil, fmt.Errorf("нужен IP/host резолвера")
	}
	// host: либо IP, либо dns-имя (без схемы, портов и пробелов)
	if net.ParseIP(r.IP) == nil {
		if strings.ContainsAny(r.IP, " /:@") || !strings.Contains(r.IP, ".") || len(r.IP) > 253 {
			return nil, fmt.Errorf("кривой host резолвера")
		}
	}
	if r.DoH != "" {
		u, err := url.ParseRequestURI(r.DoH)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("DoH — только http(s) URL")
		}
	}
	if r.ServerName != "" && (strings.ContainsAny(r.ServerName, " /:@") || len(r.ServerName) > 253) {
		return nil, fmt.Errorf("кривой SNI")
	}
	if len(r.Transports) == 0 {
		r.Transports = []string{"udp", "tcp"}
	}
	// валидация транспортов
	allow := map[string]bool{"udp": true, "tcp": true, "dot": true, "doh": true, "doq": true}
	ts := []string{}
	for _, t := range r.Transports {
		t = strings.ToLower(strings.TrimSpace(t))
		if allow[t] {
			ts = append(ts, t)
		}
	}
	if len(ts) == 0 {
		return nil, fmt.Errorf("нет валидных транспортов (udp/tcp/dot/doh/doq)")
	}
	r.Transports = ts
	r.Builtin = false
	// автоопределение страны по IP резолвера (флаг в списке)
	if info := geoip.Lookup(r.IP); !info.Unknown && info.Code != "" {
		r.CC = info.Code
	}
	var custom []Resolver
	if b, err := os.ReadFile(customPath()); err == nil {
		_ = json.Unmarshal(b, &custom)
	}
	for _, c := range custom {
		if c.ID == r.ID {
			return nil, fmt.Errorf("уже есть")
		}
	}
	custom = append(custom, r)
	_ = os.MkdirAll(dataDir(), 0o755)
	b, _ := json.MarshalIndent(custom, "", "  ")
	_ = os.WriteFile(customPath(), b, 0o644)
	return List(), nil
}

func Remove(id string) []Resolver {
	var custom []Resolver
	if b, err := os.ReadFile(customPath()); err == nil {
		_ = json.Unmarshal(b, &custom)
	}
	keep := []Resolver{}
	for _, c := range custom {
		if c.ID != id {
			keep = append(keep, c)
		}
	}
	_ = os.MkdirAll(dataDir(), 0o755)
	b, _ := json.MarshalIndent(keep, "", "  ")
	_ = os.WriteFile(customPath(), b, 0o644)
	return List()
}

// ---- запросы ----

type One struct {
	Resolver     string   `json:"resolver"`
	Transport    string   `json:"transport"`
	OK           bool     `json:"ok"`
	Ms           int64    `json:"ms"`
	Answers      []string `json:"answers,omitempty"`
	ASN          []string `json:"asn,omitempty"`
	Rcode        string   `json:"rcode,omitempty"`
	SpoofSuspect bool     `json:"spoofSuspect,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type Result struct {
	Target  string `json:"target"`
	Baseline []string `json:"baseline"`
	Rows    []One  `json:"rows"`
}

func msg(qname string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	return m
}

func fill(r *dns.Msg, ms int64) (answers []string, rcode string) {
	for _, a := range r.Answer {
		switch v := a.(type) {
		case *dns.A:
			answers = append(answers, v.A.String())
		case *dns.AAAA:
			answers = append(answers, v.AAAA.String())
		case *dns.CNAME:
			answers = append(answers, "CNAME "+v.Target)
		}
	}
	return answers, dns.RcodeToString[r.Rcode]
}

func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline"):
		return "таймаут"
	case strings.Contains(s, "connection refused"):
		return "порт закрыт"
	case strings.Contains(s, "no route"), strings.Contains(s, "unreachable"):
		return "недоступен"
	}
	if len(s) > 100 {
		return s[:100] + "…"
	}
	return s
}

func qClassic(r Resolver, network, target string, timeout time.Duration) One {
	o := One{Resolver: r.Name, Transport: network}
	m := msg(target)
	c := new(dns.Client)
	c.Net = network
	c.Timeout = timeout
	addr := net.JoinHostPort(r.IP, "53")
	if r.ID == "system" {
		// системный: резолвим через дефолтный резолвер ОС
		addrs, err := net2addrs(target, timeout)
		if err != nil {
			o.Error = shortErr(err)
			return o
		}
		o.OK = true
		o.Answers = addrs
		return o
	}
	start := time.Now()
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		o.Error = shortErr(err)
		return o
	}
	o.Ms = time.Since(start).Milliseconds()
	o.Answers, o.Rcode = fill(resp, o.Ms)
	o.OK = resp.Rcode == dns.RcodeSuccess
	if !o.OK {
		o.Error = "rcode " + o.Rcode
	}
	return o
}

func net2addrs(target string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, target)
	if err != nil {
		return nil, err
	}
	sort.Strings(addrs)
	if len(addrs) > 6 {
		addrs = addrs[:6]
	}
	return addrs, nil
}

func qDoT(r Resolver, target string, timeout time.Duration) One {
	o := One{Resolver: r.Name, Transport: "dot"}
	sni := r.ServerName
	if sni == "" {
		sni = r.IP
	}
	m := msg(target)
	c := new(dns.Client)
	c.Net = "tcp-tls"
	c.Timeout = timeout
	c.TLSConfig = &tls.Config{ServerName: sni, InsecureSkipVerify: true}
	start := time.Now()
	resp, _, err := c.Exchange(m, net.JoinHostPort(r.IP, "853"))
	if err != nil {
		o.Error = shortErr(err)
		return o
	}
	o.Ms = time.Since(start).Milliseconds()
	o.Answers, o.Rcode = fill(resp, o.Ms)
	o.OK = resp.Rcode == dns.RcodeSuccess
	if !o.OK {
		o.Error = "rcode " + o.Rcode
	}
	return o
}

func qDoH(r Resolver, target string, timeout time.Duration) One {
	o := One{Resolver: r.Name, Transport: "doh"}
	if r.DoH == "" {
		o.Error = "нет DoH-URL"
		return o
	}
	packed, err := msg(target).Pack()
	if err != nil {
		o.Error = err.Error()
		return o
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", r.DoH, bytes.NewReader(packed))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "proxy-checker")
	client := &http.Client{Timeout: timeout}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		o.Error = shortErr(err)
		return o
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != 200 {
		o.Error = fmt.Sprintf("DoH HTTP %d", resp.StatusCode)
		return o
	}
	rm := new(dns.Msg)
	if err := rm.Unpack(body); err != nil {
		o.Error = "кривой DoH-ответ"
		return o
	}
	o.Ms = time.Since(start).Milliseconds()
	o.Answers, o.Rcode = fill(rm, o.Ms)
	o.OK = rm.Rcode == dns.RcodeSuccess
	if !o.OK {
		o.Error = "rcode " + o.Rcode
	}
	return o
}

func qDoQ(r Resolver, target string, timeout time.Duration) One {
	o := One{Resolver: r.Name, Transport: "doq"}
	// пробуем 853, затем 784 (у части операторов DoQ там)
	var lastErr string
	for _, port := range []string{"853", "784"} {
		o2, ok := qDoQPort(r, target, port, timeout)
		if ok {
			return o2
		}
		lastErr = o2.Error
	}
	o.Error = lastErr
	if o.Error == "" {
		o.Error = "DoQ недоступен"
	}
	return o
}

func qDoQPort(r Resolver, target, port string, timeout time.Duration) (One, bool) {
	o := One{Resolver: r.Name, Transport: "doq"}
	sni := r.ServerName
	if sni == "" {
		sni = r.IP
	}
	packed, err := msg(target).Pack()
	if err != nil {
		o.Error = err.Error()
		return o, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tlsConf := &tls.Config{ServerName: sni, NextProtos: []string{"doq"}, InsecureSkipVerify: true}
	conn, err := quic.DialAddr(ctx, net.JoinHostPort(r.IP, port), tlsConf, &quic.Config{})
	if err != nil {
		o.Error = shortErr(err)
		return o, false
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		o.Error = shortErr(err)
		return o, false
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	// RFC 9250: 2-октетный length-prefix
	var buf bytes.Buffer
	buf.Write([]byte{byte(len(packed) >> 8), byte(len(packed))})
	buf.Write(packed)
	if _, err := stream.Write(buf.Bytes()); err != nil {
		o.Error = shortErr(err)
		return o, false
	}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		o.Error = shortErr(err)
		return o, false
	}
	ln := int(hdr[0])<<8 | int(hdr[1])
	if ln <= 0 || ln > 65535 {
		o.Error = "кривой DoQ-ответ"
		return o, false
	}
	rb := make([]byte, ln)
	if _, err := io.ReadFull(stream, rb); err != nil {
		o.Error = shortErr(err)
		return o, false
	}
	rm := new(dns.Msg)
	if err := rm.Unpack(rb); err != nil {
		o.Error = "кривой DoQ-ответ"
		return o, false
	}
	o.Ms = time.Since(start).Milliseconds()
	o.Answers, o.Rcode = fill(rm, o.Ms)
	o.OK = rm.Rcode == dns.RcodeSuccess
	if !o.OK {
		o.Error = "rcode " + o.Rcode
	}
	return o, true
}

// Job — асинхронный прогон с прогрессом для кольца процентов.
type Job struct {
	ID       string
	Target   string
	Started  time.Time
	mu       sync.Mutex
	Total    int
	DoneN    int
	Rows     []One
	Finished bool
	Baseline []string
}

var (
	jobsMu sync.Mutex
	jobs   = map[string]*Job{}
)

func startJob(target string, ids []string, timeout time.Duration) *Job {
	return StartJob(target, ids, timeout)
}

// StartJob асинхронный прогон (прогресс через GetJob).
func StartJob(target string, ids []string, timeout time.Duration) *Job {
	all := List()
	want := map[string]bool{}
	if len(ids) == 0 {
		for _, r := range all {
			if r.Default {
				want[r.ID] = true
			}
		}
	} else {
		for _, id := range ids {
			want[id] = true
		}
	}
	type job struct {
		r Resolver
		t string
	}
	var qlist []job
	for _, r := range all {
		if !want[r.ID] {
			continue
		}
		for _, t := range r.Transports {
			qlist = append(qlist, job{r, t})
		}
	}
	jb := &Job{ID: fmt.Sprintf("dns%d", time.Now().UnixNano()), Target: target, Started: time.Now(), Total: len(qlist), Rows: make([]One, len(qlist))}
	jobsMu.Lock()
	jobs[jb.ID] = jb
	jobsMu.Unlock()
	go func() {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for i, j := range qlist {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, j job) {
				defer wg.Done()
				defer func() { <-sem }()
				var o One
				switch j.t {
				case "udp", "tcp":
					o = qClassic(j.r, j.t, target, timeout)
				case "dot":
					o = qDoT(j.r, target, timeout)
				case "doh":
					o = qDoH(j.r, target, timeout)
				case "doq":
					o = qDoQ(j.r, target, timeout)
				default:
					o = One{Resolver: j.r.Name, Transport: j.t, Error: "неизвестный транспорт"}
				}
				jb.mu.Lock()
				jb.Rows[i] = o
				jb.DoneN++
				jb.mu.Unlock()
			}(i, j)
		}
		wg.Wait()
		finalize(jb)
	}()
	return jb
}

func finalize(jb *Job) {
	jb.mu.Lock()
	defer jb.mu.Unlock()
	rows := jb.Rows
	// baseline = самый частый набор ответов среди успешных
	freq := map[string]int{}
	for _, r := range rows {
		if r.OK && len(r.Answers) > 0 {
			k := strings.Join(sortedCopy(r.Answers), ",")
			freq[k]++
		}
	}
	base := ""
	best := 0
	for k, n := range freq {
		if n > best {
			best, base = n, k
		}
	}
	baseline := []string{}
	if base != "" {
		baseline = strings.Split(base, ",")
	}
	// suspect = по АВТОНОМКАМ, а не IP: round-robin/ECS у легитимных
	// резолверов гоняют разные эджи одного AS (142.251.x vs 172.217.x —
	// всё AS15169). Подмена = ASN ответов вообще нет у остальных
	// при сильном консенсусе (какую-то ASN видят >=3 строк).
	// ASN тянем через geoip (2ip, вечный кэш — повторно не дергаем).
	ips := map[string]bool{}
	for _, r := range rows {
		if r.OK {
			for _, a := range r.Answers {
				if net.ParseIP(a) != nil {
					ips[a] = true
				}
			}
		}
	}
	ipList := make([]string, 0, len(ips))
	for ip := range ips {
		ipList = append(ipList, ip)
	}
	infos := geoip.LookupMany(ipList)
	asnOf := func(ip string) string {
		if v, ok := infos[ip]; ok && !v.Unknown && v.ASN.ID != 0 {
			return fmt.Sprintf("AS%d", v.ASN.ID)
		}
		// фолбэк без ключа: Team Cymru origin.asn по DNS
		if asn := cymruASN(ip); asn != "" {
			return asn
		}
		return ""
	}
	asnFreq := map[string]int{}
	rowASN := make([][]string, len(rows))
	for i, r := range rows {
		if !r.OK {
			continue
		}
		seen := map[string]bool{}
		for _, a := range r.Answers {
			if asn := asnOf(a); asn != "" && !seen[asn] {
				seen[asn] = true
				rowASN[i] = append(rowASN[i], asn)
				asnFreq[asn]++
			}
		}
		rows[i].ASN = rowASN[i]
	}
	consensus := false
	for _, n := range asnFreq {
		if n >= 3 {
			consensus = true
			break
		}
	}
	for i, r := range rows {
		if r.OK && len(rowASN[i]) > 0 && consensus {
			hit := false
			for _, a := range rowASN[i] {
				c := 0
				for j := range rows {
					if !rows[j].OK {
						continue
					}
					for _, b := range rowASN[j] {
						if b == a {
							c++
						}
					}
				}
				if c >= 2 {
					hit = true
					break
				}
			}
			rows[i].SpoofSuspect = !hit
		}
	}
	j := Result{Target: jb.Target, Baseline: baseline, Rows: rows}
	jb.Baseline = j.Baseline
	for i := range rows {
		jb.Rows[i] = rows[i]
	}
	jb.Finished = true
}

func GetJob(id string) (*Job, bool) {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	j, ok := jobs[id]
	return j, ok
}

// Snapshot копия для API.
func (j *Job) Snapshot() Result {
	j.mu.Lock()
	defer j.mu.Unlock()
	rows := append([]One(nil), j.Rows...)
	done := []One{}
	for _, r := range rows {
		if r.Resolver != "" || r.Error != "" {
			done = append(done, r)
		}
	}
	return Result{Target: j.Target, Baseline: j.Baseline, Rows: done}
}

func (j *Job) Progress() (int, int, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.DoneN, j.Total, j.Finished
}


func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// cymruASN возвращает "AS15169" через Team Cymru (DNS, без ключа):
// <reverse-ip>.origin.asn.cymru.com TXT -> "15169 | ...".
// IPv6: <nibble-reversed>.origin6.asn.cymru.com.
func cymruASN(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	var q string
	if parsed.To4() != nil {
		parts := strings.Split(parsed.To4().String(), ".")
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		q = strings.Join(parts, ".") + ".origin.asn.cymru.com"
	} else {
		expanded := parsed.To16()
		if expanded == nil {
			return ""
		}
		var nibbles []string
		for i := len(expanded) - 1; i >= 0; i-- {
			nibbles = append(nibbles, fmt.Sprintf("%x", expanded[i]&0xf), fmt.Sprintf("%x", expanded[i]>>4))
		}
		q = strings.Join(nibbles, ".") + ".origin6.asn.cymru.com"
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(q), dns.TypeTXT)
	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	resp, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		return ""
	}
	for _, a := range resp.Answer {
		if txt, ok := a.(*dns.TXT); ok && len(txt.Txt) > 0 {
			fields := strings.Split(txt.Txt[0], "|")
			if id := strings.TrimSpace(fields[0]); id != "" {
				return "AS" + id
			}
		}
	}
	return ""
}

// Sweep чистит старые законченные задачи.
func Sweep(maxAge time.Duration, cap int) {
	cutoff := time.Now().Add(-maxAge)
	jobsMu.Lock()
	defer jobsMu.Unlock()
	for id, j := range jobs {
		j.mu.Lock()
		old := j.Finished && j.Started.Before(cutoff)
		j.mu.Unlock()
		if old {
			delete(jobs, id)
		}
	}
	for len(jobs) > cap {
		oldest := ""
		for id, j := range jobs {
			j.mu.Lock()
			fin, st := j.Finished, j.Started
			j.mu.Unlock()
			if !fin {
				continue
			}
			if oldest == "" {
				oldest = id
				continue
			}
			oj := jobs[oldest]
			oj.mu.Lock()
			ost := oj.Started
			oj.mu.Unlock()
			if st.Before(ost) {
				oldest = id
			}
		}
		if oldest == "" {
			break
		}
		delete(jobs, oldest)
	}
}
