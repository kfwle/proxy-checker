package checker

// Качество прокси: скорость через туннель, unlock-проверки сервисов
// и репутация выходного IP (DNSBL). Всё гоняется через тот же прокси,
// что и обычная проверка, но на уже поднятом локальном socks.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

// Tunnel — поднятый локальный прокси (socks-порт ядра либо direct-прокси).
type Tunnel struct {
	Core    string
	port    int
	proxies []*url.URL
	cleanup func()
}

// OpenTunnel поднимает туннель под ссылку тем же ядром, что и обычная проверка.
// Пустая ссылка = без прокси (прямой замер с этой машины).
func OpenTunnel(ctx context.Context, link string, startup time.Duration) (*Tunnel, string) {
	if strings.TrimSpace(link) == "" {
		return &Tunnel{Core: "local", proxies: []*url.URL{nil}, cleanup: func() {}}, ""
	}
	proto := DetectProtocol(link)
	if proto == "mtproto" {
		return nil, "mtproto-checker не отдаёт локальный socks — скорость/unlock для tg-ссылок недоступны"
	}
	if proto == "webproxy" {
		return nil, "webproxy не поддерживает локальный туннель"
	}
	for _, core := range resolveChain(proto, link, Options{}) {
		switch core {
		case "direct":
			proxies, errStr := directProxyURLs(link)
			if errStr != "" {
				return nil, errStr
			}
			return &Tunnel{Core: "direct", proxies: proxies, cleanup: func() {}}, ""
		case "sing-box":
			port, cleanup, errStr := startSingBox(ctx, link, startup)
			if errStr == "ERR_NO_BINARY" {
				continue
			}
			if errStr != "" {
				return nil, errStr
			}
			return &Tunnel{Core: core, port: port, proxies: []*url.URL{socksURL(port)}, cleanup: cleanup}, ""
		case "xray":
			port, cleanup, errStr := startXray(ctx, link, startup)
			if errStr == "ERR_NO_BINARY" {
				continue
			}
			if errStr != "" {
				return nil, errStr
			}
			return &Tunnel{Core: core, port: port, proxies: []*url.URL{socksURL(port)}, cleanup: cleanup}, ""
		case "mihomo":
			port, cleanup, errStr := startMihomo(ctx, link, startup)
			if errStr == "ERR_NO_BINARY" {
				continue
			}
			if errStr != "" {
				return nil, errStr
			}
			return &Tunnel{Core: core, port: port, proxies: []*url.URL{socksURL(port)}, cleanup: cleanup}, ""
		case "juicity-client":
			port, cleanup, errStr := runJuicity(ctx, link, startup)
			if errStr == "ERR_NO_BINARY" {
				continue
			}
			if errStr != "" {
				return nil, errStr
			}
			return &Tunnel{Core: core, port: port, proxies: []*url.URL{socksURL(port)}, cleanup: cleanup}, ""
		case "mieru":
			port, cleanup, errStr := runMieru(ctx, link, startup)
			if errStr == "ERR_NO_BINARY" {
				continue
			}
			if errStr != "" {
				return nil, errStr
			}
			return &Tunnel{Core: core, port: port, proxies: []*url.URL{socksURL(port)}, cleanup: cleanup}, ""
		}
	}
	return nil, "нет подходящего ядра — скачайте ядра во вкладке Ядра"
}

func socksURL(port int) *url.URL {
	u, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	return u
}

// directProxyURLs — прокси из самой ссылки (http/socks/host:port).
func directProxyURLs(link string) ([]*url.URL, string) {
	l := strings.TrimSpace(link)
	if !strings.Contains(l, "://") {
		host, port, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return nil, "invalid host:port"
		}
		host, port = strings.TrimSpace(host), strings.TrimSpace(port)
		var out []*url.URL
		for _, scheme := range []string{"http", "socks5"} {
			u, err := url.Parse(fmt.Sprintf("%s://%s:%s", scheme, host, port))
			if err == nil && u.Hostname() != "" && u.Port() != "" {
				out = append(out, u)
			}
		}
		if len(out) == 0 {
			return nil, "invalid host:port"
		}
		return out, ""
	}
	u, err := url.Parse(l)
	if err != nil || u.Hostname() == "" {
		return nil, "bad proxy url"
	}
	if strings.EqualFold(u.Scheme, "socks") {
		u.Scheme = "socks5"
	}
	return []*url.URL{u}, ""
}

// Close останавливает ядро/туннель.
func (t *Tunnel) Close() {
	if t != nil && t.cleanup != nil {
		t.cleanup()
	}
}

func (t *Tunnel) client(proxy *url.URL, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:               http.ProxyURL(proxy),
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// newRequest собирает запрос с браузерным UA (часть сервисов режет curl).
func newRequest(ctx context.Context, method, target string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "*/*")
	return req, nil
}

// get делает GET через туннель; при нескольких direct-прокси пробует по очереди.
func (t *Tunnel) get(ctx context.Context, target string, timeout time.Duration, maxBody int64) ([]byte, int, string) {
	var lastErr string
	for _, pu := range t.proxies {
		req, err := newRequest(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, 0, err.Error()
		}
		c := t.client(pu, timeout)
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err.Error()
			c.CloseIdleConnections()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		c.CloseIdleConnections()
		return body, resp.StatusCode, ""
	}
	if lastErr == "" {
		lastErr = "нет прокси"
	}
	return nil, 0, lastErr
}

// download качает до limit байт и возвращает (байты, длительность, ошибка).
func (t *Tunnel) download(ctx context.Context, target string, limit int64, timeout time.Duration) (int64, time.Duration, string) {
	var lastErr string
	for _, pu := range t.proxies {
		req, err := newRequest(ctx, http.MethodGet, target, nil)
		if err != nil {
			return 0, 0, err.Error()
		}
		if limit > 0 {
			// просим ровно limit байт, чтобы не тянуть весь 100-МБ файл
			req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", limit-1))
		}
		c := t.client(pu, timeout)
		start := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err.Error()
			c.CloseIdleConnections()
			continue
		}
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
		elapsed := time.Since(start)
		resp.Body.Close()
		c.CloseIdleConnections()
		if n == 0 {
			lastErr = fmt.Sprintf("пустой ответ (HTTP %d)", resp.StatusCode)
			continue
		}
		return n, elapsed, ""
	}
	if lastErr == "" {
		lastErr = "нет прокси"
	}
	return 0, 0, lastErr
}

// upload заливает size байт и возвращает (байты, длительность, ошибка).
func (t *Tunnel) upload(ctx context.Context, target string, size int64, timeout time.Duration) (int64, time.Duration, string) {
	payload := make([]byte, size)
	var lastErr string
	for _, pu := range t.proxies {
		req, err := newRequest(ctx, http.MethodPost, target, bytes.NewReader(payload))
		if err != nil {
			return 0, 0, err.Error()
		}
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
		c := t.client(pu, timeout)
		start := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err.Error()
			c.CloseIdleConnections()
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		elapsed := time.Since(start)
		resp.Body.Close()
		c.CloseIdleConnections()
		if resp.StatusCode >= 400 {
			lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
			continue
		}
		return size, elapsed, ""
	}
	if lastErr == "" {
		lastErr = "нет прокси"
	}
	return 0, 0, lastErr
}

// SpeedServer — публичная точка замера скорости.
type SpeedServer struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Region string `json:"region"`
	Upload bool   `json:"upload"`
	down   string
	up     string
	fmtURL bool
}

var speedServers = []SpeedServer{
	{ID: "cloudflare", Name: "Cloudflare", Region: "global", Upload: true,
		down: "https://speed.cloudflare.com/__down?bytes=%d", up: "https://speed.cloudflare.com/__up", fmtURL: true},
	{ID: "ovh", Name: "OVH", Region: "EU · Франция", down: "https://proof.ovh.net/files/100Mb.dat"},
	{ID: "cachefly", Name: "CacheFly", Region: "CDN · global", down: "https://cachefly.cachefly.net/10mb.test"},
	{ID: "tele2", Name: "Tele2", Region: "EU · Швеция", down: "http://speedtest.tele2.net/100MB.zip"},
	{ID: "vultr-nj", Name: "Vultr", Region: "US · Нью-Джерси", down: "https://nj-us-ping.vultr.com/vultr.com.100MB.bin"},
	{ID: "vultr-sgp", Name: "Vultr", Region: "Asia · Сингапур", down: "https://sgp-ping.vultr.com/vultr.com.100MB.bin"},
	{ID: "yandex", Name: "Yandex Mirror", Region: "RU · Москва",
		down: "https://mirror.yandex.ru/debian/dists/stable/main/installer-amd64/current/images/netboot/mini.iso"},
}

// SpeedServers — каталог серверов для UI.
func SpeedServers() []SpeedServer {
	out := make([]SpeedServer, len(speedServers))
	copy(out, speedServers)
	return out
}

func findSpeedServer(id string) *SpeedServer {
	for i := range speedServers {
		if speedServers[i].ID == id {
			return &speedServers[i]
		}
	}
	return nil
}

// SpeedResult — замер скорости через прокси.
type SpeedResult struct {
	OK        bool    `json:"ok"`
	Core      string  `json:"core,omitempty"`
	Server    string  `json:"server,omitempty"`
	DownMbps  float64 `json:"downMbps"`
	UpMbps    float64 `json:"upMbps"`
	DownMb    float64 `json:"downMb"`
	UpMb      float64 `json:"upMb"`
	LatencyMs int64   `json:"latencyMs"`
	Error     string  `json:"error,omitempty"`
	UpError   string  `json:"upError,omitempty"`
}

// SpeedTest качает/заливает данные через прокси (link="" — напрямую) и считает Mbps.
func SpeedTest(ctx context.Context, link, serverID string, downBytes, upBytes int64) SpeedResult {
	if downBytes <= 0 {
		downBytes = 20 << 20
	}
	if downBytes < 1<<20 {
		downBytes = 1 << 20
	}
	if downBytes > 100<<20 {
		downBytes = 100 << 20
	}
	if upBytes < 0 {
		upBytes = 0
	}
	if upBytes > 50<<20 {
		upBytes = 50 << 20
	}
	srv := findSpeedServer(serverID)
	if srv == nil {
		srv = findSpeedServer("cloudflare")
	}
	res := SpeedResult{Server: srv.Name}
	tun, errStr := OpenTunnel(ctx, link, 10*time.Second)
	if errStr != "" {
		res.Error = errStr
		return res
	}
	defer tun.Close()
	res.Core = tun.Core

	target := srv.down
	if srv.fmtURL {
		target = fmt.Sprintf(srv.down, downBytes)
	}
	n, elapsed, errStr := tun.download(ctx, target, downBytes, 90*time.Second)
	if errStr != "" && srv.ID == "cloudflare" {
		// запасной источник, если Cloudflare недоступен
		n, elapsed, errStr = tun.download(ctx, "https://proof.ovh.net/files/10Mb.dat", downBytes, 90*time.Second)
	}
	if errStr != "" {
		res.Error = "download: " + errStr
		return res
	}
	res.DownMb = float64(n) / (1 << 20)
	res.LatencyMs = elapsed.Milliseconds()
	if sec := elapsed.Seconds(); sec > 0 {
		res.DownMbps = float64(n) * 8 / sec / 1e6
	}

	if upBytes > 0 {
		if srv.up == "" {
			res.UpError = "upload не поддерживается этим сервером"
		} else if upN, upElapsed, upErr := tun.upload(ctx, srv.up, upBytes, 90*time.Second); upErr != "" {
			res.UpError = upErr
		} else {
			res.UpMb = float64(upN) / (1 << 20)
			if sec := upElapsed.Seconds(); sec > 0 {
				res.UpMbps = float64(upN) * 8 / sec / 1e6
			}
		}
	}
	res.OK = true
	return res
}

// UnlockService — вердикт по одному сервису.
type UnlockService struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // yes | no | unknown | error
	Region string `json:"region,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// UnlockResult — набор unlock-проверок через прокси.
type UnlockResult struct {
	OK       bool            `json:"ok"`
	Core     string          `json:"core,omitempty"`
	Services []UnlockService `json:"services,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// UnlockTest проверяет доступность сервисов через прокси.
func UnlockTest(ctx context.Context, link string, timeout time.Duration) UnlockResult {
	tun, errStr := OpenTunnel(ctx, link, 10*time.Second)
	if errStr != "" {
		return UnlockResult{Error: errStr}
	}
	defer tun.Close()
	out := UnlockResult{OK: true, Core: tun.Core}
	services := []UnlockService{
		{ID: "youtube", Name: "YouTube Premium"},
		{ID: "netflix", Name: "Netflix"},
		{ID: "chatgpt", Name: "ChatGPT"},
		{ID: "spotify", Name: "Spotify"},
	}
	var wg sync.WaitGroup
	for i := range services {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			services[i] = checkUnlock(ctx, tun, services[i], timeout)
		}(i)
	}
	wg.Wait()
	out.Services = services
	return out
}

var (
	ytCountryRe = regexp.MustCompile(`"countryCode":"([A-Z]{2})"`)
	ytGLRe      = regexp.MustCompile(`"GL":"([A-Z]{2})"`)
	traceLocRe  = regexp.MustCompile(`(?m)^loc=([A-Z]{2})$`)
)

func checkUnlock(ctx context.Context, tun *Tunnel, s UnlockService, timeout time.Duration) UnlockService {
	switch s.ID {
	case "youtube":
		body, code, errStr := tun.get(ctx, "https://www.youtube.com/premium", timeout, 512<<10)
		if errStr != "" {
			s.Status, s.Detail = "error", errStr
			return s
		}
		if m := ytCountryRe.FindSubmatch(body); m != nil {
			s.Region = string(m[1])
		} else if m := ytGLRe.FindSubmatch(body); m != nil {
			s.Region = string(m[1])
		}
		low := strings.ToLower(string(body))
		switch {
		case code != http.StatusOK:
			s.Status, s.Detail = "no", fmt.Sprintf("HTTP %d", code)
		case strings.Contains(low, "not available in your country"):
			s.Status, s.Detail = "no", "Premium недоступен в регионе"
		case strings.Contains(low, "consent.youtube.com"):
			s.Status, s.Detail = "unknown", "редирект на consent"
		default:
			s.Status = "yes"
		}
		return s
	case "netflix":
		body, code, errStr := tun.get(ctx, "https://www.netflix.com/title/81280792", timeout, 512<<10)
		if errStr != "" {
			s.Status, s.Detail = "error", errStr
			return s
		}
		low := string(body)
		switch {
		case code != http.StatusOK:
			s.Status, s.Detail = "no", fmt.Sprintf("HTTP %d", code)
		case strings.Contains(low, "Not Available"):
			s.Status, s.Detail = "no", "Not Available в регионе"
		case len(body) < 4096:
			s.Status, s.Detail = "unknown", "слишком короткая страница"
		default:
			s.Status = "yes"
		}
		return s
	case "chatgpt":
		trace, _, errStr := tun.get(ctx, "https://chatgpt.com/cdn-cgi/trace", timeout, 32<<10)
		if errStr != "" {
			s.Status, s.Detail = "error", errStr
			return s
		}
		if m := traceLocRe.FindSubmatch(trace); m != nil {
			s.Region = string(m[1])
		}
		body, code, errStr := tun.get(ctx, "https://chatgpt.com/", timeout, 512<<10)
		if errStr != "" {
			s.Status, s.Detail = "error", errStr
			return s
		}
		low := strings.ToLower(string(body))
		switch {
		case code == http.StatusForbidden && strings.Contains(low, "unsupported_country"):
			s.Status, s.Detail = "no", "unsupported_country"
		case strings.Contains(low, "unsupported_country"):
			s.Status, s.Detail = "no", "unsupported_country"
		case code == http.StatusOK:
			s.Status = "yes"
		default:
			s.Status, s.Detail = "unknown", fmt.Sprintf("HTTP %d", code)
		}
		return s
	case "spotify":
		_, code, errStr := tun.get(ctx, "https://open.spotify.com/", timeout, 128<<10)
		if errStr != "" {
			s.Status, s.Detail = "error", errStr
			return s
		}
		if code == http.StatusOK {
			s.Status, s.Detail = "yes", "веб-версия доступна"
		} else {
			s.Status, s.Detail = "no", fmt.Sprintf("HTTP %d", code)
		}
		return s
	}
	s.Status = "unknown"
	return s
}

// DNSBLList — вердикт по одному блэклисту.
type DNSBLList struct {
	Name   string `json:"name"`
	Zone   string `json:"zone"`
	Status string `json:"status"` // listed | clean | unknown
	Detail string `json:"detail,omitempty"`
}

// ReputationResult — репутация выходного IP прокси.
type ReputationResult struct {
	OK      bool        `json:"ok"`
	Core    string      `json:"core,omitempty"`
	ExitIP  string      `json:"exitIp,omitempty"`
	Country string      `json:"country,omitempty"`
	ASN     string      `json:"asn,omitempty"`
	Listed  int         `json:"listed"`
	Lists   []DNSBLList `json:"lists,omitempty"`
	Error   string      `json:"error,omitempty"`
}

var dnsblZones = []struct{ name, zone string }{
	{"Spamhaus ZEN", "zen.spamhaus.org"},
	{"SpamCop", "bl.spamcop.net"},
	{"Barracuda", "b.barracudacentral.org"},
	{"SORBS", "dnsbl.sorbs.net"},
	{"PSBL", "psbl.surriel.com"},
	{"DroneBL", "dnsbl.dronebl.org"},
	{"UCEPROTECT L1", "dnsbl-1.uceprotect.net"},
	{"JustSpam", "dnsbl.justspam.org"},
}

// Reputation проверяет exit-IP прокси по DNSBL.
func Reputation(ctx context.Context, link string, timeout time.Duration) ReputationResult {
	out := ReputationResult{}
	exit := ExitIP(ctx, link, timeout)
	if !exit.OK {
		// 2ip может отдать 429/без токена — пробуем простые echo-сервисы
		if ip, core, errStr := exitIPFallback(ctx, link, timeout); errStr == "" {
			exit.OK = true
			exit.ExitIP = ip
			exit.Core = core
		}
	}
	if !exit.OK {
		out.Error = exit.Error
		if out.Error == "" {
			out.Error = "не удалось узнать exit-IP"
		}
		return out
	}
	out.Core = exit.Core
	out.ExitIP = exit.ExitIP
	out.Country = exit.Country
	out.ASN = exit.ASN
	if strings.Contains(exit.ExitIP, ":") {
		out.Error = "DNSBL проверяет только IPv4, у прокси IPv6-выход"
		return out
	}
	parts := strings.Split(exit.ExitIP, ".")
	if len(parts) != 4 {
		out.Error = "некорректный exit-IP: " + exit.ExitIP
		return out
	}
	rev := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
	out.Lists = make([]DNSBLList, len(dnsblZones))
	var wg sync.WaitGroup
	for i, z := range dnsblZones {
		out.Lists[i] = DNSBLList{Name: z.name, Zone: z.zone, Status: "unknown"}
		wg.Add(1)
		go func(i int, zone string) {
			defer wg.Done()
			out.Lists[i] = lookupDNSBL(ctx, out.Lists[i], rev+"."+zone)
		}(i, z.zone)
	}
	wg.Wait()
	for _, l := range out.Lists {
		if l.Status == "listed" {
			out.Listed++
		}
	}
	out.OK = true
	return out
}

// exitIPFallback спрашивает exit-IP у простых echo-сервисов (без ключей и квот).
func exitIPFallback(ctx context.Context, link string, timeout time.Duration) (string, string, string) {
	tun, errStr := OpenTunnel(ctx, link, 10*time.Second)
	if errStr != "" {
		return "", "", errStr
	}
	defer tun.Close()
	for _, target := range []string{"https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"} {
		body, code, errStr := tun.get(ctx, target, timeout, 4<<10)
		if errStr != "" || code != http.StatusOK {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip, tun.Core, ""
		}
	}
	return "", tun.Core, "не удалось определить exit-IP"
}

func lookupDNSBL(ctx context.Context, item DNSBLList, query string) DNSBLList {
	qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(qctx, query)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			item.Status = "clean"
			return item
		}
		item.Status = "unknown"
		item.Detail = "ошибка DNS: " + err.Error()
		return item
	}
	for _, a := range addrs {
		if strings.HasPrefix(a, "127.255.255.") {
			item.Status = "unknown"
			item.Detail = "запрос заблокирован блэклистом"
			return item
		}
		if strings.HasPrefix(a, "127.") {
			item.Status = "listed"
			item.Detail = a
			return item
		}
	}
	// 0.0.0.0/иное — считаем чистым
	item.Status = "clean"
	return item
}
