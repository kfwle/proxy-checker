package checker

// Exit herd: запрос к api.2ip.io ЧЕРЕЗ прокси — показывает,
// каким IP/гео прокси выходит в интернет.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ExitInfo struct {
	OK        bool   `json:"ok"`
	LatencyMs int64  `json:"latencyMs"`
	Core      string `json:"core"`
	Error     string `json:"error,omitempty"`
	ExitIP    string `json:"exitIp,omitempty"`
	Country   string `json:"country,omitempty"`
	Code      string `json:"code,omitempty"`
	Emoji     string `json:"emoji,omitempty"`
	City      string `json:"city,omitempty"`
	ASN       string `json:"asn,omitempty"`
	Hosting   *bool  `json:"hosting,omitempty"`
}

const exitURL = "https://api.2ip.io/"

// ExitIP гоняет api.2ip.io через прокси из ссылки.
func ExitIP(ctx context.Context, link string, timeout time.Duration) ExitInfo {
	proto := DetectProtocol(link)
	out := ExitInfo{}
	var body []byte
	var ms int64
	var errStr string
	switch proto {
	case "http", "socks5", "unknown":
		out.Core = "direct"
		body, ms, errStr = fetchBodyViaProxy(ctx, link, timeout)
	case "juicity":
		out.Core = "juicity-client"
		body, ms, errStr = fetchBodyViaJuicity(ctx, link, exitURL, timeout)
		if errStr == "ERR_NO_BINARY" {
			out.Error = "скачайте juicity-client во вкладке Ядра"
			return out
		}
	case "mieru":
		out.Core = "mieru"
		body, ms, errStr = fetchBodyViaMieru(ctx, link, exitURL, timeout)
		if errStr == "ERR_NO_BINARY" {
			out.Error = "скачайте mieru во вкладке Ядра"
			return out
		}
	default:
		out.Core = "sing-box"
		body, ms, errStr = fetchViaSingBox(ctx, link, exitURL, timeout, false)
		if errStr == "ERR_NO_BINARY" {
			out.Error = "скачайте sing-box во вкладке Ядра"
			return out
		}
	}
	out.LatencyMs = ms
	if errStr != "" {
		out.Error = errStr
		return out
	}
	var v struct {
		IP      string `json:"ip"`
		City    string `json:"city"`
		Country string `json:"country"`
		Code    string `json:"code"`
		Emoji   string `json:"emoji"`
		ASN     struct {
			ID      int    `json:"id"`
			Name    string `json:"name"`
			Hosting bool   `json:"hosting"`
		} `json:"asn"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.IP == "" {
		out.Error = "не смог разобрать ответ 2ip"
		return out
	}
	out.OK = true
	out.ExitIP = v.IP
	out.Country = v.Country
	out.Code = v.Code
	out.Emoji = v.Emoji
	out.City = v.City
	h := v.ASN.Hosting
	out.Hosting = &h
	if v.ASN.Name != "" {
		out.ASN = fmt.Sprintf("AS%d %s", v.ASN.ID, v.ASN.Name)
	}
	return out
}

func fetchBodyViaProxy(ctx context.Context, link string, timeout time.Duration) ([]byte, int64, string) {
	l := strings.TrimSpace(link)
	var proxyURL *url.URL
	if !strings.Contains(l, "://") {
		host, port, ok := strings.Cut(l, ":")
		if !ok {
			return nil, 0, "invalid host:port"
		}
		var err error
		proxyURL, err = url.Parse(fmt.Sprintf("socks5://%s:%s", strings.TrimSpace(host), strings.TrimSpace(port)))
		if err != nil {
			return nil, 0, "bad proxy"
		}
	} else {
		var err error
		proxyURL, err = url.Parse(l)
		if err != nil {
			return nil, 0, "bad url"
		}
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: (&net.Dialer{Timeout: timeout}).DialContext, TLSHandshakeTimeout: timeout}
	c := &http.Client{Transport: tr, Timeout: timeout}
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", exitURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 500 {
		return nil, 0, fmt.Sprintf("bad status %d", resp.StatusCode)
	}
	return raw, time.Since(start).Milliseconds(), ""
}
