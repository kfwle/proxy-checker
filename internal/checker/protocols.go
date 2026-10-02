package checker

import (
	"net/url"
	"strings"
)

// DetectProtocol returns normalized protocol id from a proxy link.
func DetectProtocol(link string) string {
	l := strings.TrimSpace(link)
	if l == "" {
		return ""
	}
	low := strings.ToLower(l)
	// tg links
	if strings.HasPrefix(low, "tg://proxy") || strings.HasPrefix(low, "https://t.me/proxy") || strings.HasPrefix(low, "http://t.me/proxy") {
		return "mtproto"
	}
	if strings.Contains(low, "webproxy") {
		return "webproxy"
	}
	// naive has two flavours: naive+https:// and naive+quic://, also https:// with naive params
	if strings.HasPrefix(low, "naive+https://") {
		return "naive"
	}
	if strings.HasPrefix(low, "naive+quic://") {
		return "naive"
	}
	// scheme:// ...
	if idx := strings.Index(l, "://"); idx > 0 {
		scheme := strings.ToLower(l[:idx])
		switch scheme {
		case "vless":
			return "vless"
		case "vmess":
			return "vmess"
		case "ss", "shadowsocks":
			return "ss"
		case "trojan":
			return "trojan"
		case "hy2", "hysteria2":
			return "hysteria2"
		case "hysteria":
			return "hysteria"
		case "anytls":
			return "anytls"
		case "tuic":
			return "tuic"
		case "juicity":
			return "juicity"
		case "mieru", "mierus":
			return "mieru"
		case "naive":
			return "naive"
		case "shadowtls":
			return "shadowtls"
		case "socks", "socks4", "socks5", "socks5h":
			return "socks5"
		case "http", "https":
			// https without naive params is plain http-proxy over tls; treat as http
			// naive over https uses ?padding / u / ... but transport is naive — check query
			if u, err := url.Parse(l); err == nil {
				q := u.Query()
				if q.Get("padding") != "" || strings.Contains(low, "naive") {
					return "naive"
				}
			}
			return "http"
		case "wireguard", "wg":
			return "wireguard"
		}
		// bare host:port
	}
	// bare host:port -> socks-ish unknown, treat as socks5/tcp for direct dial
	if strings.Contains(l, ":") && !strings.Contains(l, " ") {
		return "unknown"
	}
	return "unknown"
}

// detectTransportSecurity вытаскивает транспорт и защиту из ссылки:
// transport: ws/grpc/httpupgrade/quic/tcp, security: tls/reality/none.
func detectTransportSecurity(link string) (transport, security string) {
	l := strings.TrimSpace(link)
	u, err := url.Parse(l)
	if err != nil {
		return "tcp", ""
	}
	q := u.Query()
	t := strings.ToLower(firstNonEmpty(q.Get("type"), q.Get("transport"), q.Get("net")))
	switch t {
	case "ws", "websocket":
		transport = "ws"
	case "grpc", "gun":
		transport = "grpc"
	case "httpupgrade", "http-upgrade":
		transport = "httpupgrade"
	case "quic":
		transport = "quic"
	default:
		transport = "tcp"
	}
	sec := strings.ToLower(q.Get("security"))
	switch sec {
	case "tls", "reality":
		security = sec
	default:
		// эвристика как в раннерах: trojan/hy2/tuic и 443 почти всегда tls
		scheme := ""
		if i := strings.Index(l, "://"); i > 0 {
			scheme = strings.ToLower(l[:i])
		}
		port := u.Port()
		if scheme == "trojan" || scheme == "hy2" || scheme == "hysteria2" || scheme == "hysteria" || scheme == "tuic" {
			security = "tls"
		} else if port == "443" {
			security = "tls"
		} else {
			security = "none"
		}
	}
	return transport, security
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// resolveChain: правило (первое совпавшее) > выбранные плитки > дефолт.
// direct/mtproto/juicity/mieru всегда включены и фильтром плиток не режутся.
func resolveChain(proto, link string, opts Options) []string {
	transport, security := detectTransportSecurity(link)
	for _, rl := range opts.Rules {
		if rl.Core == "" {
			continue
		}
		if rl.Proto != "" && !strings.EqualFold(rl.Proto, proto) {
			continue
		}
		if rl.Transport != "" && !strings.EqualFold(rl.Transport, transport) {
			continue
		}
		if rl.Security != "" && !strings.EqualFold(rl.Security, security) {
			continue
		}
		if !validCoreName(rl.Core) {
			continue
		}
		return []string{rl.Core}
	}
	chain := CorePreference(proto)
	if len(opts.Cores) == 0 {
		return chain
	}
	allowed := map[string]bool{"direct": true, "mtproto-checker": true, "juicity-client": true, "mieru": true}
	for _, c := range opts.Cores {
		if c == "sing-box" || c == "xray" || c == "mihomo" {
			allowed[c] = true
		}
	}
	var out []string
	for _, c := range chain {
		if allowed[c] {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return chain // все выключили — проверяем дефолтом, а не молчим
	}
	return out
}

func validCoreName(c string) bool {
	switch c {
	case "sing-box", "xray", "mihomo", "direct", "mtproto-checker", "juicity-client", "mieru":
		return true
	}
	return false
}
func CorePreference(proto string) []string {
	switch proto {
	case "juicity":
		return []string{"juicity-client"}
	case "mieru":
		return []string{"mieru"}
	case "vless", "vmess", "ss", "trojan":
		return []string{"sing-box", "xray", "mihomo"}
	case "socks5", "http", "unknown":
		return []string{"direct", "sing-box", "xray", "mihomo"}
	case "hysteria2", "hysteria", "anytls", "tuic":
		return []string{"sing-box", "mihomo"}
	case "naive", "shadowtls", "wireguard":
		return []string{"sing-box"}
	case "mtproto", "webproxy", "tg":
		return []string{"mtproto-checker", "direct"}
	default:
		return []string{"sing-box", "direct"}
	}
}

// ParseHostPort extracts host/port for display.
func ParseHostPort(link string) (host, port string) {
	l := strings.TrimSpace(link)
	if strings.Contains(l, "://") {
		if u, err := url.Parse(l); err == nil && u.Host != "" {
			h := u.Hostname()
			p := u.Port()
			if p == "" {
				// try query port=
				p = u.Query().Get("port")
			}
			return h, p
		}
		// tg://proxy?server=H&port=P
		if u, err := url.Parse(l); err == nil {
			q := u.Query()
			if q.Get("server") != "" {
				return q.Get("server"), q.Get("port")
			}
		}
	}
	// host:port или голый host/IP (для ping)
	if !strings.Contains(l, " ") {
		parts := strings.Split(l, ":")
		if len(parts) == 2 {
			return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		}
		if len(parts) == 1 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0]), ""
		}
	}
	return "", ""
}
