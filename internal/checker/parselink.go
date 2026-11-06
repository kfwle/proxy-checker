package checker

// Общий парсер proxy-ссылок для xray/mihomo-раннеров.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type parsedLink struct {
	Scheme   string
	User     string // uuid / username
	Password string
	Host     string
	Port     int
	Params   url.Values
	Raw      string
}

// parseLink разбирает ссылку; порт ищет в host, затем в ?port=.
// ss-ссылки часто целиком в base64 — для них отдельный разбор.
func parseLink(link string) (*parsedLink, error) {
	l := strings.TrimSpace(link)
	u, err := url.Parse(l)
	if err != nil || u.Scheme == "" {
		return nil, fmt.Errorf("не смог распарсить ссылку (нужен scheme://host...)")
	}
	if strings.ToLower(u.Scheme) == "ss" {
		if pl, err := parseSSLink(l); err == nil {
			return pl, nil
		}
		// иначе падаем в общий путь (может, открытая форма)
	}
	if strings.ToLower(u.Scheme) == "vmess" && (u.User == nil || u.Port() == "") {
		// стандартная форма vmess://<base64-json>
		if pl, err := parseVmessBase64(l); err == nil {
			return pl, nil
		}
	}
	if u.Host == "" {
		return nil, fmt.Errorf("пустой host")
	}
	pl := &parsedLink{Scheme: strings.ToLower(u.Scheme), Host: u.Hostname(), Params: u.Query(), Raw: l}
	if u.User != nil {
		pl.User = u.User.Username()
		pl.Password, _ = u.User.Password()
		// ss://method:password@host — method в username
	}
	p := u.Port()
	if p == "" {
		p = u.Query().Get("port")
	}
	fmt.Sscanf(p, "%d", &pl.Port)
	if pl.Host == "" {
		return nil, fmt.Errorf("пустой host")
	}
	if pl.Port == 0 {
		return nil, fmt.Errorf("нет порта в ссылке")
	}
	return pl, nil
}

func (p *parsedLink) q(keys ...string) string {
	for _, k := range keys {
		if v := p.Params.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func (p *parsedLink) insecure() bool {
	v := strings.ToLower(p.q("insecure", "allowInsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify"))
	return v == "1" || v == "true"
}

func (p *parsedLink) sni() string {
	if v := p.q("sni", "servername", "serverName", "peer"); v != "" {
		return v
	}
	if v := p.q("host"); v != "" && p.transport() != "tcp" {
		return v
	}
	return p.Host
}

// transport возвращает тип транспорта: tcp/ws/grpc/httpupgrade/quic/""
func (p *parsedLink) transport() string {
	t := strings.ToLower(p.q("type", "transport", "net"))
	switch t {
	case "ws", "websocket":
		return "ws"
	case "grpc", "gun":
		return "grpc"
	case "httpupgrade", "http-upgrade", "http":
		// осторожно: http может быть схемой; как транспорт — только явный флаг
		if strings.ToLower(p.q("type")) == "httpupgrade" || strings.ToLower(p.q("transport")) == "httpupgrade" {
			return "httpupgrade"
		}
		return ""
	case "quic":
		return "quic"
	case "tcp", "none", "":
		return "tcp"
	default:
		return t
	}
}

func (p *parsedLink) wsPath() string {
	if v := p.q("path"); v != "" {
		return v
	}
	return "/"
}

func (p *parsedLink) wsHost() string {
	return p.q("host", "ws-host", "ws_host")
}

// parseSSLink разбирает ss-ссылку целиком (включая base64-формы).
func parseSSLink(l string) (*parsedLink, error) {
	after := l[strings.Index(l, "://")+3:]
	query := url.Values{}
	if i := strings.IndexAny(after, "?#"); i >= 0 {
		if uq, err := url.ParseQuery(strings.TrimLeft(after[i:], "?#")); err == nil {
			query = uq
		}
		after = after[:i]
	}
	var userinfo, hostport string
	if strings.Contains(after, "@") {
		left := after[:strings.LastIndex(after, "@")]
		hostport = after[strings.LastIndex(after, "@")+1:]
		if dec, err := b64decode(left); err == nil && strings.Contains(dec, ":") {
			userinfo = dec
		} else {
			userinfo = left
		}
	} else {
		dec, err := b64decode(after)
		if err != nil {
			return nil, fmt.Errorf("не смог разобрать ss-ссылку")
		}
		at := strings.LastIndex(dec, "@")
		if at < 0 {
			return nil, fmt.Errorf("не смог разобрать ss-ссылку")
		}
		userinfo, hostport = dec[:at], dec[at+1:]
	}
	ci := strings.Index(userinfo, ":")
	if ci < 0 {
		return nil, fmt.Errorf("нет method:password в ss-ссылке")
	}
	host := hostport
	port := 0
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		host = hostport[:i]
		fmt.Sscanf(hostport[i+1:], "%d", &port)
	}
	if host == "" || port == 0 {
		return nil, fmt.Errorf("нет host:port в ss-ссылке")
	}
	return &parsedLink{Scheme: "ss", User: userinfo[:ci], Password: userinfo[ci+1:], Host: host, Port: port, Params: query, Raw: l}, nil
}

// parseVmessBase64 разбирает каноническую vmess://<base64-json> ссылку
// (add/port/id/net/tls/host/path/sni) в общий parsedLink.
func parseVmessBase64(l string) (*parsedLink, error) {
	rest := strings.TrimPrefix(strings.TrimSpace(l), "vmess://")
	if i := strings.IndexAny(rest, "#?"); i >= 0 {
		rest = rest[:i]
	}
	dec, err := b64decode(rest)
	if err != nil {
		return nil, fmt.Errorf("vmess: не base64")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(dec), &m); err != nil {
		return nil, fmt.Errorf("vmess: не JSON")
	}
	str := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return strings.TrimSpace(v)
		case float64:
			return strconv.FormatInt(int64(v), 10)
		}
		return ""
	}
	host := str("add")
	port := 0
	fmt.Sscanf(str("port"), "%d", &port)
	uuid := str("id")
	if host == "" || port == 0 || uuid == "" {
		return nil, fmt.Errorf("vmess: нет add/port/id")
	}
	q := url.Values{}
	if v := str("scy"); v != "" {
		q.Set("scy", v)
	}
	if v := str("aid"); v != "" {
		q.Set("alterId", v)
	}
	netw := strings.ToLower(str("net"))
	if netw == "" {
		netw = "tcp"
	}
	q.Set("type", netw)
	if v := str("host"); v != "" {
		q.Set("host", v)
	}
	path := str("path")
	if netw == "grpc" {
		if path != "" {
			q.Set("serviceName", path)
		}
	} else if path != "" {
		q.Set("path", path)
	}
	if strings.EqualFold(str("tls"), "tls") {
		q.Set("security", "tls")
	}
	if v := str("sni"); v != "" {
		q.Set("sni", v)
	}
	if v := str("fp"); v != "" {
		q.Set("fp", v)
	}
	if v := str("alpn"); v != "" {
		q.Set("alpn", v)
	}
	return &parsedLink{Scheme: "vmess", User: uuid, Host: host, Port: port, Params: q, Raw: l}, nil
}

func looksB64(s string) bool {
	if len(s) < 8 || len(s)%4 != 0 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

func b64decode(s string) (string, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	b, err := base64.RawStdEncoding.DecodeString(s)
	return string(b), err
}
