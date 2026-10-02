package checker

// Общий парсер proxy-ссылок для xray/mihomo-раннеров.

import (
	"encoding/base64"
	"fmt"
	"net/url"
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
