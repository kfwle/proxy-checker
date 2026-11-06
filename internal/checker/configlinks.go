package checker

// Импорт JSON-конфигов: вставляешь целиком sing-box или xray конфиг —
// достаём из него проверяемые ссылки. Балансеры (selector/urltest)
// раскрываются в участников по тегам.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func qesc(s string) string { return url.QueryEscape(s) }

func frag(s string) string {
	// фрагмент ссылки: кодируем опасное
	r := strings.NewReplacer("#", "%23", " ", "%20", "\n", "")
	return r.Replace(s)
}

// ExtractLinks: ссылка как есть, JSON — разбираем в ссылки.
func ExtractLinks(input string) []string {
	t := strings.TrimSpace(input)
	if t == "" {
		return nil
	}
	if !strings.HasPrefix(t, "{") {
		return []string{t}
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(t), &raw); err != nil {
		return []string{t} // кривой JSON — пусть упадёт как invalid-ссылка
	}
	if obs, ok := raw["outbounds"].([]any); ok {
		if links := singBoxLinks(obs); len(links) > 0 {
			return links
		}
		if links := xrayLinks(obs); len(links) > 0 {
			return links
		}
	}
	return []string{t}
}

func strMap(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case float64:
				return fmt.Sprintf("%d", int(t))
			}
		}
	}
	return ""
}

func strMapNested(m map[string]any, path ...string) string {
	cur := m
	for i, k := range path {
		v, ok := cur[k]
		if !ok {
			return ""
		}
		if i == len(path)-1 {
			if s, ok := v.(string); ok {
				return s
			}
			return ""
		}
		nm, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		cur = nm
	}
	return ""
}

// singBoxLinks: outbounds sing-box -> ссылки (selector/urltest раскрываем).
func singBoxLinks(obs []any) []string {
	byTag := map[string]map[string]any{}
	for _, o := range obs {
		if m, ok := o.(map[string]any); ok {
			if tag, ok := m["tag"].(string); ok && tag != "" {
				byTag[tag] = m
			}
		}
	}
	var out []string
	seen := map[string]bool{} // защита от циклов selector A -> B -> A
	var walk func(m map[string]any)
	walk = func(m map[string]any) {
		if tag, ok := m["tag"].(string); ok && tag != "" {
			if seen[tag] {
				return
			}
			seen[tag] = true
		}
		typ, _ := m["type"].(string)
		switch typ {
		case "selector", "urltest":
			members, _ := m["outbounds"].([]any)
			for _, mm := range members {
				if tag, ok := mm.(string); ok {
					if target, ok := byTag[tag]; ok {
						walk(target)
					}
				}
			}
			return
		}
		if l := singBoxOutboundLink(m); l != "" {
			out = append(out, l)
		}
	}
	for _, o := range obs {
		if m, ok := o.(map[string]any); ok {
			if t, _ := m["type"].(string); t == "selector" || t == "urltest" {
				walk(m)
			}
		}
	}
	// если балансеров нет — все прямые
	if len(out) == 0 {
		for _, o := range obs {
			if m, ok := o.(map[string]any); ok {
				if l := singBoxOutboundLink(m); l != "" {
					out = append(out, l)
				}
			}
		}
	}
	return out
}

func sbTLSParams(m map[string]any, q url.Values) {
	tls, _ := m["tls"].(map[string]any)
	if tls == nil {
		return
	}
	if en, _ := tls["enabled"].(bool); !en {
		return
	}
	q.Set("security", "tls")
	if v := strMap(tls, "server_name"); v != "" {
		q.Set("sni", v)
	}
	if v, _ := tls["insecure"].(bool); v {
		q.Set("insecure", "1")
	}
	if v := strMap(tls, "fingerprint"); v != "" {
		q.Set("fp", v)
	}
	if v := strMap(tls, "alpn"); v != "" {
		q.Set("alpn", v)
	}
	// reality отмечает полем reality в tls у sing-box
	if r, ok := tls["reality"].(map[string]any); ok {
		if en, _ := r["enabled"].(bool); en {
			q.Set("security", "reality")
			if v := strMap(r, "public_key"); v != "" {
				q.Set("pbk", v)
			}
			if v := strMap(r, "short_id"); v != "" {
				q.Set("sid", v)
			}
		}
	}
}

func sbTransportParams(m map[string]any, q url.Values) {
	tr, _ := m["transport"].(map[string]any)
	if tr == nil {
		return
	}
	switch t, _ := tr["type"].(string); t {
	case "ws":
		q.Set("type", "ws")
		if v := strMap(tr, "path"); v != "" {
			q.Set("path", v)
		}
		if h, _ := tr["headers"].(map[string]any); h != nil {
			if v := strMap(h, "Host", "host"); v != "" {
				q.Set("host", v)
			}
		}
	case "grpc":
		q.Set("type", "grpc")
		if v := strMap(tr, "service_name"); v != "" {
			q.Set("serviceName", v)
		}
	case "httpupgrade":
		q.Set("type", "httpupgrade")
		if v := strMap(tr, "path"); v != "" {
			q.Set("path", v)
		}
	case "quic":
		q.Set("type", "quic")
	}
}

// singBoxOutboundLink: один outbound -> ссылка. "" = не умеем/пропускаем.
func singBoxOutboundLink(m map[string]any) string {
	typ, _ := m["type"].(string)
	server := strMap(m, "server")
	var port int
	fmt.Sscanf(strMap(m, "server_port"), "%d", &port)
	tag, _ := m["tag"].(string)
	if server == "" || port == 0 {
		return ""
	}
	q := url.Values{}
	sbTLSParams(m, q)
	sbTransportParams(m, q)
	hostport := fmt.Sprintf("%s:%d", server, port)
	switch typ {
	case "vless":
		uuid := strMap(m, "uuid")
		if uuid == "" {
			return ""
		}
		if v := strMap(m, "flow"); v != "" {
			q.Set("flow", v)
		}
		return fmt.Sprintf("vless://%s@%s?%s#%s", uuid, hostport, q.Encode(), frag(tag))
	case "vmess":
		uuid := strMap(m, "uuid")
		if uuid == "" {
			return ""
		}
		if v := strMap(m, "security"); v != "" && v != "auto" {
			q.Set("scy", v)
		}
		return fmt.Sprintf("vmess://%s@%s?%s#%s", uuid, hostport, q.Encode(), frag(tag))
	case "shadowsocks":
		method := strMap(m, "method")
		password := strMap(m, "password")
		if method == "" || password == "" {
			return ""
		}
		return fmt.Sprintf("ss://%s@%s#%s", b64std(method+":"+password), hostport, frag(tag))
	case "trojan":
		pw := strMap(m, "password")
		if pw == "" {
			return ""
		}
		return fmt.Sprintf("trojan://%s@%s?%s#%s", qesc(pw), hostport, q.Encode(), frag(tag))
	case "hysteria2", "hy2":
		pw := strMap(m, "password")
		if pw == "" {
			pw = strMap(m, "up_mbps")
		}
		if pw == "" {
			return ""
		}
		return fmt.Sprintf("hysteria2://%s@%s?%s#%s", qesc(pw), hostport, q.Encode(), frag(tag))
	case "hysteria":
		pw := strMap(m, "password", "auth_str", "auth")
		return fmt.Sprintf("hysteria://%s@%s?%s#%s", qesc(pw), hostport, q.Encode(), frag(tag))
	case "tuic":
		uuid := strMap(m, "uuid")
		pw := strMap(m, "password")
		if uuid == "" {
			return ""
		}
		if v := strMap(m, "congestion_control"); v != "" {
			q.Set("congestion_control", v)
		}
		return fmt.Sprintf("tuic://%s:%s@%s?%s#%s", qesc(uuid), qesc(pw), hostport, q.Encode(), frag(tag))
	case "anytls":
		pw := strMap(m, "password")
		if pw == "" {
			return ""
		}
		return fmt.Sprintf("anytls://%s@%s?%s#%s", qesc(pw), hostport, q.Encode(), frag(tag))
	case "socks":
		u := strMap(m, "username")
		pw := strMap(m, "password")
		auth := ""
		if u != "" {
			auth = qesc(u) + ":" + qesc(pw) + "@"
		}
		return fmt.Sprintf("socks5://%s%s#%s", auth, hostport, frag(tag))
	case "http":
		u := strMap(m, "username")
		pw := strMap(m, "password")
		auth := ""
		if u != "" {
			auth = qesc(u) + ":" + qesc(pw) + "@"
		}
		return fmt.Sprintf("http://%s%s#%s", auth, hostport, frag(tag))
	}
	return ""
}

// xrayLinks: outbounds xray (protocol/settings) -> ссылки.
func xrayLinks(obs []any) []string {
	var out []string
	for _, o := range obs {
		m, ok := o.(map[string]any)
		if !ok {
			continue
		}
		if l := xrayOutboundLink(m); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func xrayStreamParams(m map[string]any, q url.Values) {
	ss, _ := m["streamSettings"].(map[string]any)
	if ss == nil {
		return
	}
	if net, _ := ss["network"].(string); net != "" && net != "tcp" {
		switch net {
		case "ws":
			q.Set("type", "ws")
		case "grpc":
			q.Set("type", "grpc")
		case "httpupgrade":
			q.Set("type", "httpupgrade")
		default:
			q.Set("type", net)
		}
	}
	switch sec, _ := ss["security"].(string); sec {
	case "tls":
		q.Set("security", "tls")
		tls, _ := ss["tlsSettings"].(map[string]any)
		if tls != nil {
			if v := strMap(tls, "serverName"); v != "" {
				q.Set("sni", v)
			}
			if v, _ := tls["allowInsecure"].(bool); v {
				q.Set("insecure", "1")
			}
			if v, _ := tls["insecure"].(bool); v {
				q.Set("insecure", "1")
			}
			if v := strMap(tls, "fingerprint"); v != "" {
				q.Set("fp", v)
			}
		}
	case "reality":
		q.Set("security", "reality")
		rs, _ := ss["realitySettings"].(map[string]any)
		if rs != nil {
			if v := strMap(rs, "serverName"); v != "" {
				q.Set("sni", v)
			}
			if v := strMap(rs, "fingerprint"); v != "" {
				q.Set("fp", v)
			}
			if v := strMap(rs, "publicKey"); v != "" {
				q.Set("pbk", v)
			}
			if v := strMap(rs, "shortId"); v != "" {
				q.Set("sid", v)
			}
			if v := strMap(rs, "spiderX"); v != "" {
				q.Set("spx", v)
			}
		}
	}
	if ws, ok := ss["wsSettings"].(map[string]any); ok {
		if v := strMap(ws, "path"); v != "" {
			q.Set("path", v)
		}
		if h, ok := ws["headers"].(map[string]any); ok {
			if v := strMap(h, "Host", "host"); v != "" {
				q.Set("host", v)
			}
		}
	}
	if grpc, ok := ss["grpcSettings"].(map[string]any); ok {
		if v := strMap(grpc, "serviceName"); v != "" {
			q.Set("serviceName", v)
		}
	}
}

func firstServer(m map[string]any, keys ...string) map[string]any {
	settings, _ := m["settings"].(map[string]any)
	if settings == nil {
		return nil
	}
	for _, k := range keys {
		if arr, ok := settings[k].([]any); ok && len(arr) > 0 {
			if sm, ok := arr[0].(map[string]any); ok {
				return sm
			}
		}
	}
	return nil
}

// xrayOutboundLink: один outbound xray -> ссылка.
func xrayOutboundLink(m map[string]any) string {
	proto, _ := m["protocol"].(string)
	tag, _ := m["tag"].(string)
	q := url.Values{}
	xrayStreamParams(m, q)
	switch proto {
	case "vless":
		srv := firstServer(m, "vnext")
		if srv == nil {
			return ""
		}
		users, _ := srv["users"].([]any)
		if len(users) == 0 {
			return ""
		}
		u, _ := users[0].(map[string]any)
		uuid := strMap(u, "id")
		if uuid == "" {
			return ""
		}
		if v := strMap(u, "flow"); v != "" {
			q.Set("flow", v)
		}
		return fmt.Sprintf("vless://%s@%s:%s?%s#%s", uuid, strMap(srv, "address"), strMap(srv, "port"), q.Encode(), frag(tag))
	case "vmess":
		srv := firstServer(m, "vnext")
		if srv == nil {
			return ""
		}
		users, _ := srv["users"].([]any)
		if len(users) == 0 {
			return ""
		}
		u, _ := users[0].(map[string]any)
		uuid := strMap(u, "id")
		if uuid == "" {
			return ""
		}
		return fmt.Sprintf("vmess://%s@%s:%s?%s#%s", uuid, strMap(srv, "address"), strMap(srv, "port"), q.Encode(), frag(tag))
	case "shadowsocks":
		srv := firstServer(m, "servers")
		if srv == nil {
			return ""
		}
		method := strMap(srv, "method")
		password := strMap(srv, "password")
		if method == "" || password == "" {
			return ""
		}
		return fmt.Sprintf("ss://%s@%s:%s#%s", b64std(method+":"+password), strMap(srv, "address"), strMap(srv, "port"), frag(tag))
	case "trojan":
		srv := firstServer(m, "servers")
		if srv == nil {
			return ""
		}
		pw := strMap(srv, "password")
		if pw == "" {
			return ""
		}
		return fmt.Sprintf("trojan://%s@%s:%s?%s#%s", qesc(pw), strMap(srv, "address"), strMap(srv, "port"), q.Encode(), frag(tag))
	case "socks":
		srv := firstServer(m, "servers")
		if srv == nil {
			return ""
		}
		auth := ""
		if users, ok := srv["users"].([]any); ok && len(users) > 0 {
			if um, ok := users[0].(map[string]any); ok {
				auth = qesc(strMap(um, "user")) + ":" + qesc(strMap(um, "pass", "password")) + "@"
			}
		}
		return fmt.Sprintf("socks5://%s%s:%s#%s", auth, strMap(srv, "address"), strMap(srv, "port"), frag(tag))
	case "http":
		srv := firstServer(m, "servers")
		if srv == nil {
			return ""
		}
		auth := ""
		if users, ok := srv["users"].([]any); ok && len(users) > 0 {
			if um, ok := users[0].(map[string]any); ok {
				auth = qesc(strMap(um, "user")) + ":" + qesc(strMap(um, "pass", "password")) + "@"
			}
		}
		return fmt.Sprintf("http://%s%s:%s#%s", auth, strMap(srv, "address"), strMap(srv, "port"), frag(tag))
	}
	return ""
}

func b64std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
