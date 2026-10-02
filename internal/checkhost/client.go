package checkhost

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const base = "https://check-host.net"

// Node describes a checking node from check-host.
type Node struct {
	Code    string `json:"code"`
	Country string `json:"country"`
	Name    string `json:"name"`
	City    string `json:"city"`
	IP      string `json:"ip"`
	ASN     string `json:"asn"`
}

type startResp struct {
	OK            int                            `json:"ok"`
	RequestID     string                         `json:"request_id"`
	PermanentLink string                         `json:"permanent_link"`
	Nodes         map[string][]json.RawMessage    `json:"nodes"`
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func getJSON(url string, v any) error {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("check-host HTTP %d: %s", resp.StatusCode, string(body)[:min(200, len(body))])
	}
	return json.Unmarshal(body, v)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Nodes возвращает все ноды check-host (кэш час).
var (
	nodesMu    sync.Mutex
	nodesCache map[string]Node
	nodesAt    time.Time
)

func Nodes() map[string]Node {
	nodesMu.Lock()
	defer nodesMu.Unlock()
	if time.Since(nodesAt) < time.Hour && len(nodesCache) > 0 {
		return nodesCache
	}
	var v struct {
		Nodes map[string]struct {
			ASN      string   `json:"asn"`
			IP       string   `json:"ip"`
			Location []string `json:"location"`
		} `json:"nodes"`
	}
	out := map[string]Node{}
	if err := getJSON(base+"/nodes/hosts", &v); err == nil {
		for id, n := range v.Nodes {
			cc, country, city := "", "", ""
			if len(n.Location) > 0 {
				cc = n.Location[0]
			}
			if len(n.Location) > 1 {
				country = n.Location[1]
			}
			if len(n.Location) > 2 {
				city = n.Location[2]
			}
			out[id] = Node{Code: strings.ToLower(cc), Country: country, Name: id, City: city, IP: n.IP, ASN: n.ASN}
		}
		nodesCache = out
		nodesAt = time.Now()
	}
	return out
}

// RUNodes возвращает IDs нод в России.
func RUNodes() []string {
	var out []string
	for id, n := range Nodes() {
		if n.Code == "ru" {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Start launches one check (ping|http|tcp|dns|udp) and returns request id + nodes.
// nodes — конкретные ноды (&node=...), пусто = на выбор сервиса.
func Start(checkType, host string, maxNodes int, pick []string) (requestID, link string, infos map[string]Node, err error) {
	if maxNodes <= 0 || maxNodes > 5 {
		maxNodes = 3
	}
	u := fmt.Sprintf("%s/check-%s?host=%s&max_nodes=%d", base, url.PathEscape(checkType), url.QueryEscape(host), maxNodes)
	for _, n := range pick {
		u += "&node=" + url.QueryEscape(n)
	}
	var sr startResp
	if err := getJSON(u, &sr); err != nil {
		return "", "", nil, err
	}
	if sr.OK != 1 || sr.RequestID == "" {
		return "", "", nil, fmt.Errorf("check-host не принял %s-проверку", checkType)
	}
	nodes := map[string]Node{}
	for id, arr := range sr.Nodes {
		var cc, country, city, ip, asn string
		parts := []string{}
		for _, r := range arr {
			var s string
			_ = json.Unmarshal(r, &s)
			parts = append(parts, s)
		}
		if len(parts) > 0 {
			cc = parts[0]
		}
		if len(parts) > 1 {
			country = parts[1]
		}
		if len(parts) > 2 {
			city = parts[2]
		}
		if len(parts) > 3 {
			ip = parts[3]
		}
		if len(parts) > 4 {
			asn = parts[4]
		}
		nodes[id] = Node{Code: strings.ToLower(cc), Country: country, Name: id, City: city, IP: ip, ASN: asn}
	}
	return sr.RequestID, sr.PermanentLink, nodes, nil
}

// FetchResult polls one request id once. Returns raw per-node payloads (nil = ещё считается).
func FetchResult(requestID string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := getJSON(base+"/check-result/"+url.PathEscape(requestID), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// WaitResult polls until all nodes answered or timeout. Returns last snapshot.
func WaitResult(requestID string, timeout time.Duration) map[string]json.RawMessage {
	deadline := time.Now().Add(timeout)
	var last map[string]json.RawMessage
	for {
		m, err := FetchResult(requestID)
		if err == nil {
			last = m
			done := true
			for _, v := range m {
				if string(v) == "null" {
					done = false
					break
				}
			}
			if done {
				return m
			}
		}
		if time.Now().After(deadline) {
			return last
		}
		time.Sleep(3 * time.Second)
	}
}
