package dnstest

// DNS-тест хоста: шлём DNS-запрос (A google.com) НА САМ АДРЕС разными
// транспортами — UDP/53, TCP/53, DoT/853 — и смотрим, резолвит ли.
// Отвечает: время, ответы, rcode. Молчит/REFUSED — так и пишем.

import (
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type One struct {
	OK      bool     `json:"ok"`
	Ms      int64    `json:"ms"`
	Answers []string `json:"answers,omitempty"`
	Rcode   string   `json:"rcode,omitempty"`
	Error   string   `json:"error,omitempty"`
}

type Result struct {
	Target string `json:"target"`
	UDP    One    `json:"udp"`
	TCP    One    `json:"tcp"`
	DoT    One    `json:"dot"`
}

const qname = "google.com."

func Test(hostport string) Result {
	host := hostport
	if i := strings.LastIndex(hostport, ":"); i > 0 && strings.Count(hostport, ":") == 1 {
		host = hostport[:i]
	}
	res := Result{Target: host}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); res.UDP = query(host, "udp", 5*time.Second) }()
	go func() { defer wg.Done(); res.TCP = query(host, "tcp", 5*time.Second) }()
	go func() { defer wg.Done(); res.DoT = queryDoT(host, 7*time.Second) }()
	wg.Wait()
	return res
}

func query(host, network string, timeout time.Duration) One {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)
	c := new(dns.Client)
	c.Net = network
	c.Timeout = timeout
	start := time.Now()
	r, _, err := c.Exchange(m, net.JoinHostPort(host, "53"))
	if err != nil {
		return One{Error: shortErr(err)}
	}
	return fill(r, time.Since(start))
}

func queryDoT(host string, timeout time.Duration) One {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)
	c := new(dns.Client)
	c.Net = "tcp-tls"
	c.Timeout = timeout
	c.TLSConfig = &tls.Config{ServerName: host, InsecureSkipVerify: true}
	start := time.Now()
	r, _, err := c.Exchange(m, net.JoinHostPort(host, "853"))
	if err != nil {
		return One{Error: shortErr(err)}
	}
	return fill(r, time.Since(start))
}

func fill(r *dns.Msg, d time.Duration) One {
	o := One{OK: true, Ms: d.Milliseconds(), Rcode: dns.RcodeToString[r.Rcode]}
	for _, a := range r.Answer {
		switch v := a.(type) {
		case *dns.A:
			o.Answers = append(o.Answers, v.A.String())
		case *dns.AAAA:
			o.Answers = append(o.Answers, v.AAAA.String())
		case *dns.CNAME:
			o.Answers = append(o.Answers, "CNAME "+v.Target)
		}
		if len(o.Answers) >= 4 {
			break
		}
	}
	if r.Rcode != dns.RcodeSuccess {
		o.OK = false
		o.Error = "rcode " + o.Rcode
	}
	return o
}

func shortErr(err error) string {
	s := err.Error()
	if strings.Contains(s, "i/o timeout") {
		return "таймаут (не отвечает)"
	}
	if strings.Contains(s, "connection refused") {
		return "порт закрыт"
	}
	if strings.Contains(s, "no route") || strings.Contains(s, "unreachable") {
		return "недоступен"
	}
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
