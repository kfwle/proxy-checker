package trace

// Фолбэк: системные tracepath / traceroute / tracert.
// Форматы разные — парсим все три, на выходе те же Hop.

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func sysTrace(ctx context.Context, target string, maxHops int, onHop func(Hop)) ([]Hop, error) {
	switch runtime.GOOS {
	case "windows":
		return tracert(ctx, target, maxHops, onHop)
	default:
		if _, err := exec.LookPath("traceroute"); err == nil {
			return unixTraceroute(ctx, target, maxHops, onHop)
		}
		if _, err := exec.LookPath("tracepath"); err == nil {
			return tracepath(ctx, target, maxHops, onHop)
		}
		return nil, fmt.Errorf("нет ни прав на raw-сокеты, ни traceroute/tracepath в системе")
	}
}

var (
	reHopStart = regexp.MustCompile(`^\s*(\d+)\s+`)
	reIP       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reMs       = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*ms`)
)

// unixTraceroute: traceroute -n -w2 -q3 -mN. Строки парсим по мере
// поступления (живая таблица как в терминале), а не в конце.
func unixTraceroute(ctx context.Context, target string, maxHops int, onHop func(Hop)) ([]Hop, error) {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(maxHops)*7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "traceroute", "-n", "-w", "2", "-q", "3", "-m", fmt.Sprintf("%d", maxHops), target)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("traceroute: %v", shortSysErr(err))
	}
	var hops []Hop
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		h, ok := parseTracerouteLine(sc.Text())
		if !ok {
			continue
		}
		hops = append(hops, h)
		if onHop != nil {
			onHop(h)
		}
	}
	_ = cmd.Wait()
	if len(hops) == 0 {
		return hops, fmt.Errorf("traceroute ничего не вывел")
	}
	return hops, nil
}

func parseTracerouteLine(line string) (Hop, bool) {
	m := reHopStart.FindStringSubmatch(line)
	if m == nil {
		return Hop{}, false
	}
	ttl, _ := strconv.Atoi(m[1])
	rest := line[len(m[0]):]
	var probes []Probe
	if strings.Contains(rest, "*") && reIP.FindString(rest) == "" {
		for len(probes) < 3 {
			probes = append(probes, Probe{})
		}
	} else {
		ips := reIP.FindAllString(rest, -1)
		mss := reMs.FindAllStringSubmatch(rest, -1)
		ip := ""
		if len(ips) > 0 {
			ip = ips[0]
		}
		for i := 0; i < 3; i++ {
			if i < len(mss) {
				ms, _ := strconv.ParseFloat(mss[i][1], 64)
				probes = append(probes, Probe{IP: ip, Ms: ms})
			} else {
				probes = append(probes, Probe{})
			}
		}
		if ip == "" {
			probes = []Probe{{}, {}, {}}
		}
	}
	return Hop{TTL: ttl, Probes: probes}, true
}

// tracepath: строки " 1?: [LOCALHOST] ...", " 1:  router  1.2ms".
func tracepath(ctx context.Context, target string, maxHops int, onHop func(Hop)) ([]Hop, error) {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(maxHops)*4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "tracepath", "-n", target)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tracepath: %v", shortSysErr(err))
	}
	byTTL := map[int][]Probe{}
	order := []int{}
	flush := func() {}
	_ = flush
	sc := bufio.NewScanner(pipe)
	for sc.Scan() {
		line := sc.Text()
		m := reHopStart.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ttl, _ := strconv.Atoi(m[1])
		if ttl > maxHops {
			continue
		}
		rest := line[len(m[0]):]
		if strings.HasPrefix(rest, "[LOCALHOST]") || strings.Contains(rest, "no reply") {
			byTTL[ttl] = append(byTTL[ttl], Probe{})
		} else {
			ip := reIP.FindString(rest)
			msm := reMs.FindStringSubmatch(rest)
			ms := 0.0
			if msm != nil {
				ms, _ = strconv.ParseFloat(msm[1], 64)
			}
			if ip == "" {
				byTTL[ttl] = append(byTTL[ttl], Probe{})
			} else {
				byTTL[ttl] = append(byTTL[ttl], Probe{IP: ip, Ms: ms})
			}
		}
		if len(order) == 0 || order[len(order)-1] != ttl {
			order = append(order, ttl)
		}
	}
	var hops []Hop
	for _, ttl := range order {
		ps := byTTL[ttl]
		for len(ps) < 1 {
			ps = append(ps, Probe{})
		}
		h := Hop{TTL: ttl, Probes: ps}
		hops = append(hops, h)
		if onHop != nil {
			onHop(h)
		}
	}
	_ = cmd.Wait()
	if len(hops) == 0 {
		return hops, fmt.Errorf("tracepath ничего не вывел")
	}
	return hops, nil
}

// tracert (Windows): "  1    <1 ms    <1 ms    <1 ms  10.0.0.1", таймауты — "* ... Request timed out."
func tracert(ctx context.Context, target string, maxHops int, onHop func(Hop)) ([]Hop, error) {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(maxHops)*5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "tracert", "-d", "-w", "2000", "-h", fmt.Sprintf("%d", maxHops), target)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tracert: %v", shortSysErr(err))
	}
	var hops []Hop
	sc := bufio.NewScanner(pipe)
	for sc.Scan() {
		line := sc.Text()
		m := reHopStart.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ttl, _ := strconv.Atoi(m[1])
		rest := line[len(m[0]):]
		if strings.Count(rest, "*") >= 3 || strings.Contains(rest, "timed out") {
			h := Hop{TTL: ttl, Probes: []Probe{{}, {}, {}}}
			hops = append(hops, h)
			if onHop != nil {
				onHop(h)
			}
			continue
		}
		ip := reIP.FindString(rest)
		mss := regexp.MustCompile(`<?\s*(\d+)\s*ms`).FindAllStringSubmatch(rest, -1)
		var probes []Probe
		for i := 0; i < 3; i++ {
			if i < len(mss) {
				ms, _ := strconv.ParseFloat(mss[i][1], 64)
				if strings.Contains(mss[i][0], "<") && ms < 1 {
					ms = 0.5
				}
				probes = append(probes, Probe{IP: ip, Ms: ms})
			} else {
				probes = append(probes, Probe{})
			}
		}
		if ip == "" {
			probes = []Probe{{}, {}, {}}
		}
		h := Hop{TTL: ttl, Probes: probes}
		hops = append(hops, h)
		if onHop != nil {
			onHop(h)
		}
	}
	_ = cmd.Wait()
	if len(hops) == 0 {
		return hops, fmt.Errorf("tracert ничего не вывел")
	}
	return hops, nil
}

func shortSysErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 150 {
		return s[:150] + "…"
	}
	return s
}
