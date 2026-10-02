package daily

// Сохранение ежедневного прогона: results/daily/YYYY-MM-DD/
// alive_all.txt + <CC>.txt по странам + summary.json.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yzewe/proxy-checker/internal/geoip"
	"github.com/yzewe/proxy-checker/internal/twoip"
)

func resultsRoot() string {
	if v := os.Getenv("CHECKER_RESULTS_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "results")
	}
	return "results"
}

type summary struct {
	Date    string         `json:"date"`
	Checked int            `json:"checked"`
	Alive   int            `json:"alive"`
	ByCC    map[string]int `json:"byCountry"`
}

// autoAbuse тянет abuse для новых живых IP если есть токен и включено.
func autoAbuse(ips []string) {
	s := twoip.LoadSettings()
	if s.TwoIPToken == "" || !s.AbuseAuto {
		return
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] || ip == "" {
			continue
		}
		seen[ip] = true
		_, _ = twoip.Abuse(ip) // ошибки (квота/лимит) — молча, это фон
	}
}

func saveDaily(alive []aliveRes) {
	if len(alive) == 0 {
		return
	}
	day := time.Now().Format("2006-01-02")
	dir := filepath.Join(resultsRoot(), "daily", day)
	_ = os.MkdirAll(dir, 0o755)

	ips := make([]string, 0, len(alive))
	for _, a := range alive {
		ips = append(ips, a.ip)
	}
	infos := geoip.LookupMany(ips)
	// авто-abuse новых живых IP (только с токеном, по 1 запросу на IP, дальше кэш 7 дней)
	autoAbuse(ips)

	byCC := map[string][]string{}
	all := []string{}
	for _, a := range alive {
		cc := infos[a.ip].Code
		if cc == "" || infos[a.ip].Unknown {
			cc = "XX"
		}
		byCC[cc] = append(byCC[cc], a.link)
		all = append(all, a.link)
	}
	sort.Strings(all)
	_ = os.WriteFile(filepath.Join(dir, "alive_all.txt"), []byte(strings.Join(all, "\n")+"\n"), 0o644)
	counts := map[string]int{}
	for cc, links := range byCC {
		sort.Strings(links)
		_ = os.WriteFile(filepath.Join(dir, cc+".txt"), []byte(strings.Join(links, "\n")+"\n"), 0o644)
		counts[cc] = len(links)
	}
	sum := summary{Date: day, Alive: len(alive), ByCC: counts}
	// checked допишем из state при чтении — тут только alive
	b, _ := json.MarshalIndent(sum, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("summary_%s.json", time.Now().Format("15-04-05"))), b, 0o644)
}
