package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/yzewe/proxy-checker/internal/checker"
	"github.com/yzewe/proxy-checker/internal/checkhost"
	"github.com/yzewe/proxy-checker/internal/cores"
	"github.com/yzewe/proxy-checker/internal/daily"
	"github.com/yzewe/proxy-checker/internal/dnscomp"
	"github.com/yzewe/proxy-checker/internal/dnstest"
	"github.com/yzewe/proxy-checker/internal/geoip"
	"github.com/yzewe/proxy-checker/internal/gping"
	"github.com/yzewe/proxy-checker/internal/keyping"
	"github.com/yzewe/proxy-checker/internal/probe"
	"github.com/yzewe/proxy-checker/internal/revdns"
	"github.com/yzewe/proxy-checker/internal/rkn"
	"github.com/yzewe/proxy-checker/internal/trace"
	"github.com/yzewe/proxy-checker/internal/twoip"
)

type checkJob struct {
	job    *checker.Job
	cancel context.CancelFunc
}

type Server struct {
	mu   sync.Mutex
	jobs map[string]*checkJob
}

// qualitySem ограничивает одновременные speed/unlock/reputation:
// каждая проверка поднимает отдельное ядро.
var qualitySem = make(chan struct{}, 4)

func acquireQuality(w http.ResponseWriter) bool {
	select {
	case qualitySem <- struct{}{}:
		return true
	default:
		http.Error(w, "уже идут 4 проверки качества — подождите", http.StatusTooManyRequests)
		return false
	}
}

func releaseQuality() { <-qualitySem }

func New() *Server {
	s := &Server{jobs: map[string]*checkJob{}}
	go s.sweepLoop()
	return s
}

// sweepLoop чистит старые законченные задачи (иначе реестр растёт вечно).
func (s *Server) sweepLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-60 * time.Minute)
		s.mu.Lock()
		for id, e := range s.jobs {
			if e.job.IsFinished() && e.job.Started.Before(cutoff) {
				delete(s.jobs, id)
			}
		}
		// жёсткий кап: больше 50 задач не храним (самые старые законченные — вон)
		for len(s.jobs) > 50 {
			oldest := ""
			for id, e := range s.jobs {
				if !e.job.IsFinished() {
					continue
				}
				if oldest == "" || e.job.Started.Before(s.jobs[oldest].job.Started) {
					oldest = id
				}
			}
			if oldest == "" {
				break
			}
			delete(s.jobs, oldest)
		}
		s.mu.Unlock()
		checkhost.Sweep(60*time.Minute, 50)
		probe.Sweep(60*time.Minute, 50)
		gping.Sweep(60*time.Minute, 50)
		keyping.Sweep(60*time.Minute, 50)
		dnscomp.Sweep(60*time.Minute, 50)
		trace.Sweep(60*time.Minute, 50)
	}
}

func (s *Server) Router() *mux.Router {
	r := mux.NewRouter()
	a := r.PathPrefix("/api").Subrouter()
	a.HandleFunc("/check", s.handleStart).Methods("POST")
	a.HandleFunc("/jobs/{id}", s.handleJob).Methods("GET")
	a.HandleFunc("/jobs/{id}", s.handleDelete).Methods("DELETE")
	a.HandleFunc("/jobs/{id}/stream", s.handleStream).Methods("GET")
	a.HandleFunc("/cores", s.handleCores).Methods("GET")
	a.HandleFunc("/cores/check-updates", s.handleCheckUpdates).Methods("POST")
	a.HandleFunc("/cores/download", s.handleCoreDownload).Methods("POST")
	a.HandleFunc("/cores/update", s.handleCoreDownload).Methods("POST")
	a.HandleFunc("/cores/download-all", s.handleCoreDownloadAll).Methods("POST")
	a.HandleFunc("/cores/progress", s.handleCoresProgress).Methods("GET")
	a.HandleFunc("/parse", s.handleParse).Methods("POST")
	a.HandleFunc("/results", s.handleResultsList).Methods("GET")
	a.HandleFunc("/results/download", s.handleResultsDownload).Methods("GET")
	a.HandleFunc("/extcheck", s.handleExtStart).Methods("POST")
	a.HandleFunc("/extcheck/{id}", s.handleExtJob).Methods("GET")
	a.HandleFunc("/rkn", s.handleRkn).Methods("GET")
	a.HandleFunc("/probe", s.handleProbeStart).Methods("POST")
	a.HandleFunc("/probe/{id}", s.handleProbeJob).Methods("GET")
	a.HandleFunc("/daily", s.handleDailyStatus).Methods("GET")
	a.HandleFunc("/daily", s.handleDailySet).Methods("POST")
	a.HandleFunc("/daily/run", s.handleDailyRun).Methods("POST")
	a.HandleFunc("/exitip", s.handleExitIP).Methods("POST")
	a.HandleFunc("/speed", s.handleSpeed).Methods("POST")
	a.HandleFunc("/speed/servers", s.handleSpeedServers).Methods("GET")
	a.HandleFunc("/unlock", s.handleUnlock).Methods("POST")
	a.HandleFunc("/reputation", s.handleReputation).Methods("POST")
	a.HandleFunc("/settings", s.handleSettingsGet).Methods("GET")
	a.HandleFunc("/settings", s.handleSettingsSet).Methods("POST")
	a.HandleFunc("/twoip/abuse", s.handleTwoipAbuse).Methods("GET")
	a.HandleFunc("/twoip/domains", s.handleTwoipDomains).Methods("GET")
	a.HandleFunc("/twoip/whois", s.handleTwoipWhois).Methods("GET")
	a.HandleFunc("/twoip/asn", s.handleTwoipAsn).Methods("GET")
	a.HandleFunc("/revdns", s.handleRevDNS).Methods("GET")
	a.HandleFunc("/dnstest", s.handleDNSTest).Methods("POST")
	a.HandleFunc("/trace", s.handleTraceStart).Methods("POST")
	a.HandleFunc("/trace/{id}", s.handleTraceJob).Methods("GET")
	a.HandleFunc("/trace/{id}", s.handleTraceDelete).Methods("DELETE")
	a.HandleFunc("/geo/pool", s.handleGeoPool).Methods("GET")
	a.HandleFunc("/dnscomp", s.handleDNSComp).Methods("POST")
	a.HandleFunc("/dnscomp/resolvers", s.handleDNSResolvers).Methods("GET")
	a.HandleFunc("/dnscomp/resolvers", s.handleDNSResolverAdd).Methods("POST")
	a.HandleFunc("/dnscomp/resolvers/del", s.handleDNSResolverDel).Methods("POST")
	a.HandleFunc("/dnscomp/{id}", s.handleDNSCompJob).Methods("GET")
	a.HandleFunc("/gping", s.handleGPingStart).Methods("POST")
	a.HandleFunc("/gping/{id}", s.handleGPingJob).Methods("GET")
	a.HandleFunc("/keyping", s.handleKeyPingStart).Methods("POST")
	a.HandleFunc("/keyping/{id}", s.handleKeyPingJob).Methods("GET")
	return r
}

type startReq struct {
	Links   []string        `json:"links"`
	Text    string          `json:"text"`
	Options checker.Options `json:"options"`
}

func splitLinks(req startReq) []string {
	out := req.Links
	if req.Text != "" {
		for _, line := range splitLines(req.Text) {
			if line != "" {
				out = append(out, line)
			}
		}
	}
	// dedup preserve order
	seen := map[string]bool{}
	res := []string{}
	for _, l := range out {
		if !seen[l] {
			seen[l] = true
			res = append(res, l)
		}
	}
	return res
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	var req startReq
	if !decodeJSON(w, r, &req, 10<<20) {
		return
	}
	links := splitLinks(req)
	if len(links) == 0 {
		http.Error(w, "нет ссылок", 400)
		return
	}
	if len(links) > 5000 {
		http.Error(w, "слишком много (макс 5000)", 400)
		return
	}
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	job := checker.NewJob(id, links, req.Options)
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	// не больше 4 одновременных прогонов — каждый жрёт процессы/сокеты
	running := 0
	for _, e := range s.jobs {
		if !e.job.IsFinished() {
			running++
		}
	}
	if running >= 4 {
		s.mu.Unlock()
		cancel()
		http.Error(w, "уже идут 4 проверки — дождитесь конца", 429)
		return
	}
	s.jobs[id] = &checkJob{job: job, cancel: cancel}
	s.mu.Unlock()
	go job.Run(ctx)
	writeJSON(w, map[string]any{"id": id, "total": len(links)})
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.mu.Lock()
	e, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	j := e.job
	j2 := struct {
		ID      string              `json:"id"`
		Done    int                 `json:"done"`
		Total   int                 `json:"total"`
		Results []checker.Result    `json:"results"`
		Finish  bool                `json:"finished"`
		Saved   []checker.SavedFile `json:"saved,omitempty"`
	}{ID: j.ID, Done: jobDone(j), Total: j.Total, Results: jobResults(j), Finish: jobFinished(j), Saved: j.SavedFiles()}
	writeJSON(w, j2)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.mu.Lock()
	e, ok := s.jobs[id]
	if ok {
		e.cancel()
	}
	delete(s.jobs, id)
	s.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.mu.Lock()
	e, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	j := e.job
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no sse", 500)
		return
	}
	// first send existing, помня max index — дальше только новее (без дублей)
	maxIdx := -1
	for _, res := range jobResults(j) {
		fmt.Fprintf(w, "data: %s\n\n", mustJSON(res))
		if res.Index > maxIdx {
			maxIdx = res.Index
		}
	}
	fl.Flush()
loop:
	for {
		select {
		case <-r.Context().Done():
			break loop
		case res, ok := <-j.Updates():
			if !ok {
				break loop
			}
			if res.Index <= maxIdx {
				continue
			}
			maxIdx = res.Index
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(res))
			fl.Flush()
		}
	}
	fmt.Fprintf(w, "event: done\ndata: done\n\n")
	fl.Flush()
}

func (s *Server) handleCores(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, cores.Status())
}

func (s *Server) handleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	infos := cores.Status()
	// live check tags
	for i, c := range infos {
		if c.ID == "direct" || c.ID == "builtin" {
			continue
		}
		if tag, err := cores.CheckLatest(c.ID); err == nil && tag != "" {
			infos[i].Latest = tag
			infos[i].UpdateAvail = c.Installed && c.Version != "" && c.Version != tag
		}
	}
	writeJSON(w, infos)
}

var allowedCores = map[cores.CoreID]bool{
	cores.CoreSingBox: true, cores.CoreMihomo: true, cores.CoreXray: true,
	cores.CoreMtproto: true, cores.CoreJuicity: true, cores.CoreMieru: true,
}

func validVersion(v string) bool {
	if v == "" || len(v) > 40 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == 'v') {
			return false
		}
	}
	return true
}

func (s *Server) handleCoreDownload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	id := cores.CoreID(req.ID)
	if !allowedCores[id] {
		http.Error(w, "неизвестное ядро", 400)
		return
	}
	if req.Version != "" && !validVersion(req.Version) {
		http.Error(w, "кривая версия", 400)
		return
	}
	// keep old route working
	ver, err := cores.StartDownload(id, req.Version)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "version": ver, "message": "скачивание запущено"})
}

func (s *Server) handleCoreDownloadAll(w http.ResponseWriter, r *http.Request) {
	started := []string{}
	for _, c := range cores.Status() {
		if c.ID == cores.CoreDirect {
			continue
		}
		// качаем отсутствующие + те, где есть обновление
		if !c.Installed || c.UpdateAvail || c.Version == "" {
			if _, err := cores.StartDownload(c.ID, c.Latest); err == nil {
				started = append(started, string(c.ID))
			}
		}
	}
	writeJSON(w, map[string]any{"ok": true, "started": started})
}

func (s *Server) handleCoresProgress(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, cores.GetAllProgress())
}

func (s *Server) handleResultsList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, checker.ListSaved(50))
}

func (s *Server) handleResultsDownload(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("file")
	if rel == "" {
		http.Error(w, "нужен ?file=", 400)
		return
	}
	// защита от traversal: только внутри ResultsDir, только наши расширения
	clean := filepath.Clean(rel)
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		http.Error(w, "bad path", 400)
		return
	}
	ext := strings.ToLower(filepath.Ext(clean))
	if ext != ".json" && ext != ".txt" && ext != ".csv" {
		http.Error(w, "только .json/.txt/.csv", 400)
		return
	}
	root := filepath.Clean(checker.ResultsDir())
	full := filepath.Join(root, clean)
	if filepath.Clean(full) != full || !strings.HasPrefix(full, root+string(filepath.Separator)) {
		http.Error(w, "bad path", 400)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, full)
}

func (s *Server) handleParse(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	type item struct {
		Link     string `json:"link"`
		Protocol string `json:"protocol"`
		Host     string `json:"host"`
	}
	out := []item{}
	for _, line := range splitLines(req.Text) {
		h, p := checker.ParseHostPort(line)
		host := h
		if p != "" {
			host += ":" + p
		}
		out = append(out, item{Link: line, Protocol: checker.DetectProtocol(line), Host: host})
	}
	writeJSON(w, out)
}

func (s *Server) handleExtStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host   string   `json:"host"`
		Types  []string `json:"types"`
		OnlyRU bool     `json:"onlyRU"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		http.Error(w, "нужен host (host:port сервера)", 400)
		return
	}
	// валидные типы, остальное режем
	allowed := map[string]bool{"ping": true, "tcp": true, "udp": true, "dns": true, "http": true}
	types := []string{}
	for _, t := range req.Types {
		if allowed[strings.ToLower(t)] {
			types = append(types, strings.ToLower(t))
		}
	}
	id := fmt.Sprintf("ext%d", time.Now().UnixNano())
	j := checkhost.StartJob(id, host, types, req.OnlyRU)
	writeJSON(w, map[string]any{"id": j.ID, "host": j.Host, "onlyRU": req.OnlyRU})
}

func (s *Server) handleProbeStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		http.Error(w, "нужен target (домен или IP)", 400)
		return
	}
	// IP тоже умеем: там вердикты ok/tspu_block/uncertain по traceroute
	if strings.Contains(target, "://") {
		http.Error(w, "нужен голый домен или IP, без схемы", 400)
		return
	}
	id := fmt.Sprintf("probe%d", time.Now().UnixNano())
	j := probe.StartJob(id, target)
	writeJSON(w, map[string]any{"target": j.Target, "job": id})
}

func (s *Server) handleProbeJob(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	j, ok := probe.GetJob(id)
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	snap := j.Snapshot()
	writeJSON(w, snap)
}

func (s *Server) handleDailyStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, daily.Status())
}

func (s *Server) handleDailySet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	writeJSON(w, daily.SetEnabled(req.Enabled))
}

func (s *Server) handleDailyRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Limit int `json:"limit"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	if req.Limit <= 0 || req.Limit > 3000 {
		req.Limit = 1000
	}
	daily.RunNow(req.Limit)
	writeJSON(w, map[string]any{"ok": true, "limit": req.Limit})
}

func (s *Server) handleExitIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Link       string `json:"link"`
		TimeoutSec int    `json:"timeoutSec"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	if req.Link == "" {
		http.Error(w, "нужен link", 400)
		return
	}
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout+20*time.Second)
	defer cancel()
	writeJSON(w, checker.ExitIP(ctx, req.Link, timeout))
}

func (s *Server) handleSpeed(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Link      string `json:"link"`
		Server    string `json:"server"`
		DownBytes int64  `json:"downBytes"`
		UpBytes   int64  `json:"upBytes"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	if !acquireQuality(w) {
		return
	}
	defer releaseQuality()
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	writeJSON(w, checker.SpeedTest(ctx, req.Link, req.Server, req.DownBytes, req.UpBytes))
}

func (s *Server) handleSpeedServers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, checker.SpeedServers())
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Link       string `json:"link"`
		TimeoutSec int    `json:"timeoutSec"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	if !acquireQuality(w) {
		return
	}
	defer releaseQuality()
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > 20*time.Second {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout+30*time.Second)
	defer cancel()
	writeJSON(w, checker.UnlockTest(ctx, req.Link, timeout))
}

func (s *Server) handleReputation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Link       string `json:"link"`
		TimeoutSec int    `json:"timeoutSec"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	if !acquireQuality(w) {
		return
	}
	defer releaseQuality()
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout+40*time.Second)
	defer cancel()
	writeJSON(w, checker.Reputation(ctx, req.Link, timeout))
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	s2 := twoip.LoadSettings()
	writeJSON(w, map[string]any{"twoipToken": maskToken(s2.TwoIPToken), "hasToken": s2.TwoIPToken != "", "abuseAuto": s2.AbuseAuto})
}

func maskToken(t string) string {
	if len(t) <= 4 {
		return t
	}
	return t[:2] + "…" + t[len(t)-2:]
}

func (s *Server) handleSettingsSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TwoIPToken *string `json:"twoipToken"`
		AbuseAuto  *bool   `json:"abuseAuto"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	s2 := twoip.LoadSettings()
	if req.TwoIPToken != nil {
		s2.TwoIPToken = strings.TrimSpace(*req.TwoIPToken)
	}
	if req.AbuseAuto != nil {
		s2.AbuseAuto = *req.AbuseAuto
	}
	twoip.SaveSettings(s2)
	s.handleSettingsGet(w, r)
}

func (s *Server) handleTwoipAbuse(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimSpace(r.URL.Query().Get("target"))
	if t == "" {
		http.Error(w, "нужен ?target=", 400)
		return
	}
	res, err := twoip.Abuse(t)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleTwoipDomains(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimSpace(r.URL.Query().Get("target"))
	if t == "" {
		http.Error(w, "нужен ?target=", 400)
		return
	}
	list, cached, err := twoip.Domains(t)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writeJSON(w, map[string]any{"domains": list, "count": len(list), "cached": cached})
}

func (s *Server) handleTwoipWhois(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimSpace(r.URL.Query().Get("target"))
	if t == "" {
		http.Error(w, "нужен ?target=", 400)
		return
	}
	v, cached, err := twoip.Whois(t)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writeJSON(w, map[string]any{"whois": v, "cached": cached})
}

func (s *Server) handleTwoipAsn(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimSpace(r.URL.Query().Get("id"))
	if t == "" {
		http.Error(w, "нужен ?id=", 400)
		return
	}
	v, cached, err := twoip.Asn(t)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writeJSON(w, map[string]any{"asn": v, "cached": cached})
}

func (s *Server) handleRevDNS(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimSpace(r.URL.Query().Get("ip"))
	if t == "" {
		http.Error(w, "нужен ?ip=", 400)
		return
	}
	// принимают и host:port — порт отрезаем
	if strings.Count(t, ":") == 1 {
		if h, _, ok := strings.Cut(t, ":"); ok {
			t = strings.TrimSpace(h)
		}
	}
	res, err := revdns.Lookup(t)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleDNSTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	t := strings.TrimSpace(req.Host)
	if t == "" {
		http.Error(w, "нужен host", 400)
		return
	}
	writeJSON(w, dnstest.Test(t))
}

func (s *Server) handleTraceStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target  string `json:"target"`
		MaxHops int    `json:"maxHops"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	t := strings.TrimSpace(req.Target)
	if t == "" {
		http.Error(w, "нужен target (домен или IP)", 400)
		return
	}
	// из ссылки вытащить хост
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Host != "" {
			t = u.Hostname()
		}
	}
	if t == "" {
		http.Error(w, "пустой хост", 400)
		return
	}
	id := fmt.Sprintf("tr%d", time.Now().UnixNano())
	j := trace.StartJob(id, t, req.MaxHops)
	writeJSON(w, map[string]any{"id": j.ID, "target": j.Target})
}

func (s *Server) handleTraceJob(w http.ResponseWriter, r *http.Request) {
	j, ok := trace.GetJob(mux.Vars(r)["id"])
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	hops, done, fin, errStr, verdict := j.Pub()
	writeJSON(w, map[string]any{
		"id": j.ID, "target": j.Target, "done": done, "finished": fin,
		"hops": hops, "error": errStr, "verdict": verdict,
	})
}

func (s *Server) handleTraceDelete(w http.ResponseWriter, r *http.Request) {
	if !trace.Cancel(mux.Vars(r)["id"]) {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleGeoPool(w http.ResponseWriter, r *http.Request) {
	n, via := geoip.PoolInfo()
	writeJSON(w, map[string]any{"socks": n, "via": via})
}

func (s *Server) handleDNSComp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string   `json:"target"`
		IDs    []string `json:"ids"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	t := strings.TrimSpace(req.Target)
	if t == "" {
		http.Error(w, "нужен target (домен)", 400)
		return
	}
	// если дали ссылку/host:port — вытащить хост
	if i := strings.LastIndex(t, ":"); i > 0 && !strings.Contains(t, "://") && strings.Count(t, ":") == 1 {
		t = t[:i]
	}
	j := dnscomp.StartJob(t, req.IDs, 6*time.Second)
	writeJSON(w, map[string]any{"id": j.ID})
}

func (s *Server) handleDNSCompJob(w http.ResponseWriter, r *http.Request) {
	j, ok := dnscomp.GetJob(mux.Vars(r)["id"])
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	done, total, fin := j.Progress()
	snap := j.Snapshot()
	writeJSON(w, map[string]any{
		"id": mux.Vars(r)["id"], "done": done, "total": total, "finished": fin,
		"baseline": snap.Baseline, "rows": snap.Rows,
	})
}

func (s *Server) handleDNSResolvers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, dnscomp.List())
}

func (s *Server) handleDNSResolverAdd(w http.ResponseWriter, r *http.Request) {
	var v dnscomp.Resolver
	if !decodeJSON(w, r, &v, 1<<20) {
		return
	}
	list, err := dnscomp.Add(v)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, list)
}

func (s *Server) handleDNSResolverDel(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &v, 1<<20) {
		return
	}
	writeJSON(w, dnscomp.Remove(strings.TrimSpace(v.ID)))
}

func (s *Server) handleGPingStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target  string `json:"target"`
		Country string `json:"country"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	t := strings.TrimSpace(req.Target)
	if i := strings.LastIndex(t, ":"); i > 0 && !strings.Contains(t, "://") && strings.Count(t, ":") == 1 {
		t = t[:i]
	}
	if t == "" {
		http.Error(w, "нужен target", 400)
		return
	}
	id := fmt.Sprintf("gp%d", time.Now().UnixNano())
	country := strings.ToUpper(strings.TrimSpace(req.Country))
	if len(country) != 0 && len(country) != 2 {
		country = ""
	}
	gping.StartJob(id, t, country)
	writeJSON(w, map[string]any{"id": id})
}

func (s *Server) handleGPingJob(w http.ResponseWriter, r *http.Request) {
	j, ok := gping.GetJob(mux.Vars(r)["id"])
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, j)
}

func (s *Server) handleKeyPingStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
	}
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	t := strings.TrimSpace(req.Target)
	if i := strings.LastIndex(t, ":"); i > 0 && !strings.Contains(t, "://") && strings.Count(t, ":") == 1 {
		t = t[:i]
	}
	if t == "" {
		http.Error(w, "нужен target", 400)
		return
	}
	id := fmt.Sprintf("kp%d", time.Now().UnixNano())
	keyping.StartJob(id, t)
	writeJSON(w, map[string]any{"id": id})
}

func (s *Server) handleKeyPingJob(w http.ResponseWriter, r *http.Request) {
	j, ok := keyping.GetJob(mux.Vars(r)["id"])
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, j)
}

func (s *Server) handleRkn(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	// принимают и host:port — порт отрезаем, РКН смотрит на домен/IP
	if h, _, ok := strings.Cut(target, ":"); ok && !strings.Contains(h, "://") {
		// осторожно с IPv6 — там двоеточий много
		if strings.Count(target, ":") == 1 {
			target = strings.TrimSpace(h)
		}
	}
	if target == "" {
		http.Error(w, "нужен ?target=домен-или-IP", 400)
		return
	}
	res, err := rkn.Check(target)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleExtJob(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	j, ok := checkhost.GetJob(id)
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, map[string]any{
		"id": id, "host": j.Host, "done": j.DonePub(), "checks": j.ChecksPub(),
	})
}
