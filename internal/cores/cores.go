// Package cores управляет внешними ядрами чекера (sing-box, xray, mihomo,
// mtproto-checker, juicity-client, mieru): определяет установленные бинарники,
// проверяет последние релизы на GitHub, скачивает/распаковывает и ведёт прогресс.
package cores

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CoreID — идентификатор ядра (совпадает с id в UI).
type CoreID string

const (
	CoreSingBox CoreID = "sing-box"
	CoreXray    CoreID = "xray"
	CoreMihomo  CoreID = "mihomo"
	CoreMtproto CoreID = "mtproto-checker"
	CoreJuicity CoreID = "juicity-client"
	CoreMieru   CoreID = "mieru"
	CoreDirect  CoreID = "direct"
	CoreBuiltin CoreID = "builtin"
)

// Info — карточка ядра для GET /api/cores.
type Info struct {
	ID          CoreID   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Binary      string   `json:"binary"`
	Installed   bool     `json:"installed"`
	Version     string   `json:"version,omitempty"`
	Latest      string   `json:"latest,omitempty"`
	UpdateAvail bool     `json:"updateAvailable"`
	Supports    []string `json:"supports"`
	DownloadURL string   `json:"downloadUrl,omitempty"`
}

// Progress — состояние скачивания ядра для GET /api/cores/progress.
type Progress struct {
	State   string `json:"state"` // downloading | extracting | installing | done | error
	Percent int    `json:"percent,omitempty"`
	Stage   string `json:"stage,omitempty"`
	Error   string `json:"error,omitempty"`
	Version string `json:"version,omitempty"`
}

type spec struct {
	id         CoreID
	name       string
	desc       string
	binary     string // базовое имя без .exe
	supports   []string
	repo       string // owner/name для GitHub Releases
	goModule   string // для ядер без релизов (go install)
	versionCmd []string
}

var specs = map[CoreID]*spec{
	CoreSingBox: {
		id: CoreSingBox, name: "sing-box", desc: "основное ядро: vless/vmess/ss/trojan/hysteria2/tuic/anytls/naive",
		binary: "sing-box", repo: "SagerNet/sing-box",
		supports:   []string{"vless", "vmess", "ss", "trojan", "hysteria2", "tuic", "anytls", "naive", "shadowtls", "socks", "http"},
		versionCmd: []string{"version"},
	},
	CoreXray: {
		id: CoreXray, name: "xray", desc: "фолбэк: vless (reality/grpc), vmess, ss, trojan",
		binary: "xray", repo: "XTLS/Xray-core",
		supports:   []string{"vless", "vmess", "ss", "trojan", "socks", "http"},
		versionCmd: []string{"version"},
	},
	CoreMihomo: {
		id: CoreMihomo, name: "mihomo", desc: "фолбэк: vless/vmess/ss/trojan, hysteria2, tuic, anytls",
		binary: "mihomo", repo: "MetaCubeX/mihomo",
		supports:   []string{"vless", "vmess", "ss", "trojan", "hysteria2", "tuic", "anytls", "socks", "http"},
		versionCmd: []string{"-v"},
	},
	CoreMtproto: {
		id: CoreMtproto, name: "mtproto-checker", desc: "родной чекер Telegram MTProto (ставится через go install)",
		binary: "mtproto-checker", goModule: "github.com/yzewe/mtproto-checker/cmd/mtproto-checker",
		supports:   []string{"mtproto"},
		versionCmd: []string{"--version"},
	},
	CoreJuicity: {
		id: CoreJuicity, name: "juicity-client", desc: "родной клиент juicity (sing-box/mihomo его не умеют)",
		binary: "juicity-client", repo: "juicity/juicity",
		supports:   []string{"juicity"},
		versionCmd: []string{"--version"},
	},
	CoreMieru: {
		id: CoreMieru, name: "mieru", desc: "родной клиент mieru",
		binary: "mieru", repo: "enfein/mieru",
		supports:   []string{"mieru"},
		versionCmd: []string{"version"},
	},
}

// Порядок карточек в UI.
var order = []CoreID{CoreSingBox, CoreXray, CoreMihomo, CoreMtproto, CoreJuicity, CoreMieru}

var (
	mu       sync.Mutex
	running  = map[CoreID]bool{}
	progress = map[CoreID]Progress{}
)

// CoresDir — папка с бинарниками ядер. Рядом с исполняемым файлом
// (./cores) либо $CHECKER_CORES_DIR.
func CoresDir() string {
	if d := os.Getenv("CHECKER_CORES_DIR"); d != "" {
		return d
	}
	exe, err := os.Executable()
	if err == nil {
		if real, err2 := filepath.EvalSymlinks(exe); err2 == nil {
			exe = real
		}
		return filepath.Join(filepath.Dir(exe), "cores")
	}
	return "cores"
}

func binFileName(id CoreID) string {
	s := specs[id]
	if s == nil {
		return string(id)
	}
	if runtime.GOOS == "windows" {
		return s.binary + ".exe"
	}
	return s.binary
}

func binPath(id CoreID) string {
	return filepath.Join(CoresDir(), binFileName(id))
}

// Status — локальное состояние ядер (без сети, latest берётся из кэша).
func Status() []Info {
	out := make([]Info, 0, len(order)+1)
	for _, id := range order {
		s := specs[id]
		info := Info{
			ID: id, Name: s.name, Description: s.desc, Binary: s.binary,
			Supports: append([]string(nil), s.supports...),
		}
		if st, err := os.Stat(binPath(id)); err == nil && !st.IsDir() {
			info.Installed = true
			info.Version = installedVersion(id, st)
		}
		info.Latest = cachedLatest(id)
		if id == CoreMtproto {
			if info.Installed && info.Latest == "" {
				info.Latest = "git-latest"
			}
			// git-latest переустанавливается в любой момент
			info.UpdateAvail = info.Installed && info.Latest != ""
		} else if info.Installed && info.Version != "" && info.Latest != "" {
			info.UpdateAvail = info.Version != info.Latest
		}
		info.DownloadURL = assetURL(id, info.Latest)
		out = append(out, info)
	}
	out = append(out, Info{
		ID: CoreDirect, Name: "direct (встроено)", Description: "встроенная проверка http/socks/tcp без внешних ядер",
		Binary: "—", Installed: true, Version: "встроено",
		Supports: []string{"http", "socks", "tcp"},
	})
	return out
}

// CheckLatest — последний релиз ядра на GitHub.
func CheckLatest(id CoreID) (string, error) {
	if id == CoreDirect || id == CoreBuiltin {
		return "", nil
	}
	s := specs[id]
	if s == nil {
		return "", fmt.Errorf("неизвестное ядро: %s", id)
	}
	if s.goModule != "" {
		return "git-latest", nil
	}
	if tag := freshLatest(id); tag != "" {
		return tag, nil
	}
	tag, err := fetchLatestTag(s.repo)
	if err != nil {
		// сеть недоступна — отдаём хоть что-то из кэша
		if tag := cachedLatest(id); tag != "" {
			return tag, nil
		}
		return "", err
	}
	storeLatest(id, tag)
	return tag, nil
}

const latestTTL = 6 * time.Hour

type latestEntry struct {
	Tag string    `json:"tag"`
	At  time.Time `json:"at"`
}

var (
	latestMu    sync.Mutex
	latestCache = map[CoreID]latestEntry{}
	latestFile  = func() string { return filepath.Join(CoresDir(), ".latest.json") }()
)

func loadLatestCache() {
	latestMu.Lock()
	defer latestMu.Unlock()
	if len(latestCache) > 0 {
		return
	}
	b, err := os.ReadFile(latestFile)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &latestCache)
}

func cachedLatest(id CoreID) string {
	loadLatestCache()
	latestMu.Lock()
	defer latestMu.Unlock()
	return latestCache[id].Tag
}

func freshLatest(id CoreID) string {
	loadLatestCache()
	latestMu.Lock()
	defer latestMu.Unlock()
	e, ok := latestCache[id]
	if !ok || e.Tag == "" || time.Since(e.At) > latestTTL {
		return ""
	}
	return e.Tag
}

func storeLatest(id CoreID, tag string) {
	loadLatestCache()
	latestMu.Lock()
	latestCache[id] = latestEntry{Tag: tag, At: time.Now()}
	b, _ := json.MarshalIndent(latestCache, "", "  ")
	latestMu.Unlock()
	_ = os.MkdirAll(CoresDir(), 0o755)
	_ = os.WriteFile(latestFile, b, 0o644)
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

func fetchLatestTag(repo string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "proxy-checker")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("github api %s: %s %s", repo, resp.Status, strings.TrimSpace(string(body)))
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("у %s нет релизов", repo)
	}
	return rel.TagName, nil
}

// версия ядра, сохранённая при установке (на случай если бинарник не отвечает)
var (
	verMu      sync.Mutex
	verCache   = map[CoreID]string{}
	verFile    = func() string { return filepath.Join(CoresDir(), ".versions.json") }()
	verCacheOK bool
)

func loadVersions() map[CoreID]string {
	verMu.Lock()
	defer verMu.Unlock()
	if verCacheOK {
		out := make(map[CoreID]string, len(verCache))
		for k, v := range verCache {
			out[k] = v
		}
		return out
	}
	m := map[CoreID]string{}
	if b, err := os.ReadFile(verFile); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	for k, v := range m {
		verCache[k] = v
	}
	verCacheOK = true
	out := make(map[CoreID]string, len(verCache))
	for k, v := range verCache {
		out[k] = v
	}
	return out
}

func saveVersion(id CoreID, v string) {
	verMu.Lock()
	// файл мог быть записан другим процессом — сливаем, а не затираем
	m := map[CoreID]string{}
	if b, err := os.ReadFile(verFile); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	for k, val := range verCache {
		m[k] = val
	}
	m[id] = v
	verCache = make(map[CoreID]string, len(m))
	for k, val := range m {
		verCache[k] = val
	}
	verCacheOK = true
	b, _ := json.MarshalIndent(verCache, "", "  ")
	verMu.Unlock()
	_ = os.MkdirAll(CoresDir(), 0o755)
	_ = os.WriteFile(verFile, b, 0o644)
}

// detectVersion запускает бинарник (sing-box version, mihomo -v, ...) и
// вытаскивает номер версии из вывода.
func detectVersion(id CoreID, bin string) string {
	s := specs[id]
	if s == nil || len(s.versionCmd) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, s.versionCmd...)
	out, _ := cmd.CombinedOutput()
	m := versionRe.FindSubmatch(out)
	if m == nil {
		return ""
	}
	v := string(m[0])
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?`)

// кэш версий по mtime/размеру: Status() не должен запускать все бинарники
// на каждый запрос /api/cores
type diskVer struct {
	mod  time.Time
	size int64
	ver  string
}

var (
	diskVerMu    sync.Mutex
	diskVerCache = map[CoreID]diskVer{}
)

func installedVersion(id CoreID, st os.FileInfo) string {
	diskVerMu.Lock()
	cached, ok := diskVerCache[id]
	diskVerMu.Unlock()
	if ok && cached.size == st.Size() && cached.mod.Equal(st.ModTime()) {
		return cached.ver
	}
	v := detectVersion(id, binPath(id))
	if v == "" {
		v = loadVersions()[id]
	}
	diskVerMu.Lock()
	diskVerCache[id] = diskVer{mod: st.ModTime(), size: st.Size(), ver: v}
	diskVerMu.Unlock()
	return v
}

// GetAllProgress — снимок прогресса скачиваний.
func GetAllProgress() map[CoreID]Progress {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[CoreID]Progress, len(progress))
	for k, v := range progress {
		out[k] = v
	}
	return out
}

func setProgress(id CoreID, p Progress) {
	mu.Lock()
	progress[id] = p
	mu.Unlock()
}

// StartDownload ставит ядро в очередь на скачивание. version="" — последний
// релиз. Возвращает выбранную версию (для тоста в UI).
func StartDownload(id CoreID, version string) (string, error) {
	s := specs[id]
	if s == nil {
		return "", fmt.Errorf("неизвестное ядро: %s", id)
	}
	mu.Lock()
	if running[id] {
		mu.Unlock()
		return "", fmt.Errorf("%s уже качается", id)
	}
	running[id] = true
	mu.Unlock()

	fail := func(err error) (string, error) {
		mu.Lock()
		delete(running, id)
		mu.Unlock()
		return "", err
	}

	version = strings.TrimSpace(version)
	if version == "" {
		v, err := CheckLatest(id)
		if err != nil {
			return fail(fmt.Errorf("не удалось узнать последнюю версию: %w", err))
		}
		version = v
	}
	if s.goModule != "" && (version == "" || version == "git-latest") {
		version = "git-latest"
	}
	if version == "" {
		return fail(errors.New("пустая версия"))
	}

	setProgress(id, Progress{State: "downloading", Percent: 1, Stage: "старт…", Version: version})
	go func() {
		var err error
		if s.goModule != "" {
			err = installWithGo(s)
		} else {
			err = downloadRelease(id, s, version)
		}
		mu.Lock()
		delete(running, id)
		mu.Unlock()
		if err != nil {
			setProgress(id, Progress{State: "error", Error: err.Error(), Version: version})
			return
		}
		saveVersion(id, version)
		setProgress(id, Progress{State: "done", Percent: 100, Stage: "готово", Version: version})
	}()
	return version, nil
}

func installWithGo(s *spec) error {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return errors.New("нужен Go в PATH (go install " + s.goModule + "@latest)")
	}
	setProgress(s.id, Progress{State: "installing", Percent: 20, Stage: "go install " + s.goModule + "@latest"})
	dir := CoresDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "install", s.goModule+"@latest")
	cfgDir, _ := os.UserConfigDir()
	if cfgDir != "" {
		_ = os.MkdirAll(cfgDir, 0o755)
		cmd.Env = append(os.Environ(), "GOBIN="+dir, "GOCACHE="+filepath.Join(cfgDir, "proxy-checker-go-cache"))
	} else {
		cmd.Env = append(os.Environ(), "GOBIN="+dir)
	}
	cmd.Dir = os.TempDir()
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 800 {
			msg = msg[len(msg)-800:]
		}
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("go install: %s", msg)
	}
	setProgress(s.id, Progress{State: "extracting", Percent: 90, Stage: "проверка"})
	if _, err := os.Stat(binPath(s.id)); err != nil {
		return fmt.Errorf("go install завершился, но %s не найден", binFileName(s.id))
	}
	return nil
}

func downloadRelease(id CoreID, s *spec, tag string) error {
	name, err := assetName(id, tag)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", s.repo, tag, name)
	dir := CoresDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "proxy-checker")
	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", name, resp.Status)
	}

	total := resp.ContentLength
	last := time.Now()
	var done int64
	buf := make([]byte, 256*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := tmp.Write(buf[:n]); werr != nil {
				return werr
			}
			done += int64(n)
			if time.Since(last) > 200*time.Millisecond {
				last = time.Now()
				pct := 0
				if total > 0 {
					pct = int(done * 80 / total)
				}
				setProgress(id, Progress{State: "downloading", Percent: pct, Stage: fmt.Sprintf("скачано %s", humanBytes(done)), Version: tag})
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	setProgress(id, Progress{State: "extracting", Percent: 85, Stage: "распаковка", Version: tag})
	if err := extractInto(tmpName, name, binPath(id)); err != nil {
		return err
	}
	if err := os.Chmod(binPath(id), 0o755); err != nil {
		return err
	}
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d Б", n)
	}
	units := []string{"КБ", "МБ", "ГБ", "ТБ", "ПБ"}
	div := float64(unit)
	exp := 0
	for v := float64(n) / unit; v >= unit && exp < len(units)-1; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", float64(n)/div, units[exp])
}

// assetName — имя ассета релиза для текущей ОС/архитектуры.
func assetName(id CoreID, tag string) (string, error) {
	ver := strings.TrimPrefix(tag, "v")
	goos, goarch := runtime.GOOS, runtime.GOARCH
	switch id {
	case CoreSingBox:
		ext := ".tar.gz"
		if goos == "windows" {
			ext = ".zip"
		}
		if goarch != "amd64" && goarch != "arm64" && goarch != "386" {
			return "", fmt.Errorf("sing-box: нет сборки для %s/%s", goos, goarch)
		}
		return fmt.Sprintf("sing-box-%s-%s-%s%s", ver, goos, goarch, ext), nil
	case CoreXray:
		o, ok := map[string]string{"linux": "linux", "darwin": "macos", "windows": "windows", "freebsd": "freebsd"}[goos]
		if !ok {
			return "", fmt.Errorf("xray: нет сборки для %s", goos)
		}
		a, ok := map[string]string{"amd64": "64", "arm64": "arm64-v8a", "386": "32", "arm": "arm32-v7a"}[goarch]
		if !ok {
			return "", fmt.Errorf("xray: нет сборки для %s", goarch)
		}
		return fmt.Sprintf("Xray-%s-%s.zip", o, a), nil
	case CoreMihomo:
		a, ok := map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "386", "arm": "armv7"}[goarch]
		if !ok {
			return "", fmt.Errorf("mihomo: нет сборки для %s", goarch)
		}
		if goos == "windows" {
			return fmt.Sprintf("mihomo-%s-%s-v%s.zip", goos, a, ver), nil
		}
		if goos != "linux" && goos != "darwin" {
			return "", fmt.Errorf("mihomo: нет сборки для %s", goos)
		}
		return fmt.Sprintf("mihomo-%s-%s-v%s.gz", goos, a, ver), nil
	case CoreJuicity:
		o, ok := map[string]string{"linux": "linux", "darwin": "darwin", "windows": "windows"}[goos]
		if !ok {
			return "", fmt.Errorf("juicity: нет сборки для %s", goos)
		}
		a, ok := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[goarch]
		if !ok {
			return "", fmt.Errorf("juicity: нет сборки для %s", goarch)
		}
		return fmt.Sprintf("juicity-%s-%s.zip", o, a), nil
	case CoreMieru:
		if goarch != "amd64" && goarch != "arm64" && goarch != "riscv64" {
			return "", fmt.Errorf("mieru: нет сборки для %s", goarch)
		}
		if goos == "windows" {
			return fmt.Sprintf("mieru_%s_windows_%s.zip", ver, goarch), nil
		}
		return fmt.Sprintf("mieru_%s_%s_%s.tar.gz", ver, goos, goarch), nil
	}
	return "", fmt.Errorf("для %s нет релизов", id)
}

func assetURL(id CoreID, tag string) string {
	s := specs[id]
	if s == nil {
		return ""
	}
	page := "https://github.com/" + s.repo + "/releases"
	if s.goModule != "" {
		repo := s.goModule
		if i := strings.Index(repo, "/cmd/"); i > 0 {
			repo = repo[:i]
		}
		return "https://" + repo
	}
	if tag == "" || tag == "git-latest" {
		return page
	}
	name, err := assetName(id, tag)
	if err != nil {
		return page
	}
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", s.repo, tag, name)
}

// extractInto распаковывает архив или gzip-файл в dest (атомарно).
func extractInto(archive, archiveName, dest string) error {
	lower := strings.ToLower(archiveName)
	var err error
	switch {
	case strings.HasSuffix(lower, ".zip"):
		err = extractZip(archive, filepath.Base(dest), dest)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		err = extractTarGz(archive, filepath.Base(dest), dest)
	case strings.HasSuffix(lower, ".gz"):
		err = extractGz(archive, dest)
	default:
		// голый бинарник
		err = copyFile(archive, dest)
	}
	return err
}

func writeAtomic(dest string, r io.Reader) error {
	tmp := dest + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func extractZip(archive, want, dest string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || filepath.Base(f.Name) != want {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return writeAtomic(dest, rc)
	}
	return fmt.Errorf("%s нет в архиве", want)
}

func extractTarGz(archive, want, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != want {
			continue
		}
		return writeAtomic(dest, tr)
	}
	return fmt.Errorf("%s нет в архиве", want)
}

func extractGz(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	return writeAtomic(dest, gz)
}

func copyFile(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeAtomic(dest, f)
}
