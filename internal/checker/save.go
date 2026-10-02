package checker

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SavedFile описывает один автосохранённый файл (путь относительно ResultsDir).
type SavedFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Kind string `json:"kind"` // json | alive | csv
	Size int64  `json:"size"`
}

// ResultsDir: $CHECKER_RESULTS_DIR или ./results рядом с бинарником.
func ResultsDir() string {
	if v := os.Getenv("CHECKER_RESULTS_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "results")
	}
	return "results"
}

// SaveJob пишет результаты в results/YYYY-MM-DD/HH-MM-SS_<job8>_<mode>_*
// независимо от режима проверки. Возвращает относительные пути.
func SaveJob(j *Job) []SavedFile {
	res := j.Snapshot()
	// стабильный порядок: живые first, потом по пингу
	sort.Slice(res, func(a, b int) bool {
		if res[a].Alive != res[b].Alive {
			return res[a].Alive
		}
		return res[a].Latency < res[b].Latency
	})
	day := j.Started.Format("2006-01-02")
	stamp := j.Started.Format("15-04-05")
	short := j.ID
	if len(short) > 8 {
		short = short[len(short)-8:]
	}
	mode := j.Opts.Mode
	if mode == "" {
		mode = "url"
	}
	dir := filepath.Join(ResultsDir(), day)
	_ = os.MkdirAll(dir, 0o755)
	base := fmt.Sprintf("%s_%s_%s", stamp, short, mode)

	out := []SavedFile{}
	// 1. full json
	if p, err := writeJSONFile(dir, base+"_all.json", res); err == nil {
		out = append(out, p)
	}
	// 2. alive links txt
	alive := []string{}
	for _, r := range res {
		if r.Alive {
			alive = append(alive, r.Link)
		}
	}
	if p, err := writeTextFile(dir, base+"_alive.txt", strings.Join(alive, "\n")); err == nil {
		out = append(out, p)
	}
	// 3. csv
	if p, err := writeCSVFile(dir, base+"_all.csv", res); err == nil {
		out = append(out, p)
	}
	j.mu.Lock()
	j.Saved = out
	j.SaveDir = filepath.Join(day, base)
	j.mu.Unlock()
	return out
}

func fileSize(p string) int64 {
	if st, err := os.Stat(p); err == nil {
		return st.Size()
	}
	return 0
}

func writeJSONFile(dir, name string, res []Result) (SavedFile, error) {
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		return SavedFile{}, err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(res); err != nil {
		return SavedFile{}, err
	}
	rel, _ := filepath.Rel(ResultsDir(), p)
	return SavedFile{Name: name, Path: filepath.ToSlash(rel), Kind: "json", Size: fileSize(p)}, nil
}

func writeTextFile(dir, name, content string) (SavedFile, error) {
	p := filepath.Join(dir, name)
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		return SavedFile{}, err
	}
	rel, _ := filepath.Rel(ResultsDir(), p)
	return SavedFile{Name: name, Path: filepath.ToSlash(rel), Kind: "alive", Size: fileSize(p)}, nil
}

func writeCSVFile(dir, name string, res []Result) (SavedFile, error) {
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		return SavedFile{}, err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"link", "protocol", "host", "alive", "latencyMs", "core", "error"})
	for _, r := range res {
		alive := "0"
		if r.Alive {
			alive = "1"
		}
		_ = w.Write([]string{r.Link, r.Protocol, r.Host, alive, fmt.Sprintf("%d", r.Latency), r.Core, r.Error})
	}
	w.Flush()
	rel, _ := filepath.Rel(ResultsDir(), p)
	return SavedFile{Name: name, Path: filepath.ToSlash(rel), Kind: "csv", Size: fileSize(p)}, nil
}

// ListSaved возвращает последние N файлов из results/ (плоский список, новые first).
func ListSaved(limit int) []SavedFile {
	root := ResultsDir()
	out := []SavedFile{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		kind := "json"
		switch {
		case strings.HasSuffix(p, "_alive.txt"):
			kind = "alive"
		case strings.HasSuffix(p, ".csv"):
			kind = "csv"
		}
		out = append(out, SavedFile{Name: info.Name(), Path: filepath.ToSlash(rel), Kind: kind, Size: info.Size()})
		return nil
	})
	sort.Slice(out, func(a, b int) bool { return out[a].Name > out[b].Name })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// KeepDays чистит results/ старше N дней (по имени папки YYYY-MM-DD).
func KeepDays(n int) {
	if n <= 0 {
		return
	}
	root := ResultsDir()
	cutoff := time.Now().AddDate(0, 0, -n).Format("2006-01-02")
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() < cutoff {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}
