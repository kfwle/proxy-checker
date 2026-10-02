package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yzewe/proxy-checker/internal/checker"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// decodeJSON читает JSON с лимитом тела (защита от OOM на гигантских POST).
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "кривое тело или слишком большое", 400)
		return false
	}
	return true
}

func splitLines(s string) []string {
	// склейка разорванных ссылок: строка без схемы, идущая после строки,
	// оборванной на ? или & — продолжение ссылки, а не новая.
	// JSON-конфиги (sing-box/xray целиком, многострочные) собираются
	// по балансу скобок и разбираются в ссылки через ExtractLinks.
	var joined []string
	var jsonBuf strings.Builder
	jsonDepth := 0
	inJSON := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !inJSON && (line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//")) {
			continue
		}
		if !inJSON && strings.HasPrefix(line, "{") {
			inJSON = true
		}
		if inJSON {
			jsonBuf.WriteString(line + "\n")
			jsonDepth += strings.Count(line, "{") - strings.Count(line, "}")
			if jsonDepth <= 0 {
				for _, l := range checker.ExtractLinks(jsonBuf.String()) {
					if l = strings.TrimSpace(l); l != "" {
						joined = append(joined, l)
					}
				}
				jsonBuf.Reset()
				jsonDepth = 0
				inJSON = false
			}
			continue
		}
		if len(joined) > 0 && !strings.Contains(line, "://") {
			prev := joined[len(joined)-1]
			if strings.HasSuffix(prev, "?") || strings.HasSuffix(prev, "&") {
				joined[len(joined)-1] = prev + line
				continue
			}
		}
		joined = append(joined, line)
	}
	if inJSON {
		// незакрытый JSON — разбираем как есть
		for _, l := range checker.ExtractLinks(jsonBuf.String()) {
			if l = strings.TrimSpace(l); l != "" {
				joined = append(joined, l)
			}
		}
	}
	var out []string
	for _, line := range joined {
		// allow multiple per line separated by space? links contain no spaces
		for _, f := range strings.Fields(line) {
			f = strings.TrimSpace(f)
			if f != "" {
				out = append(out, f)
			}
		}
	}
	return out
}

func jobResults(j *checker.Job) []checker.Result {
	// expose copy via method — use reflection-free accessor
	return j.Snapshot()
}

func jobDone(j *checker.Job) int { return j.Progress() }

func jobFinished(j *checker.Job) bool { return j.IsFinished() }
