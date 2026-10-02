package trace

// Локальный traceroute с машины пользователя: UDP-пакеты с растущим TTL,
// ответы-ICMP ловим через IP_RECVERR (Linux, без рута).
// Не Linux — откат на системные tracepath/traceroute/tracert.
// *** подряд = тишина (так выглядит и ТСПУ-дроп, и фильтр, и чёрная дыра).

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type Probe struct {
	IP string  `json:"ip,omitempty"`
	Ms float64 `json:"ms,omitempty"`
}

type Hop struct {
	TTL    int     `json:"ttl"`
	Probes []Probe `json:"probes"`
}

type Job struct {
	ID       string
	Target   string
	MaxHops  int
	Started  time.Time
	cancel   context.CancelFunc
	mu       sync.Mutex
	Hops     []Hop
	Done     bool
	Finished bool
	Error    string `json:"error,omitempty"`
	Verdict  string `json:"verdict,omitempty"`
}

var (
	mu   sync.Mutex
	jobs = map[string]*Job{}
)

func StartJob(id, target string, maxHops int) *Job {
	if maxHops <= 0 || maxHops > 30 {
		maxHops = 30
	}
	// порт из host:port отрезаем — трейсим хост
	if i := strings.LastIndex(target, ":"); i > 0 && strings.Count(target, ":") == 1 {
		target = target[:i]
	}
	j := &Job{ID: id, Target: target, MaxHops: maxHops, Started: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	mu.Lock()
	jobs[id] = j
	mu.Unlock()
	go j.runCtx(ctx)
	return j
}

// Cancel останавливает трейс.
func Cancel(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	j, ok := jobs[id]
	if !ok {
		return false
	}
	if j.cancel != nil {
		j.cancel()
	}
	delete(jobs, id)
	return true
}

func GetJob(id string) (*Job, bool) {
	mu.Lock()
	defer mu.Unlock()
	j, ok := jobs[id]
	return j, ok
}

// Sweep чистит старые законченные задачи.
func Sweep(maxAge time.Duration, cap int) {
	cutoff := time.Now().Add(-maxAge)
	mu.Lock()
	defer mu.Unlock()
	for id, j := range jobs {
		j.mu.Lock()
		old := j.Finished && j.Started.Before(cutoff)
		j.mu.Unlock()
		if old {
			delete(jobs, id)
		}
	}
	_ = cap
}

func (j *Job) snapshot() (hops []Hop, done, fin bool, err, verdict string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]Hop(nil), j.Hops...), j.Done, j.Finished, j.Error, j.Verdict
}

// Pub — копия для API.
func (j *Job) Pub() ([]Hop, bool, bool, string, string) { return j.snapshot() }

func (j *Job) push(h Hop) {
	j.mu.Lock()
	j.Hops = append(j.Hops, h)
	j.mu.Unlock()
}

func (j *Job) finish(verdict string) {
	j.mu.Lock()
	j.Verdict = verdict
	j.Done = true
	j.Finished = true
	j.mu.Unlock()
}

func (j *Job) fail(msg string) {
	j.mu.Lock()
	j.Error = msg
	j.Done = true
	j.Finished = true
	j.mu.Unlock()
}

func (j *Job) runCtx(ctx context.Context) {
	hops, verdict, err := runTrace(ctx, j.Target, j.MaxHops, func(h Hop) {
		j.push(h)
	})
	if err != nil {
		// отмена — не ошибка для UI, просто останавливаемся
		if ctx.Err() != nil {
			j.mu.Lock()
			j.Done = true
			j.Finished = true
			j.mu.Unlock()
			return
		}
		j.fail(err.Error())
		return
	}
	j.mu.Lock()
	j.Verdict = verdict
	j.Done = true
	j.Finished = true
	j.mu.Unlock()
	_ = hops
}

func (j *Job) run() {
	j.runCtx(context.Background())
}

// summarize выносит вердикт по хопам.
// confirmed=true: раннер остановился на подтверждённом достижении
// (системный traceroute или нативный с защитой от ложного dst).
// confirmed=false: цель видели, но достижение не подтверждено —
// вердикт честно говорит об аномалии, а не о достижении.
func summarize(target string, resolved []string, hops []Hop, confirmed bool) string {
	inSet := map[string]bool{}
	for _, ip := range resolved {
		inSet[ip] = true
	}
	// подозрительно быстрый "ответ цели" на малых TTL — промежуточный бокс
	weird := false
	for _, h := range hops {
		if h.TTL > 2 {
			break
		}
		for _, p := range h.Probes {
			if p.IP != "" && inSet[p.IP] && p.Ms < 1.0 {
				weird = true
			}
		}
	}
	lastOK := 0
	for i, h := range hops {
		answered := false
		reached := false
		for _, p := range h.Probes {
			if p.IP != "" {
				answered = true
				if inSet[p.IP] {
					reached = true
				}
			}
		}
		if reached {
			if !confirmed {
				return fmt.Sprintf("Цель %s отвечает на %d %s, но достижение не подтверждено (возможно, отвечает промежуточный бокс) — смотри таблицу", target, h.TTL, plural(h.TTL, "прыжке", "прыжках", "прыжках"))
			}
			s := fmt.Sprintf("Достигнут за %d %s", h.TTL, plural(h.TTL, "прыжок", "прыжка", "прыжков"))
			if weird {
				s += " (но цель отвечала и на TTL≤2 быстрее 1 мс — там, скорее всего, подменяет промежуточный бокс, вердикту верить осторожно)"
			}
			return s
		}
		if answered {
			lastOK = i
		}
	}
	if len(hops) == 0 {
		return "нет данных"
	}
	// были ли вообще ответы
	any := false
	for _, h := range hops {
		for _, p := range h.Probes {
			if p.IP != "" {
				any = true
			}
		}
	}
	if !any {
		return "Тишина с 1-го прыжка: режутся ICMP/UDP на твоей стороне (фаервол/маршрут) — проверь локалку"
	}
	return fmt.Sprintf("Обрыв после %d: дальше только ***. Если сервис не открывается — похоже на фильтрацию (ТСПУ/чёрная дыра) примерно на этом уровне", lastOK+1)
}

func resolveAll(host string) []string {
	// IP как есть, домен — через системный резолвер
	if net.ParseIP(host) != nil {
		return []string{host}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	sort.Strings(addrs)
	return addrs
}

func plural(n int, one, few, many string) string {
	if n%10 == 1 && n%100 != 11 {
		return one
	}
	if n%10 >= 2 && n%10 <= 4 && (n%100 < 10 || n%100 >= 20) {
		return few
	}
	return many
}

// summarizeSys — вердикт по системному traceroute (настоящему тулу верим).
func summarizeSys(target string, resolved []string, hops []Hop) string {
	return summarize(target, resolved, hops, true)
}
