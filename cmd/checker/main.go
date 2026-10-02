package main

import (
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	"github.com/yzewe/proxy-checker/internal/api"
	"github.com/yzewe/proxy-checker/internal/checker"
	"github.com/yzewe/proxy-checker/internal/daily"
)

//go:embed dist
var distFS embed.FS

func main() {
	// --full: тихий фоновый режим. Перезапускаем себя откреплённо на
	// случайном порту, печатаем порт+PID и отдаём терминал:
	// выглядит как "закончил и заткнулся", а на деле работает.
	if hasFlag("--full") {
		daemonize()
		return
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "5173"
	}
	srv := api.New()
	router := srv.Router()
	daily.StartScheduler()

	// static frontend from embed (npm run build -> ../frontend/dist copied to cmd/checker/dist)
	sub, err := fs.Sub(distFS, "dist")
	if err == nil {
		fileSrv := http.FileServer(http.FS(sub))
		router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
				http.NotFound(w, r)
				return
			}
			// SPA fallback: /test и прочие пути без файла -> index.html
			if f, err := sub.Open(strings.TrimPrefix(path.Clean(r.URL.Path), "/")); err == nil {
				if st, err := f.Stat(); err == nil && !st.IsDir() {
					f.Close()
					fileSrv.ServeHTTP(w, r)
					return
				}
				f.Close()
			}
			b, err := fs.ReadFile(sub, "index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(b)
		})
	} else {
		fmt.Println("frontend dist not embedded (dev mode): API only")
	}

	addr := "127.0.0.1:" + port
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("port busy, trying random:", err)
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("cannot listen:", err)
			os.Exit(1)
		}
		addr = ln.Addr().String()
	}
	url := "http://" + addr
	fmt.Println("checker running at", url)
	checker.KeepDays(30)
	openBrowser(url)
	if err := http.Serve(ln, router); err != nil {
		fmt.Println("server stopped:", err)
	}
}

func hasFlag(f string) bool {
	for _, a := range os.Args[1:] {
		if a == f {
			return true
		}
	}
	return false
}

// daemonize: свободный порт, откреплённый дочерний процесс, печать PID+URL.
func daemonize() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("no free port:", err)
		os.Exit(1)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	exe, err := os.Executable()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	args := []string{}
	for _, a := range os.Args[1:] {
		if a != "--full" {
			args = append(args, a)
		}
	}
	env := append(os.Environ(), fmt.Sprintf("PORT=%d", port))
	if runtime.GOOS == "windows" {
		// DETACHED_PROCESS: без консольного окна, терминал свободен
		cmd := exec.Command(exe, args...)
		cmd.Env = env
		cmd.SysProcAttr = sysProcAttrWindows()
		if err := cmd.Start(); err != nil {
			fmt.Println("start:", err)
			os.Exit(1)
		}
		fmt.Printf("checker running in background\nurl: http://127.0.0.1:%d\npid: %d\n", port, cmd.Process.Pid)
		return
	}
	// unix: setsid + перенаправление stdio в /dev/null
	cmd := exec.Command(exe, args...)
	cmd.Env = env
	cmd.SysProcAttr = sysProcAttrUnix()
	devnull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if devnull != nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	}
	if err := cmd.Start(); err != nil {
		fmt.Println("start:", err)
		os.Exit(1)
	}
	fmt.Printf("checker running in background\nurl: http://127.0.0.1:%d\npid: %d\n", port, cmd.Process.Pid)
}

func openBrowser(url string) {
	if os.Getenv("NO_BROWSER") != "" {
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		return
	}
	_ = cmd.Start()
}
