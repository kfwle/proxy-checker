package trace

// Нативный UDP-трейс для Linux через IP_RECVERR (без рута):
// шлём UDP с растущим TTL, ICMP Time Exceeded / Port Unreachable
// забираем из MSG_ERRQUEUE. Не Linux или нет прав — системные утилиты.

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	basePort  = 33434
	maxProbes = 3
	probeWait = 1500 * time.Millisecond
)

func runTrace(ctx context.Context, target string, maxHops int, onHop func(Hop)) ([]Hop, string, error) {
	resolved := resolveAll(target)
	if len(resolved) == 0 {
		return nil, "", fmt.Errorf("не резолвится: %s", target)
	}
	dstIP := resolved[0]
	var hops []Hop
	var reached bool
	var err error
	// Сначала настоящий системный traceroute — вывод 1:1 как в терминале.
	// Нативный UDP-стек — только фолбэк, если бинарника нет/упал.
	hops, err = sysTrace(ctx, target, maxHops, onHop)
	if err == nil {
		return hops, summarizeSys(target, resolved, hops), nil
	}
	sysErr := err
	if runtime.GOOS == "linux" {
		hops, reached, err = nativeTrace(ctx, dstIP, maxHops, onHop)
		if err == nil {
			return hops, summarize(target, resolved, hops, reached), nil
		}
	}
	if len(hops) > 0 {
		return hops, "", fmt.Errorf("трейс оборвался: %v", sysErr)
	}
	return hops, "", sysErr
}

type udpReply struct {
	ip  string
	rtt time.Duration
}

// nativeTrace: UDP + RECVERR. Возвращает хопы по мере готовности через onHop.
func nativeTrace(ctx context.Context, dstIP string, maxHops int, onHop func(Hop)) (hops []Hop, reached bool, err error) {
	laddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0")}
	uc, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, false, err
	}
	defer uc.Close()
	var pc net.PacketConn = uc
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, false, err
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		// extended ICMP-ошибки на UDP-сокет
		if e := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1); e != nil {
			sockErr = e
			return
		}
	})
	if err != nil {
		return nil, false, err
	}
	if sockErr != nil {
		return nil, false, sockErr
	}
	dst := &net.UDPAddr{IP: net.ParseIP(dstIP)}
	tcpOK := -1 // TCP-подтверждение считаем один раз: дальше не меняется
	lanTarget := isPrivateIP(dstIP) // свой LAN: 1 хоп до цели — норма, фильтр бокса не применяем
	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return hops, false, ctx.Err()
		default:
		}
		h := Hop{TTL: ttl}
		for i := 0; i < maxProbes; i++ {
			port := basePort + ttl*maxProbes + i
			dst.Port = port
			ip, rtt, ok := udpProbe(raw, pc, dst, ttl, lanTarget)
			if ok {
				h.Probes = append(h.Probes, Probe{IP: ip, Ms: float64(rtt.Microseconds()) / 1000})
			} else {
				h.Probes = append(h.Probes, Probe{})
			}
		}
		hops = append(hops, h)
		if onHop != nil {
			onHop(h)
		}
		// дошли до цели? только с TCP-подтверждением: ICMP-подмену
		// хендшейком не изобразить
		for _, p := range h.Probes {
			if p.IP != "" && p.IP == dstIP {
				if tcpOK == -1 {
					if tcpReachable(dstIP) {
						tcpOK = 1
					} else {
						tcpOK = 0
					}
				}
				if tcpOK == 1 {
					return hops, true, nil
				}
				break
			}
		}
	}
	return hops, false, nil
}

// isPrivateIP: локальные/частные адреса — для них 1 хоп до цели норма.
func isPrivateIP(h string) bool {
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}

// tcpReachable: TCP-хендшейк 443 (fallback 80) — настоящее подтверждение,
// которое ICMP-подменой не изобразить.
func tcpReachable(host string) bool {
	for _, port := range []string{"443", "80"} {
		d := net.Dialer{Timeout: 3 * time.Second}
		c, err := d.Dial("tcp", net.JoinHostPort(host, port))
		if err == nil {
			c.Close()
			return true
		}
	}
	return false
}

func setTTL(raw syscall.RawConn, ttl int) error {
	var err error
	_ = raw.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
	})
	if err != nil {
		return err
	}
	return nil
}

// udpProbe: один UDP с TTL, ждём ICMP из errqueue. ok=false — таймаут.
// Подмену LAN-бокса (IP цели на TTL<=2 быстрее 5мс — физически невозможно
// для внешней цели) игнорируем и ждём настоящий ответ в пределах пробы.
func udpProbe(raw syscall.RawConn, pc net.PacketConn, dst *net.UDPAddr, ttl int, lanTarget bool) (string, time.Duration, bool) {
	if err := setTTL(raw, ttl); err != nil {
		return "", 0, false
	}
	_ = pc.SetDeadline(time.Now().Add(probeWait))
	start := time.Now()
	if _, err := pc.WriteTo([]byte(""), dst); err != nil {
		return "", 0, false
	}
	dstIP := dst.IP.String()
	// крутим recvmsg: обычные данные (маловероятно) + очередь ошибок
	deadline := time.Now().Add(probeWait)
	for time.Now().Before(deadline) {
		// 1. обычная очередь — вдруг кто-то ответил напрямую
		_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 1500)
		_, _, err := pc.ReadFrom(buf)
		if err == nil {
			// UDP-ответ (резолвер/эхо) — считаем достижением через dst
			return dstIP, time.Since(start), true
		}
		// 2. очередь ошибок
		if ip, ok := readErrQueue(raw); ok {
			el := time.Since(start)
			ms := float64(el.Microseconds()) / 1000
			if !lanTarget && ip == dstIP && ttl <= 2 && ms < 5.0 {
				continue // бокс, ждём дальше
			}
			return ip, el, true
		}
	}
	return "", 0, false
}

// readErrQueue читает одно ICMP из MSG_ERRQUEUE. Возвращает IP отправителя.
func readErrQueue(raw syscall.RawConn) (string, bool) {
	var ip string
	var ok bool
	_ = raw.Control(func(fd uintptr) {
		// читаем управляющее сообщение с ошибкой
		p := make([]byte, 1500)
		oob := make([]byte, 512)
		_, _, _, addr, err := unix.Recvmsg(int(fd), p, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err != nil {
			return
		}
		// адрес отправителя ICMP
		switch a := addr.(type) {
		case *unix.SockaddrInet4:
			ip = fmt.Sprintf("%d.%d.%d.%d", a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3])
			ok = true
		}
	})
	return ip, ok
}
