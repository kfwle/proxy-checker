# Proxy Checker — один бинарник, локальный веб-UI

Проверка proxy-ключей: `vless · vmess · ss · trojan · hysteria2 · hysteria · anytls · tuic · juicity · naive(+https/+quic) · shadowtls · mieru · socks · http · mtproto · webproxy · wireguard`.

Ввод: ссылки (по одной на строку, рваные склеиваются) **или целиком JSON-конфиг sing-box/xray** — outbounds конвертятся в ссылки, балансеры `selector`/`urltest` раскрываются в участников.

Стек: **React + Vite + Tailwind** → `frontend/dist`, **Go отдаёт её через `//go:embed`** + API на `127.0.0.1:5173` и открывает браузер. Пользователю нужен только один бинарник.

## Запуск

```bash
make build        # фронт + go-бинарник bin/checker
./bin/checker     # → http://127.0.0.1:5173
PORT=8080 ./bin/checker
NO_BROWSER=1 ./bin/checker
./bin/checker --full   # тихий фон: случайный порт, печать url+pid, терминал свободен
```

Для разработки: `cd frontend && npm install && npm run dev` (прокси `/api` → `:18080`), бэк: `PORT=18080 NO_BROWSER=1 go run ./cmd/checker`.

Ядра (скачиваются из вкладки «Ядра» в UI): `sing-box`, `xray`, `mihomo`, `mtproto-checker`, `juicity-client`, `mieru`. Лежат в `./cores/` рядом с бинарником (или `$CHECKER_CORES_DIR`). Без ядер работают встроенные проверки: TCP, Ping, direct http/socks.

## Проверка ключей (режимы URL / TCP / Ping)

- **URL-тест** — HTTP-запрос к test URL (по умолчанию `https://www.gstatic.com/generate_204`) через поднятый прокси. `alive` = ответ &lt; 500. Движки с полным фолбэком: `vless/vmess/ss/trojan` → `sing-box → xray → mihomo`; `hysteria2/tuic/anytls` → `sing-box → mihomo`; `naive/shadowtls` → `sing-box`; `http/socks` и голый `host:port` → встроенный `direct`, затем ядра; `tg://` → `mtproto-checker` (`--full` пробрасывается); `juicity` → родной `juicity-client`; `mieru` (включая диплинк `mierus://user@host?port=...`) → родной `mieru` (изолированный HOME, случайные порты, после проверки `stop`). Каждый раннер поднимает локальный socks и гоняет тот же URL-тест; stderr упавшего ядра показывается в ошибке (валидность всех генерируемых конфигов проверена `xray -test` / `mihomo -t`).
- **TCP** — коннект к `host:port` (ядра не нужны).
- **Ping** — системный `ping -c1` до хоста (ядра не нужны; многие хостинги режут ICMP — это нормально и не значит «прокси мёртв»).

Результаты всегда сохраняются в `results/YYYY-MM-DD/` (`_all.json`, `_alive.txt`, `_all.csv`), старые чистятся `KeepDays(30)` при старте. В UI — фильтры живые/мёртвые + мультивыбор протоколов, экспорт, автосохранённые файлы со скачиванием.

## Сводная проверка хоста («Всё сразу», страницы /test, /trace, /dns)

В шапке вкладки **Чекер / Тесты / DNS / Трейс** (бэкенд отдаёт index.html на любой не-API путь). Трейс — отдельная вкладка со своей целью и стопом.

Кнопка на строке (и отдельная страница **Тесты** `/test` для произвольного хоста) запускает всё разом; состав выбирается тумблерами (по умолчанию всё включено, панель фильтров свернута). На /test фильтры стоят **до** кнопки Проверить и рулят запущенной панелью тоже. Отдельный тумблер **🇷🇺 Только РФ**: check-host меряет только с ru1/ru2/ru3 (`&node=`, список нод кэшируется на час), globalping — `locations: [RU]` (проверено: одни RU-города), пробы и так из РФ (у KeyCDN точек в РФ нет — пишет честно):

| Группа | Что делает |
|---|---|
| CHECK-HOST | `check-host.net`: ping/tcp/udp/dns/http с 3 нод по миру, развёртка по нодам с флагами |
| ПИНГЕРЫ | `Globalping` (до 50 проб, без ключа, через socks-ротацию при 429) + `KeyCDN` (8 точек) |
| ЧЕБУРЧЕК | вердикт РКН + GEO/ASN + живые пробы из сетей РФ с картой регионов |
| 2IP | abuse/domains/whois/revdns/exit-ip (платные — по токену, кроме revdns и exit) |
| DNS | DNS-тест + сверка резолвинга (см. ниже) |

- **Пробы РФ** (`POST /api/probe`): SNI-check + traceroute из сетей добровольцев cheburcheck (домены и IP; вердикты `ok/tspu_block/uncertain`, `sni_block/dns_spoofing`). Карта 83 субъектов, цвет по худшему вердикту, штриховка при частичной доступности, клик — детали по сканерам. Кэш час.
- **Карта и DNS-сверка**: см. разделы ниже.
- **Выходной IP** (`POST /api/exitip`): запрос к `api.2ip.io/` через сам прокси — каким IP/гео/ASN прокси выходит в мир.

## Трейс маршрута (вкладка Тесты)

Вводишь домен — идёт **настоящий системный traceroute** (`traceroute`/`tracepath`/`tracert`, строки разбираются живьём), таблица как в терминале 1:1, всегда все хопы до лимита (плюс кнопка Стоп с реальной отменой). Своего UDP-стека больше нет на первом месте: расследование показало, что промежуточные боксы синтезируют ICMP-ответы с подменой source под цель, и самописный трейс им верил. Поэтому: системный — основной, встроенный UDP (`IP_RECVERR`, без рута) — только фолбэк, если утилит нет. Вердикт: «Достигнут за N» (только с TCP-подтверждением) или «Обрыв после K — похоже на фильтрацию (ТСПУ/чёрная дыра)». Ответ с IP цели на TTL≤2 быстрее 5мс для внешней цели невозможен — такое игнорируется как подмена бокса.

## Выбор ядер и правила маршрутизации

- **Плитки ядер** над полем ввода: `sing-box` / `xray` / `mihomo` — тыкаются 1/2/3, выбор хранится в браузере (`options.cores`). `direct · mtproto · juicity · mieru` всегда включены и плитками не режутся (если выключить всё — честно упадёт в дефолт, а не в пустоту).
- **Правила** (Настройки): таблица `протокол / транспорт / защита → ядро`, первое совпадение побеждает, пустое поле = любое. Например: `vless + tcp + tls → sing-box`, `vless + tcp + reality → xray`, `vless + grpc → mihomo`. Транспорт/защита определяются из ссылки (`?type=`, `?security=`, эвристика 443/trojan → tls).

## DNS: тест хоста и сверка резолвинга (вкладка DNS, `/dns`)

- **DNS-тест** (`POST /api/dnstest`): A-запрос `google.com` прямо на хост — UDP/53, TCP/53, DoT/853. Ответ: мс + записи + rcode.
- **Сверка** (`POST /api/dnscomp` → `GET /api/dnscomp/:id`, кольцо прогресса): домен резолвится через Google / Cloudflare / Quad9 / Yandex / Alibaba / системный + пресеты из справочника **dns.quic.best** (54 штуки с IPv4, по умолчанию выключены) каждым транспортом (UDP/TCP/DoT/DoH/DoQ через quic-go). Свои резолверы добавляются (страна определяется по IP автоматически). Сравнение **по автономкам, а не IP** (round-robin/ECS гоняют разные эджи одного AS) + ASN-чипы; Team Cymru по DNS как фолбэк ASN без ключа.
- DoQ требует открытого UDP/853 — где egress его режет, будет честная ошибка.

## Ежедневные socks5

Настройки → тумблер (включено по умолчанию): раз в сутки качается `hookzof/socks5_list/proxy.txt` (лист кэшируется на сутки), прогоняется 3к строк со скользящим окном, живые — в `results/daily/YYYY-MM-DD/` + файлы по странам (`RU.txt`, …). Страна — только для живых, с вечным кэшем. Включение = сразу прогон 1к (если 0 живых — следующие чанки, с дедупом). `GET/POST /api/daily`, `POST /api/daily/run`.

## Ядра / автоскачивание

Вкладка «Ядра»: статус, версии, кнопки «Скачать / Обновить» + «Скачать всё», прогресс в карточке. `mtproto-checker` без релизов — ставится через `go install @latest` (нужен Go), версионируется как `git-latest`. Проверка обновлений — сверка с GitHub releases, отключается в настройках.

## Известные ограничения (проверено живьём)

- `mihomo`/`xray`: полноценные раннеры — `vless/vmess/ss/trojan/socks/http` через оба, `hysteria2/tuic/anytls` через mihomo. Все генерируемые конфиги валидируются (`xray -test`, `mihomo -t` — 18/18 зелёных); mihomo принудительно роутит всё через проверяемый прокси (`MATCH,sel`, иначе был бы ложный alive напрямую).
- `juicity`/`mieru`: sing-box и mihomo их выпилили — только родные клиенты.
- `anytls` в sing-box требует включённого TLS — форсируем.
- KeyCDN-пингер парсит HTML (токен со страницы) — сменит вёрстку, ляжет с честной ошибкой.
- UDP/53/TCP/53 по пути могут перехватываться провайдером (прозрачный DNS-прокси) — DoT показательнее.
- IPv6 в хостах парсится частично — для экзотики используйте скобки `[::1]:port`.

## Безопасность

- Слушает только `127.0.0.1` (порт `PORT` или случайный). Без TLS и auth — рассчитано на локальную машину, не выставлять в сеть.
- Секреты (`data/settings.json` с токенами, `twoip.json`, mieru-конфиги с паролями) пишутся с `0600`; токен 2ip в кэш-ключи и API-ответы не попадает (в UI только маска).
- Тела POST ограничены (10 МБ на /api/check, 1 МБ остальные); версий ядер — строгий allowlist; ID ядер — allowlist; custom DNS — валидация host/DoH-URL; файлы отдаются только `.json/.txt/.csv` строго внутри `results/`.
- Скачанные ядра исполняются: апстримы — официальные GitHub-релизы по HTTPS (без pin'а хэшей — сверяйте при паранойе); `mtproto-checker` ставится через `go install @latest`.
- Задачи ограничены: макс. 4 одновременных прогона, реестры чистятся (готовые старше часа, кап 50), `DELETE` отменяет прогон, SSE рвётся при отключении клиента. Внешние API дёргаются только ондеманд + TTL-кэши; платные квоты 2ip — только руками (кроме abuse новых daily-IP по 1 запросу, с кэшем).

## API (основное)

- `POST /api/check {text|links, options}` → `{id,total}`; `GET /api/jobs/:id`; `GET /api/jobs/:id/stream` (SSE); `DELETE /api/jobs/:id`
- `GET /api/cores`, `POST /api/cores/check-updates|download|download-all`, `GET /api/cores/progress`
- `POST /api/extcheck {host, types?}`, `POST /api/gping|keyping {target}`, `GET /api/rkn?target=`, `POST /api/probe {target}`, `POST /api/exitip {link}`, `GET /api/revdns?ip=`
- `POST /api/dnstest {host}`; `POST /api/dnscomp {target, ids?}`, `GET /api/dnscomp/:id`, резолверы: `GET|POST /api/dnscomp/resolvers`, `POST /api/dnscomp/resolvers/del`
- `GET|POST /api/daily`, `POST /api/daily/run`, `GET|POST /api/settings` (2ip-токен, авто-abuse), `GET /api/geo/pool`, `GET /api/results`, `GET /api/results/download?file=`

## Структура

```
cmd/checker        main (embed dist + serve :5173 + open browser + --full демон)
internal/api       REST + SSE + скачивание ядер
internal/checker   jobs, протоколы, sing-box/direct/juicity/mieru-раннеры, mtproto-exec
internal/cores     статус / версии / download+extract / прогресс
internal/checkhost|gping|keyping   внешние пингеры
internal/probe|rkn                  cheburcheck: пробы и вердикт РКН
internal/dnscomp|dnstest            DNS-сверка и DNS-тест хоста
internal/geoip|twoip|revdns         обогащение: 2ip, abuse/whois, reverse-IP
internal/daily                      ежедневные socks5 + geo по странам
frontend           React+Vite+Tailwind (report.tsx — сводная панель, RussiaMap.tsx — карта)
cores/ data/ results/   рантайм рядом с бинарником (в .gitignore)
```
