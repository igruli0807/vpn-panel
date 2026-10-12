# MikroTik: выборочный VPN по списку адресов — AmneziaWG и SSTP

Ранбук для системного администратора площадки. Роутер — MikroTik на RouterOS 7, сервер — свой
VPS с AmneziaWG и/или SSTP (его ставит эта панель: `install.sh server --proto awg3|sstp` или
раздел «Серверы»).

**Что получаем.** Трафик **выбранных компьютеров** к **адресам из списка** уходит в туннель до
VPS. Всё остальное идёт как раньше — через вашего провайдера, без изменений. Упал туннель —
трафик по списку идёт напрямую, как до внедрения; ничего, кроме самих адресов из списка, не
ломается.

**Откуда ранбук и что в нём проверено.** Схема выросла из домашней установки на cAP ac (SSTP) и
была расписана под офисное ядро CCR2004 на RouterOS 7.20 по обследованию его конфигурации. Здесь
она обезличена: всё площадочное вынесено в параметры (раздел 1). Команды под вашу конфигурацию
никто не проверял — поэтому у каждого шага есть проверка «что должно получиться», а раздел 2
начинается с обследования вашего роутера. Пункты, которых на исходной площадке не было
(fasttrack, клиенты с DNS прямо на роутере), помечены отдельно.

---

## 0. Какой вариант и в каком порядке

| | **Вариант 1 — AmneziaWG** | **Вариант 2 — SSTP** |
|---|---|---|
| Как на роутере | родной WireGuard + контейнер `awg-proxy` (переупаковывает WG в AmneziaWG) | родной `sstp-client`, ничего не ставится |
| Простой при внедрении | **да**: установка пакета `container` = перезагрузка; включение `device-mode` подтверждается **кнопкой на корпусе** или холодной перезагрузкой | нет |
| Нужен человек у роутера | да | нет |
| Поведение | UDP, быстрее, нет «TCP поверх TCP» | TCP поверх TCP: на потерях проседает сильнее |
| Сторонний код на роутере | да — образ `awg-proxy` (MIT, открытый исходник); версию фиксируем, сумму сверяем | нет |
| Проходит ли у вашего провайдера | проверяется на шаге 5.6 | проверяется на шаге 6.2 |

Рекомендуемый порядок:

1. **Этап A, без простоя:** общая часть (раздел 4) + SSTP (раздел 6) → пилот на одном ПК.
2. **Этап B, окно работ, человек у роутера:** пакет `container` и `device-mode` (5.2).
3. **Этап C, без простоя:** AmneziaWG становится основным, SSTP остаётся резервом (раздел 7).

Можно сделать только один вариант: разделы 5 и 6 друг от друга не зависят, оба опираются на
раздел 4.

---

## 1. Параметры площадки

Заполните до начала. Дальше в командах они стоят в угловых скобках — подставляйте свои значения.

| Параметр | Что это | Как узнать |
|---|---|---|
| `<WAN>` | интерфейс, через который роутер ходит в интернет (`ether1`, `pppoe-out1` …) | `/ip/route/print where dst-address=0.0.0.0/0 and active` |
| `<ROUTER_IP>` | адрес роутера в локальной сети, **статический** | `/ip/address/print` |
| `<PILOT_IP>` | адрес пилотного компьютера (закрепите его в DHCP) | на ПК: `ipconfig` |
| `<DNS1>`, `<DNS2>` | DNS-серверы, которые розданы клиентам (контроллеры домена), если клиенты спрашивают не роутер | на ПК: `ipconfig /all` |
| `<VPS_IP>` | адрес VPS | — |
| `<AWG_PORT>` | UDP-порт AmneziaWG на VPS | панель → «Серверы», или `vpnctl list` на VPS |
| `<SSTP_PORT>` | TCP-порт SSTP на VPS | там же |
| `<SSTP_GW>` | адрес сервера внутри SSTP-туннеля (у контейнера панели — `10.13.0.1`) | — |
| `<DNS_CLEAN>` | внешний DNS, который роутер спрашивает **только через туннель**; не должен совпадать с вашим обычным DNS | например `1.0.0.1`, если обычный — `1.1.1.1` |
| `<FWD_ANCHOR>` | комментарий вашего правила forward «accept established, related» | раздел 2 |
| `<INPUT_ANCHOR>` | комментарий первого запрещающего правила в input | раздел 2 |

Всё, что создаёт ранбук, помечено префиксом `VPN-SEL` — по нему же делается полный откат
(раздел 10).

| Имя | Что это |
|---|---|
| `to-vpn` | таблица маршрутизации и метка соединений |
| `VPN-SEL-clients` | **кто** ходит через VPN (адреса и подсети источников) |
| `VPN-SEL-dst` | **куда** ходить через VPN (наполняется руками и из DNS) |
| `VPN-SEL-dns` | кому разрешено спрашивать DNS у роутера |
| `VPN-SEL-OUT` | список интерфейсов-туннелей |
| `wg-awg`, `veth-awg`, контейнер `awg-proxy` | вариант 1 |
| `sstp-vps` | вариант 2 |

Если привычнее Cisco: address-list ≈ `object-group network`; mangle `mark-routing` + своя
таблица ≈ PBR (`route-map … set ip next-hop`); masquerade ≈ `ip nat inside source … overload`.
У `/ip dns static type=FWD address-list=` прямого аналога в IOS нет: роутер сам кладёт в список
адреса из DNS-ответов по нужным доменам.

---

## 2. Обследование роутера: команда → что смотреть → что из этого следует

Все команды только читают. Запишите ответы — от них зависит, какие шаги вам нужны.

| Команда | Что смотреть | Следствие |
|---|---|---|
| `/system/resource/print` | `version`, `architecture-name`, `free-hdd-space` | версия определяет формат образа и синтаксис (5.3, 5.5); архитектура — какой файл качать; образ меньше 1 МБ |
| `/system/package/print` | есть ли `container` | нет — нужен этап B (5.2) |
| `/system/device-mode/print` | `container: yes/no` | `no` — нужен этап B |
| `/ip/route/print where dst-address=0.0.0.0/0` | активный шлюз | это `<WAN>` |
| `/interface/print where name=<WAN>` | `mtu` / `actual-mtu` | PPPoE обычно 1492, Ethernet 1500; MTU туннеля 1400 подходит в обоих случаях |
| `/routing/table/print`, `/routing/rule/print` | свои таблицы и правила | имя `to-vpn` не должно быть занято; есть `/routing rule` — убедитесь, что они не перехватывают адреса клиентов раньше |
| `/ip/firewall/mangle/print where chain=prerouting` | правила, которые метят соединения | наши правила ставятся **в самый верх**: если ниже есть правило, метящее все соединения, условие «метки ещё нет» у нас иначе не сработает |
| `/ip/firewall/filter/print where action=fasttrack-connection` | есть ли fasttrack | есть — обязателен шаг 4.4, иначе помеченные соединения пойдут мимо mangle и мимо туннеля |
| `/ip/firewall/filter/print where chain=forward` | как разрешён выход в интернет и чем кончается цепочка | заканчивается на `drop` — контейнеру и клиентам нужны свои accept (4.5, 5.4); запишите комментарий правила «established, related» → `<FWD_ANCHOR>` |
| `/ip/firewall/filter/print where chain=input` | чем кончается цепочка | заканчивается на `drop` — DNS-запросы к роутеру надо разрешить явно (4.7.B); запишите комментарий первого запрещающего правила → `<INPUT_ANCHOR>` |
| `/ip/dns/print` | `servers`, `allow-remote-requests` | от этого зависит способ B в 4.7 |
| на клиентском ПК: `ipconfig /all` | кто DNS-сервер клиента | роутер → способ B1; контроллер домена или другой сервер → способ B2 |

---

## 3. Правила применения

* **Резервная копия перед началом:**
  ```
  /export file=before-vpn-sel
  /system/backup/save name=before-vpn-sel
  ```
  Скачайте оба файла с роутера.
* **Safe mode.** Каждый блок: `Ctrl-X` (вход в safe mode) → вставить → проверить → `Ctrl-X`
  (зафиксировать). Оборвалась сессия — RouterOS сам откатит блок. У safe mode есть предел на
  число изменений, поэтому длинные списки доменов и адресов (4.7) вставляйте **вне** safe mode —
  сами по себе они безвредны.
* **Комментарии в командах — только латиницей.** Кириллица в comment на части версий
  превращается в мусор, а по комментариям здесь ищутся правила.
* **Правила — по comment, не по номерам.** Номера меняются при любой правке соседями.
* **Одна правка за окно.** Не совмещайте этап B с обновлением RouterOS или RouterBOOT.

---

## 4. Общая часть (одна для обоих вариантов, без простоя)

Этот блок **сам по себе трафик не меняет**: в таблице `to-vpn` пока только «запасной» маршрут
через тот же `<WAN>`. Туннель включается позже одной строкой маршрута (5.7 / 6.3).

### 4.1 Списки

```
# KTO idet v VPN. Nachinaem s odnogo PK, potom rasshiryaem (razdel 9).
/ip/firewall/address-list/add list=VPN-SEL-clients address=<PILOT_IP> comment="VPN-SEL: pilot PC"

# Interfeisy-tunneli (uchastniki dobavyatsya v 5.5 / 6.2)
/interface/list/add name=VPN-SEL-OUT comment="VPN-SEL: selective vpn tunnels"
```

`VPN-SEL-dst` создаётся сам с первой записью (4.7).

### 4.2 Таблица маршрутизации и «запасной» маршрут

```
/routing/table/add name=to-vpn fib comment="VPN-SEL"
/ip/route/add dst-address=0.0.0.0/0 gateway=<WAN> routing-table=to-vpn distance=20 \
    comment="VPN-SEL: fallback direct"
```

Если ваш выход в интернет — не интерфейс «точка-точка» (PPPoE, LTE), а Ethernet со шлюзом,
в `gateway=` укажите **адрес шлюза провайдера**, а не имя интерфейса.

Зачем запасной маршрут: пока туннель жив, работает маршрут через него (distance 1 или 5). Упал —
трафик по списку идёт напрямую. Поведение явное и не зависит от того, как RouterOS ведёт себя
при пустой таблице. ⛔ Не добавляйте `/routing rule … action=lookup-only-in-table` для `to-vpn`:
при пустой таблице клиенты из списка остаются без сети совсем.

### 4.3 Маркировка (mangle) — в самый верх prerouting

Сначала добавляется второе правило, потом первое: оба ставятся «перед первым», поэтому в итоге
окажутся в нужном порядке. Если цепочка prerouting у вас пустая, уберите из обеих команд
`place-before=…` и добавьте правила в порядке (1), (2).

```
# (2) pakety pomechennyh soedineniy ot nashih klientov -> tablica to-vpn
/ip/firewall/mangle/add chain=prerouting action=mark-routing new-routing-mark=to-vpn passthrough=no \
    connection-mark=to-vpn src-address-list=VPN-SEL-clients \
    comment="VPN-SEL: route marked -> to-vpn" \
    place-before=[:pick [/ip/firewall/mangle/find where chain=prerouting] 0]

# (1) novoe soedinenie klienta k adresu iz spiska -> metka to-vpn
/ip/firewall/mangle/add chain=prerouting action=mark-connection new-connection-mark=to-vpn passthrough=yes \
    connection-state=new src-address-list=VPN-SEL-clients dst-address-list=VPN-SEL-dst \
    comment="VPN-SEL: mark new conn to list" \
    place-before=[:pick [/ip/firewall/mangle/find where chain=prerouting] 0]

# MSS pod MTU tunnelya (bez etogo chast saitov otkryvaetsya napolovinu)
/ip/firewall/mangle/add chain=forward action=change-mss new-mss=clamp-to-pmtu protocol=tcp tcp-flags=syn \
    out-interface-list=VPN-SEL-OUT comment="VPN-SEL: mss out"
/ip/firewall/mangle/add chain=forward action=change-mss new-mss=clamp-to-pmtu protocol=tcp tcp-flags=syn \
    in-interface-list=VPN-SEL-OUT comment="VPN-SEL: mss in"
```

**Проверка:** `/ip/firewall/mangle/print where chain=prerouting` — первым идёт
`VPN-SEL: mark new conn to list`, вторым `VPN-SEL: route marked -> to-vpn`, дальше ваши старые
правила.

Почему метим **соединение**, а не каждый пакет: запись в `VPN-SEL-dst`, пришедшая из DNS, живёт
по TTL. При пакетной маркировке соединение, начатое через туннель, после истечения записи
продолжилось бы напрямую и оборвалось. Метка соединения держит весь поток на одном пути.

### 4.4 Fasttrack — только если он у вас есть

*На исходной площадке fasttrack не было, поэтому этот шаг там не выполнялся; он следует из
того, как устроен fasttrack в RouterOS.*

Соединение, попавшее в fasttrack, идёт мимо mangle — правило (2) его пакетов не увидит, и они
уйдут напрямую. Исключите помеченные соединения из fasttrack:

```
/ip/firewall/filter/set [find where action=fasttrack-connection] connection-mark=no-mark
```

Если у правила fasttrack уже задано своё условие по `connection-mark`, не затирайте его, а
добавьте **выше** отдельное правило
`chain=forward action=accept connection-state=established,related connection-mark=to-vpn`.

**Проверка** (после включения туннеля, 5.7 / 6.3): счётчик пакетов у правила
`VPN-SEL: route marked -> to-vpn` растёт всё время, пока на пилотном ПК идёт видео, а не только
на первых пакетах.

### 4.5 NAT и firewall

```
# Vyhod v tunneli pod adresom routera v tunnele
/ip/firewall/nat/add chain=srcnat action=masquerade out-interface-list=VPN-SEL-OUT comment="VPN-SEL: masq tunnels"

# Klienty -> tunnel. Nuzhno, esli forward u vas razreshaet internet tolko cherez <WAN>
/ip/firewall/filter/add chain=forward action=accept src-address-list=VPN-SEL-clients out-interface-list=VPN-SEL-OUT \
    comment="VPN-SEL: clients -> tunnels" \
    place-before=[find where chain=forward and comment="<FWD_ANCHOR>"]
```

Входящие **новые** соединения из туннелей нигде не разрешаются: их отбросит ваш завершающий
`drop` в forward. Ответы проходят по правилу «established, related». Если завершающего `drop` в
forward у вас нет — добавьте запрет явно:

```
/ip/firewall/filter/add chain=forward action=drop connection-state=new in-interface-list=VPN-SEL-OUT \
    comment="VPN-SEL: no new from tunnels"
```

### 4.6 Запас по времени для адресов из DNS

```
/ip/dns/set address-list-extra-time=1h
```

Клиент и промежуточный DNS-сервер кэшируют ответ столько же, сколько запись живёт в списке. Без
запаса клиент успеет взять из кэша адрес, которого в списке уже нет, и пойдёт напрямую.

### 4.7 Наполнение списка `VPN-SEL-dst`

Два способа, можно оба сразу.

#### A. Статически: адреса и подсети

Для сервисов, которые ходят по «зашитым» IP без DNS, и для точечных случаев. Пример — Telegram;
актуальный список сверяйте с https://core.telegram.org/resources/cidr.txt:

```
:foreach n in={"91.108.56.0/22";"91.108.4.0/22";"91.108.8.0/22";"91.108.16.0/22";"91.108.12.0/22";"149.154.160.0/20";"91.105.192.0/23";"91.108.20.0/22";"185.76.151.0/24"} do={
  /ip/firewall/address-list/add list=VPN-SEL-dst address=$n comment="VPN-SEL: telegram"
}
```

Для веб-сервисов способ не годится: у видеохостингов и CDN адреса меняются постоянно. Для них —
способ B.

#### B. Динамически из DNS

Механика: роутер по записи `type=FWD` спрашивает `<DNS_CLEAN>` **через туннель** (провайдер не
подменит ответ), кладёт полученные адреса в `VPN-SEL-dst` и отдаёт ответ спросившему.

⚠️ Включайте **после** того, как туннель поднят (5.7 или 6.3): до этого `<DNS_CLEAN>` роутер
спрашивал бы напрямую.

Домены — только то, что реально нужно и реально недоступно. Первой строкой — проверочный сервис
«какой у меня внешний адрес», он понадобится в разделе 8:

```
:foreach d in={"ifconfig.me";"example-blocked.com";"example-cdn.net"} do={
  /ip/dns/static/add type=FWD name=$d match-subdomain=yes forward-to=<DNS_CLEAN> address-list=VPN-SEL-dst comment="VPN-SEL"
}
```

Дальше — в зависимости от того, кто DNS-сервер у клиентов (раздел 2).

**B1. Клиенты спрашивают сам роутер.** *На исходной площадке так не было — вариант не
проверялся.* Больше ничего не нужно: `allow-remote-requests` у вас уже включён. Убедитесь
только, что DNS роутера закрыт снаружи (в input нет accept на 53 с `<WAN>`).

**B2. Клиенты спрашивают контроллер домена или другой внутренний DNS.** Роутер их ответов не
видит, поэтому на внутреннем DNS для каждого домена заводится условный пересыльщик на роутер.

На роутере:

```
/ip/firewall/address-list/add list=VPN-SEL-dns address=<DNS1> comment="VPN-SEL: internal dns 1"
/ip/firewall/address-list/add list=VPN-SEL-dns address=<DNS2> comment="VPN-SEL: internal dns 2"
/ip/dns/set allow-remote-requests=yes

/ip/firewall/filter/add chain=input action=accept protocol=udp dst-port=53 src-address-list=VPN-SEL-dns \
    comment="VPN-SEL: dns from internal udp" place-before=[find where chain=input and comment="<INPUT_ANCHOR>"]
/ip/firewall/filter/add chain=input action=accept protocol=tcp dst-port=53 src-address-list=VPN-SEL-dns \
    comment="VPN-SEL: dns from internal tcp" place-before=[find where chain=input and comment="<INPUT_ANCHOR>"]
```

На контроллере домена (PowerShell от доменного администратора, один раз — зона реплицируется):

```powershell
$router = "<ROUTER_IP>"
"ifconfig.me","example-blocked.com","example-cdn.net" |
  ForEach-Object { Add-DnsServerConditionalForwarderZone -Name $_ -MasterServers $router -ReplicationScope Forest }
```

**Проверка:**

```powershell
Resolve-DnsName ifconfig.me -Server <ROUTER_IP>   # роутер отвечает
Resolve-DnsName ifconfig.me                       # тот же ответ через сам контроллер
```

Нет ответа от роутера — смотрите правила input (порядок, список `VPN-SEL-dns`) и то, с какого
адреса контроллер приходит на роутер.

Что важно понимать про B2:

* Пересыльщик действует **на всех** клиентов этого DNS, а не только на `VPN-SEL-clients`.
  Остальные получат те же ответы и пойдут напрямую. Поэтому в список — только реально
  недоступное, не общие домены и не общие CDN.
* Роутер становится зависимостью для этих доменов: роутер лежит — они не резолвятся.
* `<ROUTER_IP>` должен быть **статическим** адресом роутера.
* Домен добавляется в **двух** местах: запись FWD на роутере и зона на внутреннем DNS. Одно без
  другого не работает.
* Если сайт упорно идёт мимо — проверьте, не включён ли в браузере DNS поверх HTTPS: тогда
  браузер спрашивает не ваш DNS, и роутер адресов не видит.

---

## 5. Вариант 1 — AmneziaWG

### 5.1 Сервер: отдельный клиент для роутера

* В панели создайте **нового** клиента на нужном сервере AmneziaWG (например, «office-router») и
  скачайте его `.conf`. Если сервер ведётся приложением AmneziaVPN — «Поделиться» → протокол
  AmneziaWG, формат **AmneziaWG Format**.
* ⛔ Не берите конфиг, который уже используется на другом устройстве: один ключ с двух точек —
  пиры перебивают друг друга, и оба подключения рвутся.
* `.conf` — секрет: в нём закрытый ключ. Храните как остальные учётные данные, в переписку и в
  git не кладите.

Из `.conf` понадобятся: `[Interface]` — `PrivateKey`, `Address` и все параметры обфускации,
которые там есть; `[Peer]` — `PublicKey`, `PresharedKey` (если есть), `Endpoint`.

### 5.2 Этап B — подготовка роутера (ОКНО РАБОТ, человек у роутера)

На время перезагрузки (обычно 2–3 минуты, **дважды**) ляжет всё, что идёт через этот роутер:
интернет, туннели до филиалов, удалённые пользователи. Заранее выпишите, что именно, и
предупредите людей. Особое внимание — филиалам, у которых нет второго канала.

1. С mikrotik.com скачайте архив «Extra packages» **ровно той версии и архитектуры**, что в
   `/system/resource/print`, достаньте из него `container-<версия>-<архитектура>.npk`.
2. Winbox → Files → загрузить `.npk` в корень → `/system/reboot`.
   **Проверка:** `/system/package/print` — `container` в списке, без флага `X`.
3. Включите контейнеры:
   ```
   /system/device-mode/update container=yes
   ```
   RouterOS даст несколько минут на подтверждение: **короткое нажатие кнопки Reset/Mode на
   корпусе** либо холодная перезагрузка (снять питание). ⛔ Кнопку не удерживать: долгое
   удержание — это сброс конфигурации.
   **Проверка:** `/system/device-mode/print` → `container: yes`.

### 5.3 Образ контейнера

Проект `timbrs/amneziawg-mikrotik-c` (C, MIT): https://github.com/timbrs/amneziawg-mikrotik-c
Контейнер не шифрует — шифрует родной WireGuard роутера; контейнер только переупаковывает пакеты
в формат AmneziaWG.

Какой файл брать (по README проекта на 12.10.2026):

| RouterOS | Файл |
|---|---|
| 7.21 и новее | `awg-proxy-<arch>.tar.gz` |
| 7.20 и старше | `awg-proxy-<arch>-7.20-Docker.tar.gz` |

`<arch>` — по `architecture-name`: `arm64`, `arm`, `armv5`, `amd64`.

Правила выбора версии:

* не ставьте на ядро сборку, которой меньше недели, — берите предыдущий выпуск;
* запишите версию и sha256 файла (`Get-FileHash <файл> -Algorithm SHA256` или `sha256sum`) в
  свою документацию — при обновлении и при разборе инцидента будет с чем сверить;
* если на сервере AmneziaWG нового поколения (в `.conf` есть `S3`/`S4`, `I1`–`I5`,
  `HeaderProtectionKey`) — убедитесь по README выбранного выпуска, что он это поколение
  поддерживает.

Загрузите файл в Files роутера.

### 5.4 Сеть контейнера и firewall

Подсеть `172.18.0.0/30` не должна пересекаться с вашими.

```
/interface/veth/add name=veth-awg address=172.18.0.2/30 gateway=172.18.0.1 comment="VPN-SEL"
/ip/address/add address=172.18.0.1/30 interface=veth-awg comment="VPN-SEL: veth-awg"

# Konteiner -> server AWG. Bez etogo pravila ego pakety otbrosit zavershayushchiy drop v forward
/ip/firewall/filter/add chain=forward action=accept protocol=udp src-address=172.18.0.2 out-interface=<WAN> \
    comment="VPN-SEL: awg-proxy -> internet" \
    place-before=[find where chain=forward and comment="<FWD_ANCHOR>"]
```

Отдельный NAT контейнеру нужен, только если ваш masquerade ограничен списком исходных подсетей:
тогда добавьте в него `172.18.0.0/30`. Если masquerade стоит просто на `out-interface=<WAN>`,
он контейнер уже покрывает.

### 5.5 WireGuard на роутере

```
/interface/wireguard/add name=wg-awg listen-port=51821 mtu=1400 private-key="<PrivateKey>" comment="VPN-SEL"
/interface/wireguard/peers/add interface=wg-awg public-key="<PublicKey servera>" preshared-key="<PresharedKey>" \
    endpoint-address=172.18.0.2 endpoint-port=51820 allowed-address=0.0.0.0/0 persistent-keepalive=25s \
    comment="VPN-SEL: awg-vps"
/ip/address/add address=<Address iz .conf> interface=wg-awg comment="VPN-SEL: wg-awg"
/interface/list/member/add list=VPN-SEL-OUT interface=wg-awg comment="VPN-SEL"
```

Нет `PresharedKey` в `.conf` — уберите `preshared-key=…` из команды. Порт 51821 не должен быть
занят другим WireGuard-интерфейсом.

`allowed-address=0.0.0.0/0` в RouterOS **не создаёт маршрутов** (в отличие от `wg-quick` на
Linux), поэтому весь трафик в туннель сам не уйдёт. Маршруты — только те, что добавим в 5.7.

### 5.6 Переменные и запуск контейнера

Имя параметра списка переменных зависит от версии: на 7.20 и старше — `name=`, на 7.21+ —
`list=`. Проверьте подсказкой: `/container/envs/add ?`.

```
/container/envs/add name=awg-env key=AWG_LISTEN     value=":51820"
/container/envs/add name=awg-env key=AWG_REMOTE     value="<VPS_IP>:<AWG_PORT>"
/container/envs/add name=awg-env key=AWG_JC         value="<Jc>"
/container/envs/add name=awg-env key=AWG_JMIN       value="<Jmin>"
/container/envs/add name=awg-env key=AWG_JMAX       value="<Jmax>"
/container/envs/add name=awg-env key=AWG_S1         value="<S1>"
/container/envs/add name=awg-env key=AWG_S2         value="<S2>"
/container/envs/add name=awg-env key=AWG_H1         value="<H1>"
/container/envs/add name=awg-env key=AWG_H2         value="<H2>"
/container/envs/add name=awg-env key=AWG_H3         value="<H3>"
/container/envs/add name=awg-env key=AWG_H4         value="<H4>"
/container/envs/add name=awg-env key=AWG_SERVER_PUB value="<PublicKey servera>"
/container/envs/add name=awg-env key=AWG_CLIENT_PUB value=[/interface/wireguard/get [find name=wg-awg] public-key]
```

Если в `.conf` есть параметры новых поколений — добавьте их теми же командами (имена — из
таблицы переменных в README проекта):

| В `.conf` | Переменная |
|---|---|
| `S3`, `S4` | `AWG_S3`, `AWG_S4` |
| `I1` … `I5` | `AWG_I1` … `AWG_I5` |
| `HeaderProtectionKey` | `AWG_HEADER_PROTECTION_KEY` |

```
/container/add file=<imya faila obraza> interface=veth-awg envlist=awg-env \
    hostname=awg-proxy root-dir=awg-proxy logging=yes start-on-boot=yes comment="VPN-SEL"
```

Дождитесь распаковки (`/container/print` → статус `stopped`), затем
`/container/start [find where hostname=awg-proxy]`.

Параметры обфускации обязаны совпадать с `.conf` **знак в знак**. Разошлись — рукопожатия не
будет вовсе при внешне исправной настройке.

**Проверка:**

| Команда | Норма | Если не так |
|---|---|---|
| `/container/print` | `running` | `/log/print where topics~"container"` — ошибка распаковки или формата образа (5.3) |
| `/interface/wireguard/peers/print detail where comment="VPN-SEL: awg-vps"` | `last-handshake` меньше 2 минут, `rx` и `tx` растут | `tx` растёт, `rx` = 0 — сверить параметры обфускации и ключи; затем правило forward из 5.4; затем — доходит ли UDP до сервера (на VPS: `tcpdump -ni any udp port <AWG_PORT>`). Пакеты до сервера не доходят — провайдер режет этот UDP, пробуйте другой порт или вариант 2 |

### 5.7 Включить туннель в схему

```
/ip/route/add dst-address=0.0.0.0/0 gateway=wg-awg routing-table=to-vpn distance=1 comment="VPN-SEL: awg default"
/ip/route/add dst-address=<DNS_CLEAN>/32 gateway=wg-awg distance=1 comment="VPN-SEL: awg clean dns"
```

С этой секунды пилотный ПК ходит к адресам из списка через AmneziaWG. Теперь включайте 4.7.B.

### 5.8 Проверка живости: рукопожатие, а не ping

Интерфейс WireGuard в RouterOS всегда «running», поэтому маршрут через него сам не гаснет при
мёртвом сервере. Признак живого туннеля — **свежее криптографическое рукопожатие с сервером**.
При `persistent-keepalive` оно обновляется примерно раз в две минуты. Старше четырёх минут —
туннель мёртв: скрипт выключает маршруты `VPN-SEL: awg*`, и трафик уходит в SSTP (если есть) или
напрямую.

Сначала проверьте тип значения — иначе скрипт будет считать туннель мёртвым всегда:

```
:put [:typeof [/interface/wireguard/peers/get [find comment="VPN-SEL: awg-vps"] last-handshake]]
```

Должно быть `time`. Затем:

```
/system/script/add name=vpn-sel-health policy=read,write,test comment="VPN-SEL" source={
  :local p [/interface/wireguard/peers/find where comment="VPN-SEL: awg-vps"]
  :local hs [/interface/wireguard/peers/get $p last-handshake]
  :local ok false
  :if ([:typeof $hs] = "time") do={ :if ($hs < 00:04:00) do={ :set ok true } }
  :foreach r in=[/ip/route/find where comment~"^VPN-SEL: awg"] do={
    :local dis [/ip/route/get $r disabled]
    :if ($ok && $dis) do={ /ip/route/enable $r; :log warning "VPN-SEL: awg up, route enabled" }
    :if (!$ok && !$dis) do={ /ip/route/disable $r; :log warning "VPN-SEL: awg handshake stale, route disabled" }
  }
}
/system/scheduler/add name=vpn-sel-health interval=30s on-event=vpn-sel-health policy=read,write,test comment="VPN-SEL"
```

---

## 6. Вариант 2 — SSTP

### 6.1 Сервер: отдельный логин для роутера

Создайте в панели отдельного клиента SSTP для роутера (логин и пароль выдаст панель). Общий
логин с другим устройством использовать нельзя: сервер держит одну сессию на логин, и
подключения будут выбивать друг друга. Пароль — в хранилище секретов, не в переписку.

### 6.2 Роутер: клиент SSTP (он же проверка, проходит ли SSTP у вашего провайдера)

```
/interface/sstp-client/add name=sstp-vps connect-to=<VPS_IP> port=<SSTP_PORT> \
    user=<login> password="<parol>" authentication=mschap2 \
    certificate=none verify-server-certificate=no \
    add-default-route=no profile=default-encryption disabled=no comment="VPN-SEL"
/interface/list/member/add list=VPN-SEL-OUT interface=sstp-vps comment="VPN-SEL"
```

Само по себе это ничего не маршрутизирует (`add-default-route=no`).

Если у сервера настоящий сертификат на доменное имя — подключайтесь по имени
(`connect-to=<имя>`) и включите `verify-server-certificate=yes`. С самоподписанным сертификатом
проверка выключена, и защита держится на жёстко прописанном адресе сервера.

**Проверка:**

| Команда | Норма | Если не так |
|---|---|---|
| `/interface/sstp-client/monitor sstp-vps once` | `status: connected` | висит в `connecting`, в `/log/print where topics~"sstp"` пусто или `could not connect` — провайдер режет TCP к этому адресу и порту: пробуйте порт 443 или другой VPS |
| `/ping <SSTP_GW> count=4` | ответы есть | — |
| на сервере — раздел «Клиенты» панели | клиент роутера на связи | `terminated by remote peer` в логе роутера — сервер отказал: логин или пароль |

### 6.3 Включить в схему

Если SSTP — **единственный** вариант:

```
/ip/route/add dst-address=0.0.0.0/0 gateway=sstp-vps routing-table=to-vpn distance=1 comment="VPN-SEL: sstp default"
/ip/route/add dst-address=<DNS_CLEAN>/32 gateway=sstp-vps distance=1 comment="VPN-SEL: sstp clean dns"
```

Если SSTP — **резерв к AmneziaWG** (раздел 7), то `distance=5` в обеих строках.

Скрипт живости для SSTP не нужен: при обрыве интерфейс гаснет, маршрут через него становится
неактивным, и включается следующий по distance.

---

## 7. Оба сразу: AmneziaWG основной, SSTP резерв

| Маршрут в `to-vpn` | distance | Когда работает |
|---|---|---|
| `VPN-SEL: awg default` | 1 | рукопожатие AmneziaWG свежее (скрипт 5.8) |
| `VPN-SEL: sstp default` | 5 | AmneziaWG выключен скриптом, SSTP подключён |
| `VPN-SEL: fallback direct` | 20 | оба туннеля лежат — трафик по списку идёт напрямую |

Так же устроен маршрут до `<DNS_CLEAN>/32` в основной таблице (1 / 5 / обычный default).

Соединения, открытые через один туннель, при переключении рвутся и открываются заново через
следующий. Для веба и видео это незаметно.

---

## 8. Проверка после внедрения

Снимите `/system/resource/cpu/print` **до** начала и после — сравните.

| Что | Команда | Норма |
|---|---|---|
| Туннель AmneziaWG жив | `/interface/wireguard/peers/print detail where comment~"VPN-SEL"` | `last-handshake` меньше 2 минут, rx и tx растут |
| Контейнер | `/container/print` | `running` |
| SSTP жив | `/interface/sstp-client/monitor sstp-vps once` | `connected` |
| Активный маршрут | `/ip/route/print where routing-table=to-vpn` | флаг `A` у awg (или sstp), `fallback direct` неактивен |
| Список наполняется | `/ip/firewall/address-list/print where list=VPN-SEL-dst and dynamic` | адреса с именем домена в комментарии |
| Соединения метятся | `/ip/firewall/connection/print count-only where connection-mark=to-vpn` | больше 0 при открытом сайте на пилоте |
| **Путь на пилоте** | на пилотном ПК: `curl https://ifconfig.me` | **адрес VPS** |
| **Остальные не задеты** | на любом другом ПК: `curl https://ifconfig.me` | **ваш обычный внешний адрес** |
| Обычный сайт на пилоте | на пилотном ПК — любой сервис «мой IP», которого нет в списке | ваш обычный внешний адрес |
| Резерв | `/container/stop [find where hostname=awg-proxy]`, подождать 4–5 минут | в логе `awg handshake stale`, активен маршрут sstp, пилот по-прежнему видит адрес VPS; потом `/container/start …` |

Пилот видит обычный адрес вместо адреса VPS — по порядку: есть ли адрес `ifconfig.me` в
`VPN-SEL-dst`; растёт ли счётчик правила `VPN-SEL: mark new conn to list`; не уходит ли
соединение в fasttrack (4.4); активен ли маршрут туннеля в `to-vpn`.

---

## 9. Эксплуатация

**Добавить домен** — оба места обязательно (при способе B2):

```
/ip/dns/static/add type=FWD name=example.com match-subdomain=yes forward-to=<DNS_CLEAN> address-list=VPN-SEL-dst comment="VPN-SEL"
```
```powershell
Add-DnsServerConditionalForwarderZone -Name example.com -MasterServers <ROUTER_IP> -ReplicationScope Forest
```

Потом на клиенте `ipconfig /flushdns`, на контроллере — `Clear-DnsServerCache` (или дождаться
TTL).

**Добавить адрес или подсеть:**
`/ip/firewall/address-list/add list=VPN-SEL-dst address=… comment="VPN-SEL: <chto, latinicey>"`

**Расширить круг пользователей** (после пилота): в `VPN-SEL-clients` — адрес ПК или подсеть
целиком. Серверы, телефонию и сегменты с чувствительными данными туда без отдельного решения не
включать.

**Весь трафик одного ПК в VPN** — отдельное правило, только если действительно нужно:

```
/ip/firewall/address-list/add list=VPN-SEL-local address=10.0.0.0/8      comment="VPN-SEL"
/ip/firewall/address-list/add list=VPN-SEL-local address=172.16.0.0/12   comment="VPN-SEL"
/ip/firewall/address-list/add list=VPN-SEL-local address=192.168.0.0/16  comment="VPN-SEL"
/ip/firewall/mangle/add chain=prerouting action=mark-connection new-connection-mark=to-vpn passthrough=yes \
    connection-state=new src-address-list=VPN-SEL-force dst-address-list=!VPN-SEL-local \
    comment="VPN-SEL: force device" place-before=[find where comment="VPN-SEL: route marked -> to-vpn"]
/ip/firewall/address-list/add list=VPN-SEL-force   address=<IP PK> comment="VPN-SEL: <kto, latinicey>"
/ip/firewall/address-list/add list=VPN-SEL-clients address=<IP PK> comment="VPN-SEL: <kto, latinicey>"
```

Такой ПК выглядит зарубежным для банков и государственных сервисов.

**Обновить `awg-proxy`:** новый файл → `/container/stop`, `/container/remove`, `/container/add`
с новым `file=` (переменные `awg-env` остаются). Версию и sha256 записать.

**После обновления RouterOS** пакет `container` обновляется вместе с системой; проверьте
`/container/print` → `running` и рукопожатие. При переходе с 7.20 на 7.21+ меняется формат
образа (5.3) — образ придётся заменить.

---

## 10. Откат (полный, по comment)

Порядок: сначала перестать метить, потом убрать пути.

```
/system/scheduler/remove [find where name=vpn-sel-health]
/system/script/remove    [find where name=vpn-sel-health]
/ip/firewall/mangle/remove [find where comment~"^VPN-SEL"]
/ip/firewall/filter/remove [find where comment~"^VPN-SEL"]
/ip/firewall/nat/remove    [find where comment~"^VPN-SEL"]
/ip/route/remove           [find where comment~"^VPN-SEL"]
/ip/dns/static/remove      [find where comment~"^VPN-SEL"]
/ip/firewall/address-list/remove [find where list~"^VPN-SEL"]
/container/stop   [find where hostname=awg-proxy]
/container/remove [find where hostname=awg-proxy]
/container/envs/remove [find where name=awg-env]
/interface/list/member/remove [find where list=VPN-SEL-OUT]
/interface/list/remove [find where name=VPN-SEL-OUT]
/interface/sstp-client/remove [find where name=sstp-vps]
/interface/wireguard/remove   [find where name=wg-awg]
/ip/address/remove [find where comment~"^VPN-SEL"]
/interface/veth/remove [find where name=veth-awg]
/routing/table/remove [find where name=to-vpn]
```

На 7.21+ строка с переменными — `/container/envs/remove [find where list=awg-env]`.

Что вернуть руками — к значениям из вашей резервной копии:

* `/ip/dns/set address-list-extra-time=…` и, если включали в B2, `allow-remote-requests=no`;
* условие `connection-mark=no-mark` у правила fasttrack (4.4) можно оставить — без меток оно
  ни на что не влияет.

На внутреннем DNS: `Remove-DnsServerZone -Name <домен> -Force` для каждого пересыльщика.
⚠️ **Обязательно:** иначе он продолжит спрашивать роутер, который больше не отвечает, и эти
домены перестанут резолвиться у всех.

На сервере: удалите клиентов роутера (AmneziaWG и SSTP) в панели.

Пакет `container` и `device-mode` можно оставить — без контейнеров они ничего не делают.

---

## 11. Что решить до внедрения

1. **Кто в VPN.** Ранбук стартует с одного пилотного ПК. Какие люди и подсети дальше — решение
   руководителя площадки, не администратора.
2. **Какие домены.** Только реально недоступное и нужное для работы. При способе B2 пересыльщик
   действует на весь домен Active Directory.
3. **Сервер.** Видео нескольких десятков человек заметно нагрузит VPS с одним ядром. Считайте
   поток заранее; чем ближе сервер географически, тем меньше задержка. В список адресов не
   должно попадать ничего с персональными и иными охраняемыми данными.
4. **Окно для этапа B.** Ночь или выходной, человек у роутера, список того, что ляжет на время
   двух перезагрузок.
5. **Сторонний образ на ядре сети.** `awg-proxy` открытый и маленький, но это чужой код в
   контейнере на центральном роутере. Версия фиксируется, сумма сверяется; собрать из исходников
   самостоятельно — тоже вариант.

---

### Источники

* awg-proxy: https://github.com/timbrs/amneziawg-mikrotik-c — README и выпуски
* RouterOS Container: https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container
* Адреса Telegram: https://core.telegram.org/resources/cidr.txt
* Сервер: эта панель — [QUICKSTART](QUICKSTART.md)
