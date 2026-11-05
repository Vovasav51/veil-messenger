# Veil: фактичне розгортання на academy-450cc5

## Запущено

- Системний сервіс **`veil-relay.service`**: active/running, enabled.
- Процес запускається через systemd `DynamicUser=yes`, без root-прав.
- API слухає **лише `127.0.0.1:8787`**. Цю адресу не можна вписувати в застосунок на іншому пристрої.
- `GET http://127.0.0.1:8787/health` перевірено: HTTP 200, `{"status":"ok","version":"0.1.0"}`.
- Виконуваний пакет: `/opt/veil-relay/veil-relay.pyz`.
- Unit: `/etc/systemd/system/veil-relay.service`; вихідна копія — `deploy/veil-relay.service`.
- StateDirectory: `/var/lib/veil-relay` (systemd керує приватним/id-mapped каталогом). Каталог `0700`, SQLite `0600`; побачений зовні власник `nobody` є наслідком id-mapped DynamicUser, не публічним доступом.
- Сервіс обмежений `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, без capabilities; ліміт RAM 256 MiB і 96 tasks.
- Firewall, чужі web-сервіси й роутер не змінювалися. Публічний HTTPS endpoint ще не налаштовано.

```sh
systemctl status veil-relay.service --no-pager
curl --fail http://127.0.0.1:8787/health
sudo systemctl restart veil-relay.service
sudo systemctl stop veil-relay.service
```

Не публікуйте auth/body/access logs. Журнал unit містить лише startup і санітизовані помилки реалізації.

## Постійний доступ для майбутніх користувачів — ще не налаштовано

Потрібен постійний hostname з HTTPS і контроль DNS. Варіанти:

1. Власний домен + named tunnel із постійною адресою до loopback relay. Домен/тунель належать користувачу; сторонній TLS proxy бачить HTTP-метадані й bearer-токени. Потрібна згода на такий шлях і авторизація в обраного провайдера.
2. Власний домен + публічна адреса/VPS + HTTPS reverse proxy. DNS, доступність портів та оплата VPS/домену погоджуються окремо. На цьому хості порт 80 уже зайнятий іншим сервісом; його не можна займати або переналаштовувати без перевірки.

Тимчасовий випадковий tunnel hostname не є постійним рішенням і не видається за таке. DHCP LAN-адреса також не є публічною адресою для всіх користувачів.

Комп'ютер із relay має бути постійно увімкнений і підключений до інтернету. Цей неаудитований MVP не стає production-системою від самого налаштування домену; перед публічним запуском потрібні anti-abuse/registration gating, моніторинг без секретних логів і перевірка клієнтського recovery/операційних обмежень.

## iPhone / GitHub

Користувач дозволив новий **приватний** GitHub-репозиторій і macOS Actions лише в межах включеної квоти. Поточний GitHub MCP автентифікований як `Vovasav51`, але `POST /user/repos` для `veil-messenger` отримав **403 Resource not accessible by personal access token**. Репозиторій цією спробою не створено; жодної віддаленої збірки або оплати не запускалося.

Потрібно створити приватний репозиторій через GitHub і дати інтеграції мінімальний доступ саме до нього (`Contents`/`Workflows`; для керування workflow — `Actions`), або авторизувати GitHub CLI у власному терміналі. Не передавати PAT, паролі, Apple ID/2FA чи сертифікати в чат.

Квота/бюджет GitHub Actions мають бути перевірені перед запуском macOS runner: доступність API не доводить наявність безкоштовних хвилин. Звичайний Apple ID не надає TestFlight; unsigned archive із CI не є встановлюваним IPA. Для персонального встановлення потрібен легітимний signing-flow з участю власника акаунта (найпростіше — Xcode на Mac).
