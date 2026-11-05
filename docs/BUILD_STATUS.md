# Veil: фактичний статус перевірок

Дата: 2026-11-05. Середовище: Ubuntu Linux x86_64, Python 3.14.4.

| Компонент | Статус |
|---|---|
| Relay HTTP + SQLite | **54 тести пройшли**, повторно запущені основним агентом |
| Relay executable package | `dist/veil-relay.pyz`, Python zipapp; це не нативний ELF і не мобільний застосунок |
| Android APK | **Зібрано, debug-підпис APK v2 перевірений**; Android 8+, 4 ABI, не production release |
| Android JVM тести | **32/32 passed**, примусово повторно запущені основним агентом, реальний libsignal 0.106.0 Linux JNI |
| Android lint | **0 errors**, 38 warnings; lint не вимкнений |
| iOS compile / XCTest / IPA | **Не виконано:** на хості немає macOS, Xcode та iOS SDK |
| Swift source syntax | **22 файли** пройшли `swiftc -frontend -parse` (Swift 6.1.3 Linux); це не typecheck SwiftUI чи iOS build |
| iOS dependency pin | Commit podspec та SHA-256 звірені з офіційним upstream/release checksum asset; FFI на iOS не запускався |
| Build helpers | Bash/Python/Ruby Podfile syntax перевірені; plist/YAML коректно розбираються |
| Source ZIP filter | 1 автоматичний тест: не включає keys, tokens/env-файли, БД, symlinks та кеші |
| Swift URL/handle policy | **36 assertions у Debug + 36 у Release**, виконані інтерпретатором Swift на справжньому Linux Foundation; не iOS runtime |
| Device tests iOS ↔ Android | Не виконано |
| Криптографічний аудит / load test 10k | Не виконано |
| Публічний relay / TestFlight / Play | Не розгорнуто / не опубліковано |

## Relay

```sh
python3 -m unittest discover -s server/tests -t server -v
# Ran 54 tests in 5.218s — OK
```

Перевірено на реальних loopback HTTP-сокетах і SQLite: auth, валідацію ключів/JSON, атомарне споживання prekeys під конкуренцією, заборону повторного завантаження спожитих ids, незмінність identity, idempotent retry включно після ACK, колізії ids в inbox, чужі ACK, quotas/rate limits, TTL/startup/idle purge, відсутність plaintext content у relay, права БД і відмову від symlink, неінвазивні права існуючого каталогу, міграцію схеми та запуск зібраного zipapp.

Ці тести **не перевіряють** клієнтську Signal-криптографію або iPhone/Android runtime.

## iOS: внутрішня перевірка вихідних кодів

Основний агент виконав синтаксичний розбір усіх 22 Swift-файлів і перевірку Podfile (`ruby -c`). Виявлені під час огляду помилки виправлено, включно з loopback-host перевіркою, пінуванням доданого контакту **до** першого вхідного TOFU, межами response/plaintext, і порядком commit/ACK.

XCTest-кейси написані, **не виконані**. Окремі Linux-перевірки агента зі стаб-модулями/підміною AES — лише допоміжна перевірка state machine, **не** результати криптографічних тестів, не доказ роботи Keychain/AES/libsignal і не iOS-компіляція. Стаби не входять до production-коду чи APK.

## Android: реальні перевірки

Основний агент виконав `assembleDebug testDebugUnitTest lintDebug --rerun-tasks`: **51 tasks executed, BUILD SUCCESSFUL**. Розподіл тестів: 18 Signal protocol tests, 7 pure logic, 6 vault/transaction (JCE AES-GCM із тестовим ключем у RAM), 1 живий HTTP integration test. Використано офіційні артефакти **0.106.0** з `https://build-artifacts.signal.org/libraries/maven/`, як у Swift pin; не застарілий Maven Central pin 0.86.5.

HTTP integration test реально запускає Python relay із приватною SQLite на loopback, реєструє два JVM-клієнти, використовує **клієнтські Android Java RelayClient + SignalEngine**, перевіряє E2EE-текст, відповідь, офлайн-чергу, однаковий retry, ACK/tombstone та відсутність plaintext у relay SQLite/WAL. Це не тест Android UI чи Android Keystore на пристрої й не iOS ↔ Android device test.

`apksigner verify --verbose --print-certs` підтвердив APK v2 signature, signer **Android Debug**. SHA-256 сертифіката: `d96e4eac7db5806365d7453529ed92f6c8536991cfcb0ec366925ea8aa0bf05b`. Це публічний відбиток development-сертифіката, не приватний ключ. APK містить лише production `libsignal_jni.so` для `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`; `libsignal_jni_testing.so` відсутній.

Фінальний APK: **124 338 076 байтів (118.6 MiB)**. SHA-256: `e5a0ec0c2a0dc10a3600f7298c9667fe05668ef14fff1fdec6aae59e16cd8dd0`. Повний AGPL-текст є також в assets APK; автоматичне завантаження emoji-шрифтів вимкнене. Фінальна зміна manifest/legal UI повторно пройшла assemble/test/lint. У логах AGP 8.7 lint є діагностика старого Kotlin analyzer щодо metadata 2.2 у залежностях; Java-компіляція, реальні JVM-тести й app lint report успішні. Перед production потрібно оновити й узгодити lint/AGP toolchain, а не приховувати діагностику.

**На фізичний Android/емулятор APK не встановлювався.** Перевірка GUI, Android Keystore, backup rules на реальному пристрої та background behavior ще потрібна. Debuggable development APK не слід використовувати для секретів.

## Межа готовності

Успішна компіляція APK сама по собі не доводить безпеку, коректність Android Keystore чи iOS-сумісність. Розмежування source / compiled / signed / tested є навмисним: відсутні результати не замінюються припущеннями.
