# Збірка Veil для iPhone

> **Стан на 2026-11-05:** цей проєкт створено на Linux. На хості **немає macOS, Xcode та iOS SDK**, тому жоден рядок iOS-коду ще не скомпільований, XCTest не виконувався, `.ipa` не існує. Усе нижче — це *готовий до запуску* конвеєр, а не доказ зеленої збірки. Перший реальний прогін на Mac або в GitHub Actions є обов'язковим кроком.

## Що саме перевірено, а що ні

| Твердження | Статус | Як перевірити |
|---|---|---|
| Синтаксис `scripts/ios-build.sh`, `scripts/ios-ci-sign.sh` | **Перевірено** на Linux (`bash -n`, `shellcheck -S warning`, 0 зауважень) | `bash -n scripts/ios-build.sh && shellcheck -S warning -x scripts/*.sh` |
| Логіка гілок скриптів (unsigned-перевірка, відмова при чужому team/bundle/типі профілю, прибирання keychain) | **Перевірено зі стабами** `xcodebuild`/`security`/`codesign`/`plutil` на Linux, 27 сценаріїв, 27/27 | це перевірка керувальної логіки, **не** справжня збірка чи підпис |
| `.github/workflows/ios.yml` — валідний YAML, 3 jobs, manual-only | **Перевірено** (PyYAML) | `python3 -c "import yaml;yaml.safe_load(open('.github/workflows/ios.yml'))"` |
| `ios/ExportOptions.example.plist` — валідний plist, лише плейсхолдери | **Перевірено** (`plistlib`) | `python3 -c "import plistlib;plistlib.load(open('ios/ExportOptions.example.plist','rb'))"` |
| Swift-код компілюється під iOS SDK | **Не перевірено** — потрібен macOS | job `simulator` / `device-unsigned` |
| XCTest проходять | **Не перевірено** | job `simulator` (крок XCTest) |
| Release-конфігурація лінкується під arm64 device | **Не перевірено** | job `device-unsigned` |
| Підписаний IPA встановлюється на iPhone | **Не перевірено** і не може бути перевірено без Apple-акаунта | job `signed-export` + фізичний пристрій |
| Двопристроєве тестування iOS ↔ Android | **Не виконано** | ручний чекліст нижче |

Скрипт `scripts/ios-build.sh` навмисно завершується з кодом 2 на не-Darwin:

```
[veil-ios] ERROR: iOS builds require macOS with Xcode and the iOS SDK.
```

Це захист від спокуси зібрати «схоже на IPA» на Linux. Скомпільований на Linux бінарник не є iOS-застосунком.

---

## Три шляхи до застосунку на iPhone

### 1. Локальний Xcode (рекомендовано для першого запуску)

Найдешевший і найзрозуміліший шлях. Безкоштовний Apple ID (Personal Team) підписує застосунок на 7 днів і до 3 пристроїв — достатньо, щоб перевірити, що код взагалі збирається і працює.

1. Встановити Xcode з App Store, відкрити його один раз, прийняти ліцензію, дочекатися встановлення iOS-платформи (Settings → Components).
2. `brew install xcodegen cocoapods` (або `scripts/ios-build.sh` сам скаже, чого не вистачає).
3. З кореня репозиторію: `bash scripts/ios-build.sh prepare`, далі `open ios/Veil.xcworkspace` (**не** `.xcodeproj`).
4. У Xcode: таргет **Veil** → Signing & Capabilities → команда = ваш Personal Team, Bundle Identifier = унікальний (наприклад `com.vashaprizvyshche.veil`).
5. Підключити iPhone, увімкнути Developer Mode (Settings → Privacy & Security), вибрати пристрій → Run.
6. Trust the developer: Settings → General → VPN & Device Management.

Relay має бути доступний з iPhone по **HTTPS із довіреним сертифікатом**. `127.0.0.1` на iPhone — це сам iPhone. Release-конфігурація не має винятку для відкритого HTTP; не вимикайте перевірку TLS, щоб «завести» self-signed сертифікат.

### 2. Локальний CLI (`scripts/ios-build.sh`)

| Команда | Що робить | Результат |
|---|---|---|
| `prepare` | `xcodegen generate` + `pod install` (з `--deployment`, якщо є `Podfile.lock`) | `ios/Veil.xcworkspace` |
| `simulator` | Debug-збірка під `generic/platform=iOS Simulator` | `build/DerivedData/.../Debug-iphonesimulator/Veil.app` — **тільки симулятор** |
| `test` | Debug + XCTest на конкретному симуляторі | `build/TestResults-<timestamp>.xcresult` |
| `device-unsigned` | Release-архів під `generic/platform=iOS`, підпис **повністю вимкнено** | `build/Veil-unsigned.xcarchive` — **не встановлюється** |
| `archive` | Release-архів із реальним підписом | `build/Veil.xcarchive` |
| `export` | Експорт IPA з архіву за `ExportOptions.plist` | `build/export/*.ipa` |
| `third-party-sources` | AGPL-комплект: ліцензія, пін, checkout libsignal | `build/veil-third-party-agpl-sources.tar.gz` |

Кожен запуск `xcodebuild` дописує повний stdout/stderr у `build/logs/<mode>-<UTC>.log` — саме ці логи потрапляють в артефакти CI. Секретів у них немає: скрипт не друкує ні паролі, ні base64.

Приклади:

```sh
bash scripts/ios-build.sh simulator
bash scripts/ios-build.sh test
VEIL_TEST_DESTINATION='platform=iOS Simulator,name=iPhone 16' bash scripts/ios-build.sh test

# Компільована перевірка під реальний пристрій, без підпису:
bash scripts/ios-build.sh device-unsigned
```

`device-unsigned` — це головна «дешева» перевірка: вона доводить, що Release-конфігурація збирається під справжній device SDK і лінкується в arm64. Скрипт після збірки сам перевіряє:

- `Veil.app/Veil` існує і є arm64;
- у бандлі **немає** `_CodeSignature`, `CodeResources`, `embedded.mobileprovision`;
- усередину архіву кладеться `DO-NOT-INSTALL-UNSIGNED.txt` з поясненням.

Такий архів не запускається на iPhone жодним способом: ні Xcode, ні Apple Configurator, ні TestFlight. Перейменування у `.ipa` нічого не змінює.

### 3. GitHub Actions (тільки вручну)

`.github/workflows/ios.yml` має **лише** тригер `workflow_dispatch`. Автоматичні `push`/`pull_request` вимкнені навмисно: macOS-хвилини на приватному репозиторії тарифікуються з множником **×10**, і жоден `git push` не повинен витрачати гроші без рішення власника. У файлі є закоментований блок, який вмикає автозапуск — це робиться свідомо.

| Job | Вхідний перемикач | Що робить | Артефакт |
|---|---|---|---|
| `simulator` | `run_simulator` (default `true`) | компіляція + XCTest | `veil-simulator-unsigned-app-NOT-INSTALLABLE-ON-IPHONE`, `veil-ios-test-results`, `veil-ios-logs-simulator`, `veil-podfile-lock`, `veil-third-party-agpl-sources` |
| `device-unsigned` | `run_device_unsigned` (default `true`) | Release-архів під пристрій **без підпису** | `veil-device-UNSIGNED-xcarchive-DO-NOT-INSTALL` |
| `signed-export` | `run_signed_export` (default `false`) | підписаний архів + IPA, тимчасовий keychain | `veil-signed-ipa-<method>`, `veil-ios-logs-signed` |

`device-unsigned` — окремий job (а не крок у `simulator`) спеціально: він має інший SDK, іншу конфігурацію і не має жодного доступу до підпису. Обидва job-и незалежні, тож можна запустити лише один, щоб зекономити хвилини.

Запуск: **Actions → iOS (manual, cost-gated) → Run workflow** і вибрати перемикачі. Усі логи лежать в артефактах, нічого не публікується в App Store Connect.

---

## Підписаний артефакт

### Варіант A: Xcode Organizer (найпростіший)

Після Run на пристрої: Xcode → Window → Organizer → Archives → Distribute App. Спосіб (Development / Ad Hoc / App Store Connect) залежить від вашого акаунта. Це не потребує жодних секретів у CI і не витрачає хвилини macOS-раннера.

### Варіант B: локальний CLI

```sh
export VEIL_APPLE_TEAM_ID=YOURTEAMID          # 10 символів
export VEIL_BUNDLE_ID=com.example.veil        # ваш зареєстрований ідентифікатор
bash scripts/ios-build.sh archive             # automatic signing, потрібен акаунт у Xcode
cp ios/ExportOptions.example.plist build/ExportOptions.plist
# відредагуйте teamID / provisioningProfiles (файл у build/ ігнорується git)
VEIL_EXPORT_OPTIONS=build/ExportOptions.plist bash scripts/ios-build.sh export
```

`archive` підтримує і ручний підпис:

```sh
export VEIL_SIGNING_IDENTITY='Apple Distribution'
export VEIL_PROVISIONING_PROFILE_SPECIFIER='Veil Distribution'
```

Після архіву скрипт **відмовляється** приймати результат, якщо:

- `TeamIdentifier` у вбудованому профілі не дорівнює `VEIL_APPLE_TEAM_ID`;
- `application-identifier` не покриває `TEAM.BUNDLE_ID`;
- `CFBundleIdentifier` зібраного бандла не дорівнює `VEIL_BUNDLE_ID`;
- профіль прострочений;
- `codesign --verify --strict` не проходить;
- підписані entitlements містять інший `application-identifier` (це також ловить випадок, коли збірка насправді не підписалася).

`export` повторює всі ці перевірки вже на розпакованому `Payload/Veil.app` з готового IPA і додатково рахує `SHA256SUMS.txt`.

### Варіант C: CI з секретами (платний Apple Developer team)

`scripts/ios-ci-sign.sh` **не збирає** секрети й не питає їх у чаті. Він читає вже наявні змінні оточення, які GitHub підставляє з secrets:

| Secret | Вміст |
|---|---|
| `IOS_CERT_P12_BASE64` | `base64 -w0 signing.p12` — сертифікат **разом із приватним ключем** |
| `IOS_CERT_PASSWORD` | пароль `.p12` |
| `IOS_PROVISIONING_PROFILE_BASE64` | `base64 -w0 profile.mobileprovision` |
| `IOS_TEAM_ID` | 10-символьний Team ID |
| `IOS_BUNDLE_ID` | зареєстрований Bundle ID |

Налаштування (виконує власник репозиторію, не агент):

```sh
gh secret set IOS_CERT_P12_BASE64 --env ios-signing < <(base64 -w0 signing.p12; echo)
gh secret set IOS_CERT_PASSWORD --env ios-signing
gh secret set IOS_PROVISIONING_PROFILE_BASE64 --env ios-signing < <(base64 -w0 profile.mobileprovision; echo)
gh secret set IOS_TEAM_ID --env ios-signing
gh secret set IOS_BUNDLE_ID --env ios-signing
```

`--env ios-signing` означає, що секрети доступні лише job-у з `environment: ios-signing`. Створіть це середовище в Settings → Environments і додайте **Required reviewers** — тоді навіть ручний запуск підписаної збірки чекатиме підтвердження людини.

Що робить скрипт:

1. Перевіряє наявність усіх змінних; друкує **лише імена** відсутніх.
2. Валідує формат `IOS_TEAM_ID` / `IOS_BUNDLE_ID`, метод експорту.
3. Створює тимчасовий keychain у `mktemp -d`, з випадковим паролем (`openssl rand`), `chmod 700`.
4. Імпортує `.p12` лише в цей keychain, дозволяє доступ **тільки** `codesign` і `security`, робить `set-key-partition-list`, перевіряє, що identity справді валідний.
5. Декодує профіль, читає його plist через `security cms -D`, і **відмовляється** працювати, якщо:
   - TeamIdentifier ≠ `IOS_TEAM_ID`;
   - App ID не покриває `TEAM.BUNDLE_ID` (wildcard `TEAM.*` приймається з попередженням, конкретний id потім перевіряється на підписі);
   - профіль прострочений;
   - тип профілю не відповідає `IOS_EXPORT_METHOD` (development/ad-hoc потребують списку пристроїв; enterprise — `ProvisionsAllDevices`; app-store — ні того, ні того).
6. Копіює профіль у `~/Library/MobileDevice/Provisioning Profiles/<UUID>.mobileprovision` (попередній файл з тим самим UUID зберігає й повертає).
7. Генерує `ExportOptions.plist` у тимчасовій теці з `signingStyle=manual` і мапінгом bundle → ім'я профілю.
8. Викликає `scripts/ios-build.sh archive`, потім `export`; перевірки підпису виконуються двічі (архів і розпакований IPA).
9. На `EXIT`/`INT`/`TERM`: повертає search list і default keychain, **видаляє** тимчасовий keychain, видаляє (або відновлює) профіль, стирає тимчасову теку. Після видалення перевіряє, що keychain більше не згадується в search list.

Скрипт не робить `-allowProvisioningUpdates`: підпис повністю ручний і детермінований, тож неправильний профіль — це помилка, а не тиха заміна іншим. Для автоматичного підпису на CI знадобився б App Store Connect API key; це окреме рішення і окремі витрати.

Обмеження, які треба знати:

- `security import -P` на кілька мілісекунд показує пароль у argv процесу. Раннер GitHub — ефемерна одноосібна VM, але на спільному Mac так робити не варто.
- macOS runner не має TTY, тому будь-який запит Keychain на дозвіл означав би вічне зависання — саме для цього існує `set-key-partition-list`.
- Розмір `build/Veil.xcarchive` з LibSignalClient — сотні мегабайт; в артефакти вантажиться лише IPA та логи.

---

## GitHub Actions: гроші та безпека

- Приватний репозиторій: macOS-хвилини ×10. Job `simulator` + `device-unsigned` разом — це реалістично 20–40 хвилин, тобто 200–400 «звичайних» хвилин. Запускайте вручну і свідомо.
- Публічний репозиторій: хвилини безкоштовні, але код і логи стають публічними. Перевірте, чи немає в логах шляхів/імен, які ви не хочете показувати.
- Кеш `ios/Pods` + `~/.cocoapods` економить 5–10 хвилин на кожен запуск. Ключ включає хеш `ios/Podfile` і `ios/project.yml`, тому зміна залежностей скидає кеш.
- Ніколи не додавайте `pull_request_target` до workflow із секретами: fork-PR отримав би доступ до підпису.
- Артефакти не містять секретів, але містять логи збірки: перед публікацією артефактів у публічному репо перегляньте їх.

---

## Troubleshooting

| Симптом | Причина | Що робити |
|---|---|---|
| `Missing xcodegen` / `pod` | немає інструментів | `brew install xcodegen cocoapods` |
| `[!] The `Veil` target ... not found` під час `pod install` | `pod install` до `xcodegen generate` | завжди через `scripts/ios-build.sh prepare` (правильний порядок уже всередині) |
| `pod install --deployment` падає | `Podfile.lock` не відповідає `Podfile` | оновити lock свідомо (`pod install` без `--deployment`), переглянути diff, закомітити |
| `Sandbox: bash(...) deny` | user script sandboxing | у `project.yml` уже `ENABLE_USER_SCRIPT_SANDBOXING: NO`; не прибирайте |
| `no such module 'LibSignalClient'` | відкрито `.xcodeproj` замість `.xcworkspace` | `open ios/Veil.xcworkspace` |
| Довге завантаження ~180 МБ | prebuilt Rust FFI LibSignal | одноразово; кешується в CI |
| `errSecInternalComponent` / codesign запитує пароль | keychain не авторизований для `codesign` | `security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k <pw> <keychain>` (у CI це вже робиться) |
| `No signing certificate "iOS Development" found` | сертифікат не в тому keychain / не в search list | перевірити `security find-identity -v -p codesigning` |
| `-resultBundlePath` вже існує | повторний запуск у ту саму секунду | скрипт видаляє старий бандл перед запуском |
| `no available iPhone simulator` | не встановлено iOS runtime | Xcode → Settings → Components → iOS |
| `Signing for "Veil" requires a development team` у `device-unsigned` | хтось прибрав `CODE_SIGNING_ALLOWED=NO` | не прибирати; цей режим існує саме для збірки без підпису |
| `ProvisionedDevices` відсутній, а метод `development` | взято App Store профіль | узяти development/ad-hoc профіль або змінити `IOS_EXPORT_METHOD` |
| IPA експортується, але не ставиться | пристрій не в `ProvisionedDevices`, або UDID інший | додати UDID у профіль і перевипустити його |

---

## Що перевірити першою ж збіркою на macOS (відомі ризики)

Ці пункти виявлені під час огляду репозиторію на Linux. Вони **не** виправлені в iOS-коді (це поза межами поточної задачі), але можуть дати першу ж помилку або блокують публікацію:

1. **`ios/project.yml` тягне `../licenses` з-поза каталогу проєкту** (`sources: - path: ../licenses, buildPhase: resources`). XcodeGen зазвичай це дозволяє, але шлях поза коренем проєкту — крихка конструкція: після `xcodegen generate` перевірте, що `AGPL-3.0.txt` справді потрапив у `Veil.app` (його читає `SettingsView.licenseText` через `Bundle.main.url(forResource: "AGPL-3.0", withExtension: "txt")`). Якщо ні — перенесіть файл у `ios/Veil/Resources/` і оновіть `project.yml`.
2. **Немає `Assets.xcassets`** — ні `AppIcon`, ні `AccentColor`. Збірка й симулятор працюють, але App Store валідація відхилить застосунок без іконки.
3. **Немає `PrivacyInfo.xcprivacy`** — з травня 2024 App Store вимагає privacy manifest для застосунків, що використовують «required reason» API. Це блокер публікації, не збірки.
4. **`ios/Podfile.lock` не закомічений.** Перший `pod install` його створить; закомітьте, інакше `--deployment` ніколи не ввімкнеться, а резолюція залежностей щоразу робитиметься заново.
5. **Немає `.entitlements`.** Keychain працює з типовою access group (bundle id), тож для MVP цього достатньо. Якщо колись знадобиться App Group або Keychain Sharing — це зміна підпису, а не коду.
6. **`ITSAppUsesNonExemptEncryption = true`** в обох Info.plist. Це чесно (Signal-протокол), але при кожній подачі в App Store Connect буде питання про експортне шифрування.
7. **`macos-15`** у workflow зафіксований навмисно (Xcode 16.x, iOS 18 SDK, deployment target 17.0). Коли образ приберуть із GitHub, job впаде з `runs-on` — тоді свідомо піднімайте версію.

Про будь-яку фактичну помилку компіляції Swift — повідомте окремо; правити Swift-код у межах цієї задачі не дозволено.

---

## AGPL-3.0 та вихідні коди

LibSignalClient поширюється під AGPL-3.0. Job `simulator` (крок `third-party-sources`) збирає `veil-third-party-agpl-sources.tar.gz`:

- `AGPL-3.0.txt`, `THIRD_PARTY_NOTICES.md`;
- `Podfile`, `Podfile.lock`, `Local Podspecs/*.json`;
- `PROVENANCE.txt` — репозиторій, commit `fc90b90fa2b9c37822fa47ba0e0dcdf387a0c071`, версія `0.106.0`, SHA-256 prebuilt FFI `ddfa5ac6…7152f`;
- сам checkout `ios/Pods/LibSignalClient` (без `.git`, `target`, `*.o`, `*.a`), якщо він є.

Це і є «corresponding source» для того, що реально скомпільовано. Prebuilt Rust FFI — бінарний артефакт upstream; його джерело — той самий пін.

---

## Мінімальна ручна перевірка перед будь-яким використанням

- Два окремі пристрої/симулятори: різні `@handle`, відправка/відповідь, Unicode.
- Порівняти відбитки ключів незалежним каналом перед позначкою «перевірено».
- Офлайн-одержувач → доставка після повернення; офлайн-відправник → одна доставка, без повторного ratchet-encrypt.
- Перезапуск обох клієнтів і relay: історія/сесії залишаються, після ACK шифротекст зникає з черги.
- Відсутність plaintext у файлі vault/бекапах/логах; пошкоджений vault спричиняє помилку, а не генерацію нової особи.
- Підміна identity key блокує продовження сесії, а не приймається непомітно.
- Закриття програми приховує preview; у фоні доставка не гарантується: APNs не реалізовано.

Криптографічний аудит і навантажувальні випробування не виконані. Не використовуйте MVP для секретів.
