# Veil для iPhone — інструкція для друга з Mac

## Що це

Нативний SwiftUI-проєкт Veil, iOS 17+, текстові чати 1:1, LibSignalClient 0.106.0. Це **вихідні коди, не готовий IPA**. Справжня Xcode-збірка ще не перевірена; перша збірка може виявити помилки, які потрібно повернути розробнику. Неаудитований MVP, не для секретів.

## 1. Інструменти

Встановити актуальний сумісний **Xcode з Mac App Store**, відкрити його, прийняти ліцензію й установити iOS Simulator. У Xcode → Settings → Locations вибрати цей Xcode у Command Line Tools.

Потрібен Homebrew (якщо його немає — офіційний сайт https://brew.sh), потім у Terminal:

```sh
brew install xcodegen cocoapods
```

## 2. Відкрити проєкт

Розпакувати ZIP. У Terminal перейти в папку `Veil-iPhone` (ту, де є `ios` та `scripts`):

```sh
cd /шлях/до/Veil-iPhone
bash scripts/ios-build.sh prepare
open ios/Veil.xcworkspace
```

Замість `/шлях/до/Veil-iPhone` підставити справжню папку; її можна перетягнути у Terminal після `cd `. Відкривати саме **`.xcworkspace`**, не `.xcodeproj`. Перший запуск завантажує залежності, зокрема ~180 МБ офіційного Signal FFI. Точний commit і SHA-256 уже зафіксовані; не оновлювати залежність навмання.

## 3. Спочатку симулятор

У верхній панелі Xcode вибрати scheme **Veil** і доступний iPhone Simulator → **Run (⌘R)**. Для тестів — **⌘U**. Альтернатива з журналами:

```sh
bash scripts/ios-build.sh simulator
bash scripts/ios-build.sh test
```

## 4. Встановити на фізичний iPhone

1. Підключити потрібний iPhone до Mac кабелем, підтвердити **Trust / Довіряти**; iPhone має бути на iOS 17+.
2. Увімкнути **Settings → Privacy & Security → Developer Mode**, якщо Xcode/iPhone попросить, і виконати необхідний перезапуск.
3. Xcode → Settings → Accounts → додати Apple ID. Власник вводить пароль і 2FA **особисто**, не пересилає їх у чат.
4. Target **Veil → Signing & Capabilities**: `Automatically manage signing` = ON; Team = свій **Personal Team**; Bundle Identifier змінити на унікальний, наприклад `com.yournickname.veil.dev` (замінити `yournickname`).
5. У верхній панелі вибрати підключений iPhone → **Run (⌘R)**. За потреби підтвердити довіру своєму developer-профілю на iPhone в Settings → General → VPN & Device Management.

Безкоштовний Personal Team має обмеження; підпис зазвичай діє **7 днів**, після чого застосунок потрібно знову встановити/підписати через Xcode. Після зміни signing у GUI не запускати знову `prepare` без потреби: XcodeGen регенерує проєкт із `project.yml` і може скинути ручні налаштування.

**Якщо потрібного iPhone немає поряд із Mac:** друг може зібрати й перевірити код, але просто переслати `.app` або непідписаний `.ipa` недостатньо для встановлення на іншому iPhone. Потрібен окремий законний signing/sideloading-процес або Apple Developer Program/TestFlight. Паролі Apple ID чи приватні signing keys пересилати не потрібно.

## 5. Адреса сервера

На onboarding потрібна **справжня HTTPS-адреса Veil relay**, доступна з телефону. Її має надати власник сервера. Постійний публічний домен ще налаштовується. `127.0.0.1` на iPhone — сам iPhone, не Linux-сервер; GitHub URL також не є relay. Без доступного relay можна перевірити збірку й початковий інтерфейс, але не зареєструватися чи листуватися.

Не вимикати перевірку TLS і не підміняти криптографію для обходу помилки.

## Що повернути розробнику

- Чи пройшли збірка та тести, версію Xcode, версію iOS.
- Створений файл `ios/Podfile.lock`.
- Якщо є помилка — текст перших помилок Xcode або відповідний журнал із `build/logs/`. Не надсилати паролі, токени, `.p12`, `.mobileprovision` чи приватні ключі.

Для першого особистого запуску **не потрібно** купувати Apple Developer Program, налаштовувати GitHub Secrets чи використовувати `ios-ci-sign.sh`. Ці платні/CI-варіанти описані окремо в `docs/IOS_BUILD.md`.
