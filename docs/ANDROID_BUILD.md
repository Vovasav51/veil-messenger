# Android APK

Veil для Android — нативний клієнт, не WebView/PWA. Потрібен Android 8+; підтримувані ABI залежать від зафіксованого libsignal-android. Актуальні результати збірки й тестів — у `BUILD_STATUS.md`.

## Готовий development APK

Якщо збірка успішна, артефакт знаходиться у **`dist/Veil-0.1.0-dev.apk`**. Це експериментальна **debug-підписана** збірка, не production-реліз. Дозволяйте встановлення з конкретного файлового менеджера лише на час встановлення. Підпис і SHA-256 — у результатах збірки; сторонні перепаковані файли не використовувати.

Для зв'язку потрібен той самий доступний із пристрою **HTTPS relay**, що й у iPhone-клієнта. Готовий APK не означає, що сервер уже розгорнутий. Налаштування — `DEPLOYMENT.md`.

## Зібрати на Linux/macOS

Потрібні повний JDK 17/21, Gradle **8.9**, Android SDK Platform **35**, Build Tools **35.0.0**. У проєкті немає SDK чи завантажених toolchain-бінарників.

За відсутності інструментів на Linux x86_64 допоміжний скрипт завантажить JDK21, Gradle8.9 та Android command-line tools в `~/.cache/veil-build`, з перевіркою хешів з офіційних джерел:

```sh
python3 scripts/bootstrap-android.py
source "$HOME/.cache/veil-build/env.sh"
sdkmanager --licenses
sdkmanager 'platforms;android-35' 'build-tools;35.0.0' 'platform-tools'
```

Прочитайте ліцензії SDK перед їх прийняттям. Кеш великий; потрібні кілька ГБ вільного місця. Не додавайте toolchain, кеш, власні keystore чи `local.properties` у репозиторій/архів.

```sh
bash scripts/android-build.sh debug
bash scripts/android-build.sh test
bash scripts/android-build.sh lint
```

Або відкрийте `android/` у Android Studio й установіть відповідний SDK. Не оновлюйте автоматично криптобібліотеку без тестів та звірки iOS-сумісності.

## Встановлення через USB

На **власному** тестовому пристрої увімкніть Developer options → USB debugging, підтвердьте його діалог довіри:

```sh
adb install -r dist/Veil-0.1.0-dev.apk
```

Видалення застосунку може назавжди втратити локальні ключі/історію та доступ до handle: account recovery у MVP немає. Не використовуйте `adb uninstall` як спосіб «полагодити» справжній акаунт.

## Release перед розповсюдженням

Development APK не підходить для реальних секретів. Для релізу потрібні окремий приватний signing key (не debug key), захищене зберігання ключа, перевірка backup/network policy та залежностей, device/runtime й двоплатформові тести, аналіз AGPL-умов, privacy policy та незалежний криптографічний аудит. Наявність успішного `assembleDebug` цих перевірок не замінює.
