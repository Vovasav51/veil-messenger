# libsignal is used as a published artifact; no reflection into it.
# Keep the names of any future reflection-based members out of obfuscation.
-keep class org.signal.libsignal.** { *; }
-dontwarn org.signal.libsignal.**
-dontwarn org.jetbrains.annotations.**
