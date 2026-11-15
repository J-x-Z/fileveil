# FileVeil for Android

Native Kotlin/Jetpack Compose UI with the same Rust Engine and file protocols as
the desktop applications. ARM64, Android 8.0/API 26 or later. The current native
acceptance record names the device and Android version actually tested.

Files are selected through the Storage Access Framework. The application has no
Internet, broad storage or root permission. Input documents are copied to a
bounded app-private snapshot, processed there and never opened for writing.
Outputs remain separate. Optional directory exports create new documents and
read them back to compare SHA-256. Results can also be shared through a restricted
FileProvider. Existing local results and reports survive an application restart.

Mark uses an Ed25519 identity whose seed is AES-GCM wrapped by Android Keystore.
The wrapping key is nonexportable. Uninstalling the application or clearing its
data loses that local identity. Public signature and content-binding verification
does not require the private signing key. Keyed Watermark Engine 2 detection and
cleaning require the matching watermark identity. Robust signal processing is
Experimental; an undetected watermark is not proof that an image has no watermark.

The mobile limits are 64 MiB per file, 12 million decoded pixels, 16 inputs per
batch and 256 MiB of retained results. Clear local results after exporting them.
Document-provider operations have a 30-second caller deadline, cancellation and
descriptor closure. One uncooperative provider can occupy the single bounded
provider worker until it returns; additional provider operations then fail closed.
Native processing stops after its current bounded file, rather than claiming
immediate cancellation of a Rust operation.

JPEG/PNG processing, supported container metadata, Ed25519 and offline C2PA use
the shared Core. Desktop external executables are not bundled into Android.
Capabilities requiring those executables, including qpdf PDF rewriting and
external HEIF pixel codecs, report their actual unsupported scope. C2PA signature,
asset binding and issuer trust are assessed separately without network retrieval.

Build with JDK 17, Android platform/build-tools 34, CMake 3.22.1, NDK 25.1.8937393
and an installed Rust `aarch64-linux-android` standard library. The checked-in
Gradle wrapper pins both distribution version and SHA-256. Use the existing
workspace Cargo target and set `CARGO_HOME` if using an offline registry cache.
Gradle's default cache and Java temporary files are placed in the existing
workspace's ignored `work/` directory. An explicitly supplied `GRADLE_USER_HOME`
is respected. Kotlin compilation runs in-process. `--offline` prevents fresh
dependency downloads when the required Cargo and Gradle artifacts are cached.

```sh
python3 android/build-apk.py \
  --java-home /path/to/jdk17 \
  --sdk /path/to/android-sdk \
  --signing-dir /private/path/outside-repository/android-signing \
  --output /path/to/new/FileVeil-android-arm64.apk
```

The first build creates a separate persistent APK signing key and owner-only
password file in the supplied private directory. Preserve both for future
updates. They must remain outside the source repository and output directories.
The build emits a signed APK, SHA-256 and certificate verification receipt. This
Android application signing identity is independent of copyright signing keys
and paid desktop developer certificates.

Debug instrumentation tests are built with `./gradlew :app:assembleDebug
:app:assembleDebugAndroidTest`. They cover the JNI processing loop, a desktop-made
signature fixture, C2PA cryptography, keyed image processing, Keystore wrapping,
path rejection, output budgets and noncooperative provider cancellation. Their
outputs enable independent desktop rechecks. A debug application and the public
APK have different signers; switching between them requires removing the test
installation and loses its test-only app data. Upgrade acceptance uses the
persistent public APK signer, not the debug signer.
