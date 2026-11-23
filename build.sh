#!/bin/bash
# Builds and signs the APK with plain SDK tools (no Gradle, no third-party libraries).
#   ANDROID_JAR  platform android.jar (API 34+)
#   R8_JAR       r8/d8 jar from Google's maven
#   KEYSTORE     signing keystore (created on first build if missing)
set -euo pipefail
cd "$(dirname "$0")"
ANDROID_JAR=${ANDROID_JAR:-$HOME/android/platform-34/android.jar}
R8_JAR=${R8_JAR:-$HOME/android/tools/r8-8.5.35.jar}
KEYSTORE=${KEYSTORE:-$HOME/.android/l2tpvpn-release.jks}
OUT=build/apk
rm -rf "$OUT" && mkdir -p "$OUT"/{res,gen,classes,dex}

if [ ! -f "$KEYSTORE" ]; then
    mkdir -p "$(dirname "$KEYSTORE")"
    pw=$(openssl rand -hex 16)
    keytool -genkeypair -keystore "$KEYSTORE" -storepass "$pw" -keypass "$pw" -alias l2tpvpn \
        -keyalg EC -groupname secp256r1 -validity 10000 -dname "CN=L2TP VPN" >/dev/null
    echo "$pw" > "$KEYSTORE.pass" && chmod 600 "$KEYSTORE" "$KEYSTORE.pass"
    echo "created signing key $KEYSTORE (password in $KEYSTORE.pass) - back these up"
fi

aapt2 compile --dir app/res -o "$OUT/res/compiled.zip"
aapt2 link -I "$ANDROID_JAR" --manifest app/AndroidManifest.xml --java "$OUT/gen" \
    -o "$OUT/unsigned.apk" "$OUT/res/compiled.zip"

javac --release 11 -Xlint:-options -cp "$ANDROID_JAR" -d "$OUT/classes" \
    $(find core/src app/src "$OUT/gen" -name '*.java')

java -cp "$R8_JAR" com.android.tools.r8.D8 --release --min-api 31 --lib "$ANDROID_JAR" \
    --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')

python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1], "a", zipfile.ZIP_DEFLATED).write(sys.argv[2], "classes.dex")' \
    "$OUT/unsigned.apk" "$OUT/dex/classes.dex"
zipalign -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
apksigner sign --ks "$KEYSTORE" --ks-pass "file:$KEYSTORE.pass" --out build/l2tpvpn.apk "$OUT/aligned.apk"
apksigner verify build/l2tpvpn.apk
ls -l build/l2tpvpn.apk
