#!/usr/bin/env python3
"""Build a harmless local fixture for opt-in disposable-emulator verification.

Requires aapt, smali, Android framework resources, keytool and jarsigner. Does not
install an APK, contact a device or create production workspace records.
"""

import argparse
import subprocess
import tempfile
import zipfile
from pathlib import Path

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="dev.droidshield.smoke" android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="28"/>
    <application android:label="DroidShield lab smoke" android:testOnly="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter><action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
        </activity>
    </application>
</manifest>"""
SMALI = """.class public Ldev/droidshield/smoke/MainActivity;
.super Landroid/app/Activity;
.method public constructor <init>()V
.locals 0
invoke-direct {p0}, Landroid/app/Activity;-><init>()V
return-void
.end method
.method public onCreate(Landroid/os/Bundle;)V
.locals 2
invoke-super {p0,p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
new-instance v0, Landroid/widget/TextView;
invoke-direct {v0,p0}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V
const-string v1, "DroidShield offline runtime validation"
invoke-virtual {v0,v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
invoke-virtual {p0,v0}, Landroid/app/Activity;->setContentView(Landroid/view/View;)V
return-void
.end method
"""


def build(directory: Path, framework: Path):
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    (directory / "AndroidManifest.xml").write_text(MANIFEST)
    (directory / "MainActivity.smali").write_text(SMALI)
    apk = directory / "smoke.apk"
    key = directory / "local-debug.keystore"

    def run(args):
        subprocess.run(args, check=True, capture_output=True, timeout=60)

    run(
        [
            "aapt",
            "package",
            "-f",
            "-M",
            str(directory / "AndroidManifest.xml"),
            "-I",
            str(framework),
            "-F",
            str(apk),
        ]
    )
    run(
        [
            "smali",
            "assemble",
            str(directory / "MainActivity.smali"),
            "-o",
            str(directory / "classes.dex"),
        ]
    )
    with zipfile.ZipFile(apk, "a") as archive:
        archive.write(directory / "classes.dex", "classes.dex")
    # This throwaway debug key has no identity/production value and is removed
    # immediately after signing. It is never accepted as an application secret.
    try:
        run(
            [
                "keytool",
                "-genkeypair",
                "-noprompt",
                "-alias",
                "lab",
                "-keyalg",
                "RSA",
                "-keystore",
                str(key),
                "-storepass",
                "android",
                "-keypass",
                "android",
                "-dname",
                "CN=DroidShield disposable lab",
                "-validity",
                "1",
            ]
        )
        run(
            [
                "jarsigner",
                "-keystore",
                str(key),
                "-storepass",
                "android",
                "-keypass",
                "android",
                str(apk),
                "lab",
            ]
        )
    finally:
        key.unlink(missing_ok=True)
    return apk


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    parser.add_argument(
        "--framework", type=Path, default=Path("/usr/share/android-framework-res/framework-res.apk")
    )
    args = parser.parse_args()
    target = args.directory or Path(tempfile.mkdtemp(prefix="droidshield-fixture-")) / "runtime"
    try:
        print(build(target.resolve(), args.framework.resolve()))
    except (OSError, subprocess.SubprocessError):
        parser.exit(1, "Fixture build failed. Check the required Android/Java build tools.\n")
