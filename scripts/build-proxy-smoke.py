#!/usr/bin/env python3
"""Build a harmless HTTPS GET fixture for an explicitly configured disposable lab.

Requires aapt, smali, keytool and jarsigner. The supplied lab CA is trusted only
inside this fixture's SSLContext. Hostname/certificate verification and normal
TLS remain enabled. No APK installation, device discovery or trust-store edits.
"""

import argparse
import importlib.util
import json
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

MAIN = """.class public Ldev/droidshield/proxysmoke/MainActivity;
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
const-string v1, "DroidShield approved HTTPS fixture"
invoke-virtual {v0,v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
invoke-virtual {p0,v0}, Landroid/app/Activity;->setContentView(Landroid/view/View;)V
new-instance v0, Ldev/droidshield/proxysmoke/ProxyProbe;
invoke-direct {v0}, Ldev/droidshield/proxysmoke/ProxyProbe;-><init>()V
new-instance v1, Ljava/lang/Thread;
invoke-direct {v1,v0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
invoke-virtual {v1}, Ljava/lang/Thread;->start()V
return-void
.end method
"""
PROBE = """.class public Ldev/droidshield/proxysmoke/ProxyProbe;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;
.method public constructor <init>()V
.locals 0
invoke-direct {p0}, Ljava/lang/Object;-><init>()V
return-void
.end method
.method public run()V
.locals 8
:try_start
const-string v0, __CA__
const-string v1, "US-ASCII"
invoke-virtual {v0,v1}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B
move-result-object v0
new-instance v1, Ljava/io/ByteArrayInputStream;
invoke-direct {v1,v0}, Ljava/io/ByteArrayInputStream;-><init>([B)V
const-string v0, "X.509"
invoke-static {v0}, Ljava/security/cert/CertificateFactory;->getInstance(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;
move-result-object v0
invoke-virtual {v0,v1}, Ljava/security/cert/CertificateFactory;->generateCertificate(Ljava/io/InputStream;)Ljava/security/cert/Certificate;
move-result-object v0
invoke-static {}, Ljava/security/KeyStore;->getDefaultType()Ljava/lang/String;
move-result-object v1
invoke-static {v1}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;
move-result-object v1
const/4 v2, 0x0
invoke-virtual {v1,v2,v2}, Ljava/security/KeyStore;->load(Ljava/io/InputStream;[C)V
const-string v3, "dedicated-lab-ca"
invoke-virtual {v1,v3,v0}, Ljava/security/KeyStore;->setCertificateEntry(Ljava/lang/String;Ljava/security/cert/Certificate;)V
invoke-static {}, Ljavax/net/ssl/TrustManagerFactory;->getDefaultAlgorithm()Ljava/lang/String;
move-result-object v0
invoke-static {v0}, Ljavax/net/ssl/TrustManagerFactory;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;
move-result-object v0
invoke-virtual {v0,v1}, Ljavax/net/ssl/TrustManagerFactory;->init(Ljava/security/KeyStore;)V
invoke-virtual {v0}, Ljavax/net/ssl/TrustManagerFactory;->getTrustManagers()[Ljavax/net/ssl/TrustManager;
move-result-object v0
const-string v1, "TLS"
invoke-static {v1}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;
move-result-object v1
invoke-virtual {v1,v2,v0,v2}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V
invoke-virtual {v1}, Ljavax/net/ssl/SSLContext;->getSocketFactory()Ljavax/net/ssl/SSLSocketFactory;
move-result-object v1
new-instance v0, Ljava/net/URL;
const-string v3, __URL__
invoke-direct {v0,v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
new-instance v3, Ljava/net/InetSocketAddress;
const-string v4, "127.0.0.1"
const/16 v5, 0x1f91
invoke-direct {v3,v4,v5}, Ljava/net/InetSocketAddress;-><init>(Ljava/lang/String;I)V
sget-object v4, Ljava/net/Proxy$Type;->HTTP:Ljava/net/Proxy$Type;
new-instance v5, Ljava/net/Proxy;
invoke-direct {v5,v4,v3}, Ljava/net/Proxy;-><init>(Ljava/net/Proxy$Type;Ljava/net/SocketAddress;)V
invoke-virtual {v0,v5}, Ljava/net/URL;->openConnection(Ljava/net/Proxy;)Ljava/net/URLConnection;
move-result-object v0
check-cast v0, Ljavax/net/ssl/HttpsURLConnection;
invoke-virtual {v0,v1}, Ljavax/net/ssl/HttpsURLConnection;->setSSLSocketFactory(Ljavax/net/ssl/SSLSocketFactory;)V
invoke-virtual {v0,v2}, Ljava/net/HttpURLConnection;->setInstanceFollowRedirects(Z)V
const/16 v1, 0x1388
invoke-virtual {v0,v1}, Ljava/net/URLConnection;->setConnectTimeout(I)V
invoke-virtual {v0,v1}, Ljava/net/URLConnection;->setReadTimeout(I)V
const-string v1, "GET"
invoke-virtual {v0,v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V
invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I
invoke-virtual {v0}, Ljava/net/HttpURLConnection;->disconnect()V
:try_end
.catch Ljava/lang/Exception; {:try_start .. :try_end} :failed
return-void
:failed
move-exception v0
return-void
.end method
"""


def build(directory, framework, certificate, url):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(c.isspace() for c in url)
        or len(url) > 2048
    ):
        raise ValueError("A single exact HTTPS fixture URL without credentials/query is required")
    pem = certificate.read_text(encoding="ascii")
    if (
        not 0 < len(pem) <= 16384
        or "-----BEGIN CERTIFICATE-----" not in pem
        or "PRIVATE KEY" in pem
    ):
        raise ValueError("A public lab CA certificate is required")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location(
        "droidshield_runtime_fixture", Path(__file__).with_name("build-runtime-smoke.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.MANIFEST.replace(
        "dev.droidshield.smoke", "dev.droidshield.proxysmoke"
    ).replace(
        "    <application",
        '    <uses-permission android:name="android.permission.INTERNET"/>\n    <application',
    )
    (directory / "AndroidManifest.xml").write_text(manifest)
    smali = directory / "smali"
    smali.mkdir()
    (smali / "MainActivity.smali").write_text(MAIN)
    (smali / "ProxyProbe.smali").write_text(
        PROBE.replace("__CA__", json.dumps(pem)).replace("__URL__", json.dumps(url))
    )
    apk, key = directory / "proxy-smoke.apk", directory / "local-debug.keystore"

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
    run(["smali", "assemble", str(smali), "-o", str(directory / "classes.dex")])
    with zipfile.ZipFile(apk, "a") as archive:
        archive.write(directory / "classes.dex", "classes.dex")
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
                "CN=DroidShield disposable HTTPS fixture",
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
    parser.add_argument("--ca-cert", required=True, type=Path)
    parser.add_argument("--url", required=True)
    parser.add_argument(
        "--framework", type=Path, default=Path("/usr/share/android-framework-res/framework-res.apk")
    )
    args = parser.parse_args()
    target = args.directory or Path(tempfile.mkdtemp(prefix="droidshield-proxy-fixture-")) / "app"
    try:
        print(build(target.resolve(), args.framework.resolve(), args.ca_cert.resolve(), args.url))
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(
            1,
            "Fixture build failed. Check its exact HTTPS URL, public CA and Android/Java tools.\n",
        )
