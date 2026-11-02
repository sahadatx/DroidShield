"""Real DEX assembled by smali 2.5.2; reproducible source is retained below.

No application or test fixture code is executed. The byte fixture permits CI
without an Android SDK or Java; an optional test reassembles and checks it.
"""

import base64
import hashlib
import io
import struct
import zipfile
import zlib

from tests.apk_factory import binary_manifest

SMALI_SOURCE = '.class public Lcom/example/Probe;\n.super Ljava/lang/Object;\n\n.method public static inspect(Landroid/webkit/WebSettings;)V\n    .registers 4\n    new-instance v0, Ljava/util/Random;\n    invoke-direct {v0}, Ljava/util/Random;-><init>()V\n    const-string v1, "MD5"\n    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;\n    const-string v1, "SHA-1"\n    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;\n    const-string v1, "DES/ECB/PKCS5Padding"\n    invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n    const/4 v1, 0x0\n    invoke-virtual {p0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V\n    invoke-virtual {p0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V\n    invoke-virtual {p0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V\n    invoke-virtual {p0, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V\n    invoke-static {v1}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V\n    const-string v1, "AKIA0123456789ABCDEF"\n    const-string v1, "password=do-not-expose-this-realistic-test-fixture"\n    return-void\n.end method\n\n.method public static harmless()Ljava/lang/String;\n    .registers 1\n    const-string v0, "https://private.example.invalid/path?token=do-not-expose"\n    return-object v0\n.end method\n'

COMPILED_DEX = base64.b64decode(
    "ZGV4CjAzNQBY+sjnIKeP+p2ViXBf8XQUkezG+0f96yA0BQAAcAAAAHhWNBIAAAAAAAAAAKAEAAAdAAAAcAAAAAoAAADkAAAA"
    "BgAAAAwBAAAAAAAAAAAAAAoAAABUAQAAAQAAAKQBAABwAwAAxAEAAMQBAADMAQAA4gEAAPgBAAD7AQAA/wEAAB0CAAA3AgAA"
    "TAIAAGACAAB0AgAAkwIAAKcCAAC+AgAAwwIAAMoCAADNAgAA0QIAANUCAADYAgAA5QIAAO8CAAApAwAAMgMAAGYDAAB6AwAA"
    "mgMAAL8DAADVAwAABQAAAAYAAAAHAAAACAAAAAkAAAAKAAAACwAAAAwAAAAPAAAAEgAAAAMAAAAEAAAAAAAAAAQAAAAFAAAA"
    "+AMAAAQAAAAHAAAA+AMAAA8AAAAIAAAAAAAAABAAAAAIAAAAAAQAABEAAAAIAAAACAQAAAAABQAYAAAAAAAFABkAAAAAAAUA"
    "GgAAAAAABQAbAAAAAQAFABwAAAACAAAAFAAAAAIABAAWAAAABQABABMAAAAGAAMAAAAAAAcAAgATAAAAAgAAAAEAAAADAAAA"
    "AAAAAP////8AAAAAkgQAAAAAAAAGPGluaXQ+ABRBS0lBMDEyMzQ1Njc4OUFCQ0RFRgAUREVTL0VDQi9QS0NTNVBhZGRpbmcA"
    "AUwAAkxMABxMYW5kcm9pZC93ZWJraXQvV2ViU2V0dGluZ3M7ABhMYW5kcm9pZC93ZWJraXQvV2ViVmlldzsAE0xjb20vZXhh"
    "bXBsZS9Qcm9iZTsAEkxqYXZhL2xhbmcvT2JqZWN0OwASTGphdmEvbGFuZy9TdHJpbmc7AB1MamF2YS9zZWN1cml0eS9NZXNz"
    "YWdlRGlnZXN0OwASTGphdmEvdXRpbC9SYW5kb207ABVMamF2YXgvY3J5cHRvL0NpcGhlcjsAA01ENQAFU0hBLTEAAVYAAlZM"
    "AAJWWgABWgALZ2V0SW5zdGFuY2UACGhhcm1sZXNzADhodHRwczovL3ByaXZhdGUuZXhhbXBsZS5pbnZhbGlkL3BhdGg/dG9r"
    "ZW49ZG8tbm90LWV4cG9zZQAHaW5zcGVjdAAycGFzc3dvcmQ9ZG8tbm90LWV4cG9zZS10aGlzLXJlYWxpc3RpYy10ZXN0LWZp"
    "eHR1cmUAEnNldEFsbG93RmlsZUFjY2VzcwAec2V0QWxsb3dGaWxlQWNjZXNzRnJvbUZpbGVVUkxzACNzZXRBbGxvd1VuaXZl"
    "cnNhbEFjY2Vzc0Zyb21GaWxlVVJMcwAUc2V0SmF2YVNjcmlwdEVuYWJsZWQAHnNldFdlYkNvbnRlbnRzRGVidWdnaW5nRW5h"
    "YmxlZAAAAAABAAAABAAAAAEAAAAAAAAAAQAAAAkAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAMAAAAaABUAEQAAAAQAAQACAAAA"
    "AAAAACkAAAAiAAYAcBAIAAAAGgENAHEQBwABABoBDgBxEAcAAQAaAQIAcRAJAAEAEgFuIAMAEwBuIAAAEwBuIAEAEwBuIAIA"
    "EwBxEAQAAQAaAQEAGgEXAA4AAAACAAUJmAgBCbAIAAAMAAAAAAAAAAEAAAAAAAAAAQAAAB0AAABwAAAAAgAAAAoAAADkAAAA"
    "AwAAAAYAAAAMAQAABQAAAAoAAABUAQAABgAAAAEAAACkAQAAAiAAAB0AAADEAQAAARAAAAMAAAD4AwAAAxAAAAIAAAAQBAAA"
    "ASAAAAIAAAAYBAAAACAAAAEAAACSBAAAABAAAAEAAACgBAAA"
)


def rehash_dex(data):
    data = bytearray(data)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


def dex_apk(
    dex=COMPILED_DEX, *, dex_entries=None, compression=zipfile.ZIP_STORED, **manifest_options
):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        info = zipfile.ZipInfo("AndroidManifest.xml", date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = compression
        archive.writestr(info, binary_manifest(**manifest_options))
        if dex_entries is None:
            dex_entries = (
                [("classes.dex", dex)] if dex is not None else [("resources.arsc", b"resources")]
            )
        for name, payload in dex_entries:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = compression
            archive.writestr(info, payload)
    return stream.getvalue()


EDGE_SOURCE = '.class public Lcom/example/Edge;\n.super Ljava/lang/Object;\n\n.method public static payload(I)I\n.registers 4\npacked-switch p0, :switch_data\nconst/4 v0, 0x0\nreturn v0\n:case_one\nconst/4 v0, 0x1\nreturn v0\n:case_two\nconst/4 v0, 0x2\nreturn v0\n:switch_data\n.packed-switch 0x1\n:case_one\n:case_two\n.end packed-switch\n.end method\n\n.method public static array()[I\n.registers 2\nconst/4 v0, 0x3\nnew-array v0, v0, [I\nfill-array-data v0, :array_data\nreturn-object v0\n:array_data\n.array-data 4\n0x1\n0x2\n0x3\n.end array-data\n.end method\n\n.method public static catches()V\n.registers 2\n:try_start\nconst-string v0, "MD5"\ninvoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;\n:try_end\nreturn-void\n.catch Ljava/lang/Exception; {:try_start .. :try_end} :handler\n:handler\nmove-exception v1\nreturn-void\n.end method\n\n.method public static text()Ljava/lang/String;\n.registers 1\nconst-string v0, "A\\u0000\\u00e9\\ud83d\\ude00"\nreturn-object v0\n.end method\n'

EDGE_DEX = base64.b64decode(
    "ZGV4CjAzNQDCa3Opy6Q+KubXUjsSV7hZUGvcM4UL1guQAwAAcAAAAHhWNBIAAAAAAAAAAPwCAAASAAAAcAAAAAgAAAC4AAAA"
    "BQAAANgAAAAAAAAAAAAAAAUAAAAUAQAAAQAAADwBAAA0AgAAXAEAAFwBAABpAQAAbAEAAHABAABzAQAAdwEAAIsBAACiAQAA"
    "tgEAAMoBAADpAQAA7gEAAPEBAAD1AQAA/AEAAAUCAAASAgAAGwIAAAEAAAAFAAAABgAAAAcAAAAIAAAACQAAAAsAAAAMAAAA"
    "AgAAAAAAAAAsAgAAAwAAAAQAAAAAAAAABAAAAAUAAAAkAgAACwAAAAYAAAAAAAAAAwAAAAcAAAAAAAAAAQAEAA0AAAABAAMA"
    "DgAAAAEAAAAQAAAAAQABABEAAAAFAAIADwAAAAEAAAABAAAAAwAAAAAAAAD/////AAAAAOYCAAAAAAAABUHAgMOp7aC97biA"
    "AAFJAAJJSQABTAACTEwAEkxjb20vZXhhbXBsZS9FZGdlOwAVTGphdmEvbGFuZy9FeGNlcHRpb247ABJMamF2YS9sYW5nL09i"
    "amVjdDsAEkxqYXZhL2xhbmcvU3RyaW5nOwAdTGphdmEvc2VjdXJpdHkvTWVzc2FnZURpZ2VzdDsAA01ENQABVgACW0kABWFy"
    "cmF5AAdjYXRjaGVzAAtnZXRJbnN0YW5jZQAHcGF5bG9hZAAEdGV4dAAAAAABAAAABAAAAAEAAAAAAAAAAAAAAAAAAAACAAAA"
    "AAAAAAAAAAASAAAAEjAjAAcAJgAFAAAAEQAAAAADBAADAAAAAQAAAAIAAAADAAAAAgAAAAEAAQAAAAAACAAAABoACgBxEAQA"
    "AAAOAA0BDgAAAAAABQABAAEBAgYEAAEAAAAAAAAAAAASAAAAKwMKAAAAEgAPABIQDwASIA8AAAAAAQIAAQAAAAUAAAAHAAAA"
    "AQAAAAAAAAAAAAAAAwAAABoAAAARAAAABAAACbwEAQnwBAEJnAUBCdAFAAAMAAAAAAAAAAEAAAAAAAAAAQAAABIAAABwAAAA"
    "AgAAAAgAAAC4AAAAAwAAAAUAAADYAAAABQAAAAUAAAAUAQAABgAAAAEAAAA8AQAAAiAAABIAAABcAQAAARAAAAIAAAAkAgAA"
    "AxAAAAIAAAA0AgAAASAAAAQAAAA8AgAAACAAAAEAAADmAgAAABAAAAEAAAD8AgAA"
)
