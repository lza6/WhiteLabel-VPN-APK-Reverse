#!/usr/bin/env python
"""SuperUnlimited (com.free.vpn.super.hotspot.open) 静态资产解密器.

密钥来源：classes.dex `LR3/a;-><clinit>` 的 char[7]="EasyVPN" 与
`LR3/a;->b()` 拼接的 "IKEV2Open" => "EasyVPNIKEV2Open" (16 字节)。
`LR3/a;->a(String)` = Base64.decode(s,2) -> AES/ECB/PKCS5 -> String。

用法：
    python asset_decrypt_easyvpn.py <apk> <asset-path> [output]
"""
import base64
import sys
import zipfile

from Crypto.Cipher import AES

KEY = b"EasyVPNIKEV2Open"


def decrypt(b64_payload: bytes) -> bytes:
    raw = base64.b64decode(b64_payload + b"=" * (-len(b64_payload) % 4))
    return AES.new(KEY, AES.MODE_ECB).decrypt(raw).rstrip(b"\x00")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    apk, asset = sys.argv[1], sys.argv[2]
    payload = zipfile.ZipFile(apk).read(asset)
    plain = decrypt(payload)
    if len(sys.argv) > 3:
        with open(sys.argv[3], "wb") as f:
            f.write(plain)
        print("wrote %s (%d bytes)" % (sys.argv[3], len(plain)))
    else:
        sys.stdout.buffer.write(plain)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())