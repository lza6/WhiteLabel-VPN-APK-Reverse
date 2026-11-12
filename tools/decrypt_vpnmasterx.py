#!/usr/bin/env python
"""com.vpnmasterx.fast  (VPN Proxy Master 2.3.6) 报文解密器.

来源（静态还原，lib/arm64-v8a/libnative.so）：

  to_data_password  @0x36338
    snprintf(buf, 200, "%s_%s",
             "d770ff1b0e4238377b06952b448c99d7b42c5caa",
             "aca8fb1bed0a6547bc5a422eb9a966aa")
    -> qB2vL4sZ6o(env, "SHA1", jstring)      # MessageDigest("SHA1") + "%02x"
    -> strncpy(dst, hex, 0x20)               # 取 SHA1 十六进制前 32 字符
    -> NewStringUTF(dst)

  mB1wU3gS3h  @0x353ec  (Java decryptData 的实现)
    SecretKeySpec(password.getBytes("UTF-8"), "AES")
    Cipher.getInstance("AES/CFB/NoPadding")
    IvParameterSpec(<.data:0x64010 的 16 字节常量>)
    Cipher.init(2 /* DECRYPT */, key, iv) -> doFinal(data)

  常量 IV 位于 .data:0x64010 = 00 01 02 ... 0f

注：decryptApi([B I I String String J) 走的是另一条带外部 key 的分支，本脚本只覆盖
decryptData —— 常量密钥这条，用于静态嵌入的密文。
"""
import base64
import hashlib
import sys

from Crypto.Cipher import AES

_SEED = (
    b"d770ff1b0e4238377b06952b448c99d7b42c5caa"
    b"_"
    b"aca8fb1bed0a6547bc5a422eb9a966aa"
)

KEY = hashlib.sha1(_SEED).hexdigest()[:32].encode()   # 32 ASCII 字节 -> AES-256
IV = bytes(range(16))                                  # .data:0x64010


def decrypt_data(payload_b64) -> bytes:
    """入参是 Java 侧 Base64.decode(s, 3) 之前的字符串。"""
    raw = base64.b64decode(payload_b64)
    return AES.new(KEY, AES.MODE_CFB, iv=IV, segment_size=128).decrypt(raw)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    arg = sys.argv[1]
    if arg == "--key":
        print("key =", KEY.decode())
        print("iv  =", IV.hex())
        return 0
    if arg.startswith("@"):
        data = open(arg[1:], "rb").read()
    else:
        data = arg.encode()
    sys.stdout.buffer.write(decrypt_data(data))
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())