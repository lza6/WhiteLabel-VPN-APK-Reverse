# 白标 VPN APK 逆向 · 四样本静态分析

对四个 Android VPN 应用做静态逆向：架构辨认、协议栈还原、native 密钥链还原、端点实测。
**结论：这批样本不产出可用代理节点。** 记录过程与工具，供下一个样本复用。

## 结论速览

| # | 文件 | 真实包名 | 隧道内核 | 节点来源 | 静态可产出 |
|---|---|---|---|---|---|
| 1 | ExpressVPN v12.71.0 (PREMIUM).apk | `com.free.vpn.super.hotspot.open` | Xray + OpenVPN + IKEv2 + Trojan | 账号态下发 | 否 |
| 2 | Proxy Master v5.4.5 (Premium).apk | `com.free.vpn.proxy.master.app` | sing-box + 私有 TLS+ | AllConnect 初始化接口 | 否 |
| 3 | VPN Proxy Master v2.3.6 [Premium].apk | `com.vpnmasterx.fast` | OpenVPN3 / OpenVPN2 | protobuf 下发 | 否 |
| 4 | VPN v206 (Premium).apk | `com.starnest.vpnandroid` | ICS OpenVPN | 配置下发 | 否 |

四个样本**没有一条** `ss://` / `vless://` / `vmess://` / `trojan://` 链接。节点全在账号态之后。

文件名不可信：`ExpressVPN v12.71.0` 的真实包名是 `com.free.vpn.super.hotspot.open`，
内部命名空间 `com.superunlimited.*`，品牌是 SuperUnlimited VPN，与 ExpressVPN 无关。

## 已经拿到的

| 产出 | 说明 |
|---|---|
| `tools/decrypt_vpnmasterx.py` | `com.vpnmasterx.fast` 报文解密：AES-256-CFB，key/IV 全部静态还原 |
| `tools/asset_decrypt_easyvpn.py` | SuperUnlimited 静态资产解密：AES-128-ECB，密钥 `EasyVPNIKEV2Open` |
| `loot/open_readme.decrypted` | 解出来的 OpenVPN 模板 + 内嵌 CA（2096 字节） |
| `docs/01-深度分析.md` | 四样本完整逆向报告（九节，含 native 层） |
| `docs/02-new-api对接指南.md` | 代理池接入 new-api 的文件契约、配置、验收 |
| `docs/03-方法论与工具.md` | 判路线顺序、jadx 替代方案、ELF/JNI 恢复、五层节点来源模型 |
| `data/probes.json` | 9 个端点实测：TCP 可达 7、TLS 1.3 成功 6 |
| `demo/` | 样本看板 + 端点探测 + 代理池压测台（127.0.0.1:9099） |

## 关键发现

**1. 密钥链的形式决定了可行性。** 三个 native 库都没加壳、符号表都在：

- `libnative.so`（vpnmasterx）：通过 `natiflect` C++ 反射桥回调 Java `Cipher`，
  算法与密钥都在 native 侧，符号未剥离 —— 一路读到底，拿到 key/IV。
- `libsswanutils.so`（Proxy Master 5.4.5）：`RegisterNatives` 注册 9 个方法，
  表在 `.data`，指针全是 `R_AARCH64_RELATIVE`。全解出来后发现 `TlsPlusManager.f`
  前面卡着签名指纹比对 `cmp w22, #0xE8A612C2`，原厂商证书不在包里。
- `libnative-legacy.so`（SuperUnlimited）：`getKeyBytes` 是三段 8 字节 XOR 0xA5，
  解出 24 字节 key；但对不上包内那批 `assets/server*`，且该批文件长度格式自相矛盾。

**2. 卡点不是混淆，是输入。** 三套链分别缺：原厂商签名证书、设备侧 key、账号登录态。
三者都指向同一件事 —— 要节点必须有能跑起来的环境。

**3. 广告域冒充业务域。** `api.{keysuccess,inmense,dollphoin,kickoffo}.site` 实测统一返回
`405 {"msg":"invalid uri"}`，看着像同一套后端，反查引用方全是 `sg.bigo.ads` —— 广告变现中台，
与节点无关。`rx3.io` 同理，那是 RxJava3 的系统属性键 `rx3.io-priority`，不是域名。

## 目录

```
docs/    01 逆向报告 · 02 new-api 对接 · 03 方法论
tools/   DEX 字符串/xref/类反汇编 · ELF 反汇编/交叉引用/PLT/vaddr · 两个解密器 · 压测
demo/    看板（样本 + 端点 + 压测）
data/    samples / endpoints / probes / proxies.txt
loot/    解出来的资产
```

## 跑起来

```bash
python -I demo/demo_server.py            # http://127.0.0.1:9099
python -I tools/stress_pool.py --pool data/proxies.txt --concurrency 8 --rounds 3
python -I tools/stress_pool.py --proxy socks5://HOST:PORT --ip-check
```

看板会真实显示当前池状态。池空时它显示空，不编数字。

全部脚本裸 socket 直连，不读 `HTTP_PROXY`、不写注册表、不改 DNS，
只监听 `127.0.0.1`。跑着 v2rayN/xray 的机器上不会互相干扰。

## new-api 对接

见 `docs/02-new-api对接指南.md`。要点：池文件逐行整行 `url.Parse`、只认 `#` 开头的
整行注释、scheme 白名单 `http/https/socks5/socks5h`、Docker 里 `127.0.0.1` 指容器自身。
**目前池为空**，文档第二半是节点产出后的流水线。

## 路线图

- [x] 四样本架构与协议栈还原
- [x] 三套 native 密钥链静态分析
- [x] 端点实测与看板
- [ ] 能跑 arm64 的运行环境（官方 emulator 拒绝在 x86_64 主机加载 arm64 镜像）
- [ ] `com.vpnmasterx.fast` 的 API 基址（运行时构造，dex/so 无明文）
- [ ] `com.starnest.vpnandroid` 的 API 主机（唯一带 x86_64 原生库，可直接在 x86_64 AVD 跑）

## 合规

样本为第三方商业应用。本文档仅用于安全研究与互操作性分析，不含任何用户凭据。
文中出现的常量均为应用内硬编码值，用于复现分析过程。节点属厂商资源，
对外售卖或大规模转售属未授权使用。