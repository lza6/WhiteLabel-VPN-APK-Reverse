# new-api 代理池对接指南

面向：接手对接的会话 / 运维。

## 0. 先说现状

本仓库目前 **0 条可用节点**。四个样本的节点都在账号态之后，静态侧未产出任何
`ss://` / `vless://` / `vmess://` / `trojan://` 链接。

所以这份文档分两半：**第一半是现在就能验证的池文件契约与接入方式**，第二半是
节点产出之后要走的流水线。不要把本文档当成「已经有池」来用。

## 1. 池文件契约

`data/proxies.txt`，一行一个：

```
# 注释行（# 开头，整行）
socks5://1.2.3.4:1080
socks5h://5.6.7.8:1080
```

硬约束（来自 new-api 的解析实现，不是我们的约定）：

| 项 | 事实 |
|---|---|
| 解析方式 | **逐行整行 `url.Parse`** |
| 注释 | **只跳过 `#` 开头的整行**，不支持行尾注释 |
| scheme 白名单 | `http` / `https` / `socks5` / `socks5h`，其它一律丢弃 |
| 空行 | 跳过 |
| 去重 | new-api 不做，需要我们自己保证 |

`# 1.2.3.4:1080  # 备用` 这种写法会让整行解析失败并被丢掉——写注释就单独占一行。

## 2. new-api 侧配置

```bash
# 单个池
TRYINGOPEN_PROXY_FILE=/data/pools/vpn-batch.txt

# 多个池，逗号分隔
TRYINGOPEN_PROXY_FILE=/data/pools/vpn-batch.txt,/data/pools/other.txt
```

两个坑：

1. **来源卡片名 = `filepath.Base(file)`**。一个池一个文件名，前端会自动分成独立卡片；
   两个池叫同一个文件名就会互相覆盖显示。
2. **Docker 里 `127.0.0.1` 指容器自身**。如果代理跑在宿主机上，池文件里必须写宿主机
   在容器网络里可达的地址（同 network namespace 时可用容器 IP，否则用宿主 IP 或
   `host.docker.internal`），写 `127.0.0.1:1080` 只会连到容器自己。

国内 DNS 污染场景优先用 `socks5h://`，让远端解析域名。

热更新：`POST /api/twoapi_panel/proxy_pool/reload`。
**待验证** —— 这个接口在当前部署的 new-api 版本上是否存在，需要对接会话先
`curl` 一次确认；不存在就重启进程或依赖轮询。

## 3. 节点产出 → 入池流水线

```
harvest.py        →  data/nodes.json      归一化节点（locations → servers → protocols）
refresh_pool.py   →  data/proxies.txt     每节点一条 socks5://，整体覆写不累积
demo/stress       →  data/stress.json     存活率 + 平均延迟 + 出口 IP
（人工确认）
  → 写入 new-api 的 TRYINGOPEN_PROXY_FILE
  → POST /api/twoapi_panel/proxy_pool/reload
  → 验收
```

三条来自实战的硬规则：

1. **入池只认二级结果**。TCP/TLS 握手通只说明端口开着，必须经代理实际发一次请求
   （`gstatic/generate_204` + 出口 IP 比对），一级过滤会放进大量假活。
2. **出口 IP 必须等于节点 IP**。不等就说明中间还有一层转发，不是真隧道。
3. **延迟阈值是必要不充分条件**。出现过 RTT 正常但 6 并发全挂的节点，高延迟节点
   要人工剔。

## 4. 验收

```bash
# 1) 池文件能被解析（行数 = 期望节点数）
grep -vc '^#' data/proxies.txt

# 2) 经代理拿出口 IP，必须等于节点自身 IP
python -I tools/stress_pool.py --proxy socks5://HOST:PORT --ip-check

# 3) 全池压测
python -I tools/stress_pool.py --target www.gstatic.com:443 --concurrency 8 --rounds 3
```

第 3 步的产出是 `data/stress.json`：`entries` / `attempts` / `ok` / `success_rate` /
`avg_ms`。**成功率 100% 且 avg_ms 正常**才算这一批能用。

## 5. 本机自检（现在就能跑）

池为空时，压测台会如实返回 `entries: 0`，不会伪造数据。要验证链路本身，
可以用仓库自带的 SOCKS5 夹具：

```bash
python -I tools/selftest_socks5.py 24099
echo "socks5://127.0.0.1:24099" > data/proxies.txt
python -I demo/demo_server.py     # http://127.0.0.1:9099 → 代理池压测 → 开始压测
```

2026-11-12 实测：`entries=1 attempts=3 ok=3 rate=100.0% avg=31.1ms`。
自检完记得把夹具条目从 `data/proxies.txt` 删掉。

## 6. 不要做的事

- 不要在跑着 v2rayN/xray 的机器上用 `HTTP_PROXY` 环境变量做测活——代理层会把流量
  再绕一圈，出口 IP 全变成代理 IP，节点集合和延迟数据全废。本仓库全部脚本用裸
  socket 直连，就是为了避开这个。
- 不要把 `127.0.0.1` 写进 Docker 里的池文件。
- 不要在生产主机上跑全池压测。