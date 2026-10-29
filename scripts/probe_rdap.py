#!/usr/bin/env python3
"""RDAP 实测探针 —— 复现 docs/design.md §3 的实测结论。

用途：
  1. 观察真实注册局 RDAP 响应的官方字段名与取值格式
  2. 验证 §3.2 表中各条结论（T1~T7）是否仍然成立
  3. 为后续扩展采集器提供参考样本

用法：
    python3 scripts/probe_rdap.py                       # 默认探测 example.com / google.com
    python3 scripts/probe_rdap.py example.com foo.com  # 指定域名
    python3 scripts/probe_rdap.py --full               # 打印完整 JSON 响应

注意：
  - 本脚本仅做只读查询，不修改任何数据。
  - 直连外网通常不通，需经 SOCKS 代理（地址不写死在代码里，从环境变量读取）：
        export ALL_PROXY=socks5h://<proxy-host>:<proxy-port>
        export RDAP_PROXY=socks5h://<proxy-host>:<proxy-port>
    也可临时用 --proxy 参数覆盖。
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

DEFAULT_DOMAINS = ["example.com", "google.com"]

USER_AGENT = "whois_db-design-probe/0.1 (+internal research)"


def _resolve_proxy(explicit: str | None = None) -> str | None:
    """代理优先级：命令行参数 > RDAP_PROXY > ALL_PROXY / HTTPS_PROXY。

    代理地址属于内部基础设施信息，不写死在代码里，统一由环境变量注入。
    """
    if explicit:
        return explicit
    for name in ("RDAP_PROXY", "ALL_PROXY", "HTTPS_PROXY", "https_proxy"):
        value = os.environ.get(name)
        if value:
            return value
    return None


def _http_get(url: str, proxy: str | None = None, timeout: int = 30) -> bytes:
    """用 curl 做 HTTP 取数。

    选 curl 而非 urllib：urllib 的 ProxyHandler 不支持 socks5h 代理，
    而本机访问外网必须经 SOCKS 代理，curl 原生支持且系统自带。
    """
    if not shutil.which("curl"):
        raise RuntimeError("未找到 curl，无法执行探测（可改用 requests + PySocks）")

    cmd = ["curl", "-sS", "--compressed", "--max-time", str(timeout),
           "-H", f"Accept: application/rdap+json", "-H", f"User-Agent: {USER_AGENT}"]
    if proxy:
        cmd += ["--proxy", proxy]
    cmd.append(url)

    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip() or f"curl 退出码 {proc.returncode}")
    return proc.stdout


def rdap_urls(domain: str, bootstrap: dict | None = None, proxy: str | None = None) -> list[str]:
    """按 IANA bootstrap 找到该域名的候选 RDAP 服务地址。

    同一 TLD 可能对应多个注册局（如 .com 有多个 RDAP 服务），
    因此返回列表由调用方依次尝试。
    """
    if bootstrap is None:
        bootstrap = load_bootstrap(proxy)
    tld = domain.rsplit(".", 1)[-1].lower()
    for tlds, urls in bootstrap.get("services", []):
        if tld in tlds:
            return [u + f"domain/{domain}" for u in urls]
    raise LookupError(f"IANA bootstrap 中没有 {tld} 的 RDAP 服务")


def load_bootstrap(proxy: str | None = None) -> dict:
    return json.loads(_http_get(RDAP_BOOTSTRAP, proxy))


def fetch_rdap(domain: str, proxy: str | None = None, bootstrap: dict | None = None) -> dict:
    """依次尝试候选 RDAP 服务，首个成功即返回。"""
    errors = []
    for url in rdap_urls(domain, bootstrap, proxy):
        try:
            return json.loads(_http_get(url, proxy))
        except (RuntimeError, TimeoutError) as exc:
            errors.append(f"{url} -> {exc}")
    raise RuntimeError("所有候选 RDAP 服务均失败:\n  " + "\n  ".join(errors))


def probe(domain: str, data: dict) -> None:
    print(f"\n{'=' * 70}")
    print(f"域名: {domain}")
    print(f"{'=' * 70}")

    print(f"顶层成员        : {list(data.keys())}")

    # T2：ldhName 大小写
    ldh = data.get("ldhName")
    print(f"ldhName         : {ldh!r}  (大写? {bool(ldh) and ldh.isupper()})")

    # T1：status 格式
    status = data.get("status") or []
    print(f"status          : {status}")
    if status:
        s = status[0]
        print(f"  → 格式判定    : {'空格分隔小写 (RDAP 风格)' if ' ' in s else 'camelCase (port43 风格)'}")

    # events
    events = data.get("events") or []
    print(f"events          : {len(events)} 条")
    for ev in events:
        date = ev.get("eventDate")
        fmt = "ISO8601 带时区" if (date and ("T" in date and (date.endswith("Z") or "+" in date))) else "其它格式"
        print(f"  - eventAction={ev.get('eventAction')!r:32} eventDate={date!r} ({fmt})")

    # secureDNS
    sdns = data.get("secureDNS") or {}
    if sdns:
        print(f"secureDNS       : zoneSigned={sdns.get('zoneSigned')} delegationSigned={sdns.get('delegationSigned')}")
        for ds in sdns.get("dsData") or []:
            print(f"  - dsData: keyTag={ds.get('keyTag')} algorithm={ds.get('algorithm')} "
                  f"digestType={ds.get('digestType')} digest={str(ds.get('digest'))[:16]}…")
    else:
        print("secureDNS       : (无)")

    # entities（T3 / T6）
    entities = data.get("entities") or []
    print(f"entities        : {len(entities)} 个")
    for ent in entities:
        roles = ent.get("roles")
        ids = ent.get("publicIds")
        vcard = ent.get("vcardArray")
        fn = ""
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "fn":
                    fn = item[-1]
        print(f"  - roles={roles} handle={ent.get('handle')!r} fn={fn!r}")
        if ids:
            for pid in ids:
                print(f"      publicIds: type={pid.get('type')!r} identifier={pid.get('identifier')!r}")
        for sub in ent.get("entities") or []:
            print(f"      >> nested roles={sub.get('roles')}")

    # T3：registrant 是否存在
    roles_all = {r for ent in entities for r in (ent.get("roles") or [])}
    print(f"含 registrant?  : {'是' if 'registrant' in roles_all else '否（RDAP 下 registrant 常被整体移除）'}")
    print(f"含 redacted 成员?: {'是' if 'redacted' in data else '否'}")

    # nameservers
    nss = data.get("nameservers") or []
    print(f"nameservers     : {len(nss)} 个 -> {[ns.get('ldhName') for ns in nss][:5]}")

    print(f"rdapConformance : {data.get('rdapConformance')}")
    notices = data.get("notices") or []
    if notices:
        print(f"notices         : {len(notices)} 条 -> titles={[n.get('title') for n in notices]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="RDAP 实测探针")
    parser.add_argument("domains", nargs="*", default=DEFAULT_DOMAINS, help="待探测域名")
    parser.add_argument("--full", action="store_true", help="打印完整 JSON 响应")
    parser.add_argument("--proxy", default=None, help="代理地址（默认取 RDAP_PROXY / ALL_PROXY 环境变量）")
    args = parser.parse_args()
    args.proxy = _resolve_proxy(args.proxy)

    try:
        bootstrap = load_bootstrap(args.proxy)
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] 拉取 IANA bootstrap 失败: {exc}", file=sys.stderr)

    for domain in args.domains:
        try:
            data = fetch_rdap(domain, proxy=args.proxy, bootstrap=bootstrap)
        except (LookupError, RuntimeError, TimeoutError) as exc:
            print(f"\n[skip] {domain}: 查询失败 -> {exc}", file=sys.stderr)
            continue
        probe(domain, data)
        if args.full:
            print(json.dumps(data, ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
