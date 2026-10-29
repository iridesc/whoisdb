# whois_db

对数据库中已知域名的 **WHOIS 信息进行持续监测**的系统。

- 查询：Web 页面输入域名返回 WHOIS 信息；输入关键字返回关键字相关的 WHOIS 记录（IK 中文分词 + 模糊检索）
- 新鲜度：域名在库中且 WHOIS 更新时间距今 < 1 天则直接返回；否则实时获取
- 变更留痕：实时结果与库中最新记录比对，完全一致则跳过；有差异则以当前时间插入一条新记录，保留完整历史
- 定时刷新：每天批量刷新需要更新的域名

## 现状

项目处于**设计阶段**，尚无实现代码。

- [设计文档](docs/design.md) —— 字段标准调研（RDAP）、实测结论、字段方案、架构设计、**待裁决问题清单**
- `scripts/probe_rdap.py` —— RDAP 实测探针，用于复现设计文档中的实测结论

## 调研结论速览

上游 `whois_lookup`（FastTask 服务）已提供 13 字段归一化的 WHOIS 查询，本项目沿用其字段语义，
并补齐监测必需的扩展字段（`fetched_at` / `content_hash` / `statuses` / `dnssec` 等）。

存储采用 ES **历史版本序列**模型（同一域名多条记录），与 `icp_lookup` 的单文档模型不同。

## 常用命令

```bash
# 复现 RDAP 实测（直连外网不通，经 SOCKS 代理，地址由环境变量注入）
export ALL_PROXY=socks5h://<proxy-host>:<proxy-port>
python3 scripts/probe_rdap.py example.com google.com
```
