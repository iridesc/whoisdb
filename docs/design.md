# whois_db 设计文档

> 状态：**草案，待裁决**
> 文档版本：v0.1（2025-10-29）
> 说明：本文中标记 `【待裁决】` 的条目为尚未确定的设计决策，需产品/架构负责人拍板后再进入实现。

---

## 1. 项目定位

whois_db 是一个**对数据库中已知域名的 WHOIS 信息进行持续监测**的系统。

核心能力：

1. **查询**：Web 页面输入域名，返回该域名的 WHOIS 信息；输入关键字，返回关键字相关的 WHOIS 记录。
2. **新鲜度策略**：若域名在库中，且其 WHOIS 信息的更新时间距今 < 1 天，直接返回库中数据；否则实时获取。
3. **变更留痕**：实时获取后与库中最新记录比对——
   - 信息**完全一致** → 跳过，不写入；
   - 信息**有差异** → 以当前时间插入一条**新的**记录，保留完整历史。
4. **定时刷新**：每天对需要更新的域名批量刷新 WHOIS 信息。
5. **模糊检索**：需要 IK 中文分词，支持按关键字模糊查询（主办单位名、注册人、注册商等中文字段）。

### 1.1 与现有项目的关系

调查发现，EISA 生态内已存在 ICP 备案查询服务（`icp_lookup`）与 WHOIS 查询服务（`whois_lookup`）。本项目**不是**它们的重复建设，而是它们的下游：

```
pypywhois / whois 命令
  └─> whois_lookup (FastTask :9018)      13 字段归一化 + 24h 缓存 + 隐私保护识别
        └─> eisa_whois_lookup (MCP)        create_get_domain_whois / check_get_domain_whois
              └─> easm-scout              domain 表 14 个 whois_* 列（静态快照）
                    └─> whois_db (本项目)  历史版本序列 + 变更监测 + Web 查询
```

### 1.2 现状调研结论

| 项目 | whois 字段体系 | 存储模型 | 与本项目的关系 |
|---|---|---|---|
| `whois_lookup` | 13 个标准字段（去 `whois_` 前缀） | 无存储（纯查询 + 24h 缓存） | **直接上游**，字段语义与踩坑经验需继承 |
| `easm-scout` | 14 列（13 + `whois_is_registered`） | SQLite `domain` 表，`domain` 为 PRIMARY KEY，静态快照 | **下游消费方**，字段名已对齐 |
| `icp_lookup` | ICP 备案 8 字段 | ES 单文档（域名即 `_id`） | 同构参考，但存储模型不同 |

**结论**：本项目的字段体系应**沿用上游 13 字段语义与命名**，保证 EISA 生态内一致，避免三处映射。

---

## 2. 字段标准调研：RDAP

### 2.1 标准体系

| RFC | 名称 | 作用 |
|---|---|---|
| RFC 9083 (2021) | RDAP Query Format | 现行查询协议，取代 RFC 7482 |
| RFC 7483 (2015) | RDAP JSON Responses | 对象类定义（domain/entity/nameserver），现仍有效 |
| RFC 7095 (2014) | jCard | JSON 格式的 vCard 4.0 |
| RFC 9537 (2024) | Redacted Fields in RDAP | `redacted` 成员（GDPR 脱敏） |
| RFC 9535 (2023) | JSONPath | `prePath` / `postPath` 路径语言 |
| RFC 3912 | port 43 WHOIS | 传统 WHOIS 协议（RDAP 前身） |

媒体类型：`application/rdap+json`

### 2.2 三种对象类（`objectClassName`）

**`domain`（域名对象，RFC 7483 §5.3）**

```json
{
  "objectClassName": "domain",
  "handle": "2336799_DOMAIN_COM-VRSN",
  "ldhName": "EXAMPLE.COM",
  "unicodeName": "…",
  "variants": [...],
  "nameservers": [ … ],
  "secureDNS": { … },
  "entities": [ … ],
  "status": [ "client transfer prohibited" ],
  "publicIds": [ … ],
  "remarks": [ … ],
  "links": [ … ],
  "port43": "…",
  "events": [ … ],
  "redacted": [ … ]
}
```

**`entity`（实体对象，§5.1）**

```json
{
  "objectClassName": "entity",
  "handle": "292",
  "vcardArray": ["vcard", [ ["fn",{},"text","MarkMonitor Inc."], … ]],
  "roles": [ "registrar" ],
  "publicIds": [ {"type":"IANA Registrar ID","identifier":"292"} ],
  "entities": [ … ],
  "status": [ "proxy", "private", "obscured" ],
  "events": [ … ],
  "asEventActor": [ … ],
  "remarks": [ … ], "links": [ … ], "port43": "…"
}
```

**`nameserver`（NS 对象，§5.2）**

```json
{
  "objectClassName": "nameserver",
  "handle": "…",
  "ldhName": "ELLIOTT.NS.CLOUDFLARE.COM",
  "unicodeName": "…",
  "ipAddresses": { "v4": ["…"], "v6": ["…"] },
  "entities": [ … ], "status": [ … ], "events": [ … ]
}
```

### 2.3 公共数据结构（RFC 9083 §4）

| § | 成员 | 子字段 |
|---|---|---|
| 4.1 | `rdapConformance` | 扩展标识符数组，如 `["rdap_level_0","icann_rdap_response_profile_1"]` |
| 4.2 | `links[]` | `value` / `rel` / `href` / `hreflang` / `title` |
| 4.3 | `notices[]` / `remarks[]` | `title` / `description[]` / `type` |
| 4.4 | `lang` | 语言标识符 |
| 4.5 | `events[]` | `eventAction` / `eventDate` / `eventActor` / `links` |
| 4.6 | `status[]` | 字符串数组 |
| 4.7 | `port43` | WHOIS 服务器 FQDN/IP（字符串，**不是 URI**） |
| 4.8 | `publicIds[]` | `type` / `identifier` |
| 4.9 | `objectClassName` | 对象类名 |

`secureDNS` 子字段（RFC 9083 §5.3）：`zoneSigned` / `delegationSigned` / `maxSigLife` /
`dsData[]`（`keyTag` / `algorithm` / `digestType` / `digest`）/ `keyData[]`（`flags` / `protocol` / `publicKey` / `algorithm`）

### 2.4 vCard（jCard）属性官方名（RFC 7095）

| 属性 | 官方含义 | RDAP 中对应 |
|---|---|---|
| `fn` | Formatted Name | 注册人姓名 |
| `n` | Structured Name | 结构化姓/名 |
| `org` | Organization Name | 注册人单位 |
| `adr` | Address | `po-box`/`extended`/`street`/`locality`/`region`/`postal-code`/`country` |
| `email` | Electronic Mail Address | |
| `tel` | Telephone Number（uri 形式 `tel:+1.201.555.0123`） | |
| `url` | URL | |
| `note` | Note | |

### 2.5 IANA "RDAP JSON Values" 注册表现值

**`eventAction`（12 个）**

`registration` / `reregistration` / `last changed` / `expiration` / `deletion` /
`reinstantiation` / `transfer` / `locked` / `unlocked` /
`last update of RDAP database` / `registrar expiration` / `enum validation expiration`

**`roles`（11 个）**

`registrant` / `technical` / `administrative` / `abuse` / `billing` / `registrar` /
`reseller` / `sponsor` / `proxy` / `notifications` / `noc`

**`status`（39 个）**

- RFC 7483 基础 15 个：`validated` `renew prohibited` `update prohibited`
  `transfer prohibited` `delete prohibited` `proxy` `private` `removed` `obscured`
  `associated` `active` `inactive` `locked` `pending create` `pending renew`
  `pending transfer` `pending update` `pending delete`
- EPP 扩展：`add period` `auto renew period` `client delete prohibited` `client hold`
  `client renew prohibited` `client transfer prohibited` `client update prohibited`
  `pending restore` `redemption period` `renew period` `server delete prohibited`
  `server renew prohibited` `server transfer prohibited` `server update prohibited`
  `server hold` `transfer period`
- 其他：`administrative` `reserved`

**`redacted name`（17 个）**

`Registry Domain ID` / `Registry Registrant ID` / `Registrant Name` /
`Registrant Organization` / `Registrant Street` / `Registrant City` /
`Registrant Postal Code` / `Registrant Phone` / `Registrant Phone Ext` /
`Registrant Fax` / `Registrant Fax Ext` / `Registrant Email` /
`Registry Tech ID` / `Tech Name` / `Tech Phone` / `Tech Phone Ext` / `Tech Email`

### 2.6 字段映射表

| 传统 WHOIS | RDAP 官方叫法 | 上游 13 字段 |
|---|---|---|
| Domain Name | `ldhName`（大写）/ `unicodeName` | — |
| Registry Domain ID | `handle`（domain 对象） | — |
| Registrar | `entities[].roles=["registrar"].vcardArray[fn]` | `registrar` |
| Registrar IANA ID | `entities[].publicIds[type="IANA Registrar ID"].identifier` | — |
| Creation Date | `events[eventAction="registration"].eventDate` | `creation_date` |
| Updated Date | `events[eventAction="last changed"].eventDate` | `updated_date` |
| Registry Expiry Date | `events[eventAction="expiration"].eventDate` | `expiration_date` |
| Domain Status | `status[]` | — |
| Name Server | `nameservers[].ldhName` | `name_servers` |
| DNSSEC | `secureDNS.delegationSigned` / `zoneSigned` | — |
| Registrant Name | `entities[].roles=["registrant"].vcardArray[fn]` | `registrant_name` |
| Registrant Organization | `…vcardArray[org]` | `registrant_organization` |
| Registrant Street/City/Region/Postal/Country | `…vcardArray[adr]` | `registrant_address` / `_city` / `_province` / `_country` |
| Registrant Phone | `…vcardArray[tel]` | `registrant_phone` |
| Registrant Email | `…vcardArray[email]` | `registrant_email` |
| WHOIS Server | `port43` | — |

---

## 3. 实测结果

调研过程中对真实注册局 RDAP 服务做了实际请求，记录如下。

### 3.1 RDAP 响应样本（Verisign .com）

```json
{
  "objectClassName": "domain",
  "handle": "2336799_DOMAIN_COM-VRSN",
  "ldhName": "EXAMPLE.COM",
  "status": ["client delete prohibited","client transfer prohibited","client update prohibited"],
  "secureDNS": {"delegationSigned": true,
                "dsData":[{"keyTag":2371,"algorithm":13,"digestType":2,"digest":"C988EC42…"}]},
  "events": [
    {"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
    {"eventAction":"expiration","eventDate":"2027-08-13T04:00:00Z"},
    {"eventAction":"last changed","eventDate":"2026-08-14T08:01:43Z"},
    {"eventAction":"last update of RDAP database","eventDate":"2026-10-29T11:15:00Z"}
  ],
  "entities": [{
    "objectClassName":"entity","handle":"292","roles":["registrar"],
    "publicIds":[{"type":"IANA Registrar ID","identifier":"292"}],
    "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","MarkMonitor Inc."]]],
    "entities":[{"roles":["abuse"],
                 "vcardArray":["vcard",[["tel",{"type":"voice"},"uri","…"],["email",{},"text","…"]]]}]
  }],
  "nameservers":[{"objectClassName":"nameserver","ldhName":"ELLIOTT.NS.CLOUDFLARE.COM"}],
  "rdapConformance":["rdap_level_0","icann_rdap_technical_implementation_guide_1",
                     "icann_rdap_response_profile_1"],
  "notices":[{"title":"Terms of Service","description":["…"],
              "links":[{"rel":"terms-of-service",…}]}]
}
```

### 3.2 关键实测结论

| # | 结论 | 影响 |
|---|---|---|
| T1 | RDAP `status` 用**小写空格分隔**（`client transfer prohibited`），传统 port43 用 **camelCase**（`clientTransferProhibited`） | 需要归一化映射表，否则 diff 产生假变更 |
| T2 | RDAP `ldhName` 返回**大写**（`EXAMPLE.COM`），上游 13 字段体系全程用小写 | 入库前必须 `lowercase()`，否则域名主键匹配失败 |
| T3 | RDAP 下 registrant 联系人**基本拿不到**：`google.com` 的 `entities` 仅含 registrar 一个，registrant 被整体移除，且无 `redacted` 成员 | RDAP **不应**作为唯一数据源；传统 port43 反而能拿到更多 registrant 字段（脱敏后仍保留部分） |
| T4 | RDAP `eventDate` 是 **ISO 8601 带时区**（`1995-08-14T04:00:00Z`），上游用的是 `YYYY-MM-DD` | 建议日期统一升级为 ISO 8601，秒级精度对"到期倒计时"是刚需 |
| T5 | RDAP 能拿到 `status` / `secureDNS` / `events` / `publicIds`，而这些**上游 13 字段全部缺失** | RDAP 适合作为**补充源**，补齐监测关键字段 |
| T6 | 注册商 IANA ID 官方位置是 `entities[].publicIds[type="IANA Registrar ID"].identifier` | 可作为 `registrar_iana_id` 字段来源 |
| T7 | RDAP 顶层存在 `notices` / `links` / `rdapConformance`，上游 13 字段未覆盖 | `notices` 含服务条款/投诉入口，业务上可选保留 |
| T8 | `nameservers[].ldhName` 同样是**大写**（`NS1.GOOGLE.COM`） | NS 入库同样需 `lowercase()` |
| T9 | 同一 TLD 在 IANA bootstrap 中对应**多个** RDAP 服务（如 `.com` 有多个注册局），需依次回退 | 采集器必须实现多服务回退，否则会随机超时 |

### 3.3 实测复现方式

直连外网不通，需经 SOCKS 代理（地址不写入仓库，由环境变量注入）：

```bash
export ALL_PROXY=socks5h://<proxy-host>:<proxy-port>
python3 scripts/probe_rdap.py example.com google.com
# 或临时指定：python3 scripts/probe_rdap.py --proxy socks5h://<proxy-host>:<proxy-port> example.com
```

输出包含：顶层成员列表、`ldhName` 大小写判定、`status` 格式判定、`events` 时间格式、
`secureDNS` 摘要、`entities` 的 roles / publicIds / 嵌套实体、`nameservers`、
`rdapConformance`、`notices` 标题，以及 registrant 是否存在、是否有 `redacted` 成员。

### 3.4 上游 `whois_lookup` 已踩过的坑（必须继承）

来自 `whois_lookup/tasks/packages/whois_kit.py`：

1. ⚠️ **pypywhois 的 `name` / `tld` 是被查询域名自身**（未注册域名也会返回）。
   绝不能当作注册人信息使用，否则"未注册域名"会被误判为"已注册"。
2. 隐私保护关键词覆盖 9 种（`privacy` / `private` / `redacted` / `statutory masking enabled` /
   `non-public data` / `隐私保护` / `whois agent` / `domain administrator` / `domain admin`），
   命中后 4 个注册者字段统一改写为 `隐私保护`。
3. 日期归一化：datetime / list[datetime] → `YYYY-MM-DD`。
4. `registrant_country` 统一大写（`CN`）。
5. 多值字段（email / name_servers）去重 + 小写 + 英文逗号连接。
6. 查询失败与"未注册"在上游**无法区分**（均为 13 字段全空）——本项目必须区分，见 Q3。

---

## 4. 字段方案

### 4.0 设计总基调（已裁决）

**平铺为主 + 原始文档兜底**：

- 需要检索 / diff 的核心字段拍平成平铺字段；天然多值字段用 `keyword[]` 数组，不拍成逗号串
- 其余信息（admin/tech 联系人、NS 的 IP、RDAP 原始嵌套结构等）**不拍平**，统一由原始文档
  （`raw_whois`，后续抓取模块若走 RDAP 则另存 `raw_rdap`）兜底，需要时再翻
- 字段命名对齐 **RDAP / vCard 官方术语**，snake_case，不迁就上游 / EISA 生态旧命名

> 依据：RDAP 是嵌套 JSON 文档（见 §2.2），全拍平会丢结构、全保留嵌套会难检索难 diff，
> 故取「拍平核心 + raw 兜底」。

### 4.1 字段总表（23 个平铺字段）

类型列含义：`kw`=keyword，`kw[]`=keyword 数组，`ik`=text(ik_max_word 分词)，
`date`=date（ISO8601），`bool`=boolean，`raw`=text(index:false)。

#### 域名与系统元数据

| 字段 | 类型 | 说明 | RDAP 官方路径 |
|---|---|---|---|
| `domain` | kw | 域名（小写化），查询主键 | `ldhName`（小写化） |
| `fetched_at` | date | 本次抓取时间，判断 1d 新鲜度、排序取最新 | —（系统生成） |
| `query_status` | kw | `ok` / `not_found` / `error`，区分失败与未注册 | —（系统生成） |
| `content_hash` | kw | 规范化核心字段 hash，判断"完全一致则跳过" | —（计算） |
| `raw_whois` | raw | 原始文档兜底（溯源/排障，不参与检索；体积问题后置） | —（原始响应） |

#### 生命周期（RDAP `events[].eventAction`）

| 字段 | 类型 | 说明 | RDAP 官方路径 |
|---|---|---|---|
| `registration_date` | date | 创建时间 | `events[eventAction=registration].eventDate` |
| `expiration_date` | date | 过期时间 | `events[eventAction=expiration].eventDate` |
| `last_changed_date` | date | 注册局最后变更时间 | `events[eventAction=last changed].eventDate` |

#### 状态与 DNSSEC

| 字段 | 类型 | 说明 | RDAP 官方路径 |
|---|---|---|---|
| `status` | kw[] | EPP 状态码数组（如 `clientTransferProhibited`） | `status[]` |
| `zone_signed` | bool | 区域是否已签名 | `secureDNS.zoneSigned` |
| `delegation_signed` | bool | 父区是否有 DS 记录 | `secureDNS.delegationSigned` |

#### 名称服务器与注册商

| 字段 | 类型 | 说明 | RDAP 官方路径 |
|---|---|---|---|
| `nameservers` | kw[] | NS 主机名列表（小写化） | `nameservers[].ldhName` |
| `registrar` | ik | 注册商名称 | `entities[roles=registrar].vcardArray[fn]` |
| `registrar_iana_id` | kw | 注册商 IANA ID | `entities[roles=registrar].publicIds[type="IANA Registrar ID"].identifier` |

#### 注册人（vCard 属性，`entities[roles=registrant]`）

| 字段 | 类型 | 说明 | vCard 官方属性 |
|---|---|---|---|
| `registrant_name` | ik | 注册人姓名，隐私保护时为「隐私保护」 | `fn` |
| `registrant_organization` | ik | 注册人单位 | `org` |
| `registrant_phone` | kw | 注册人电话，**存 URI 原值**（`tel:+1-555-555-1234;ext=102`） | `tel` |
| `registrant_email` | kw | 注册人邮箱 | `email` |
| `registrant_street` | ik | 街道地址 | `adr[2]` street address |
| `registrant_locality` | ik | 城市 | `adr[3]` locality |
| `registrant_region` | ik | 州/省 | `adr[4]` region |
| `registrant_postal_code` | kw | 邮编 | `adr[5]` postal code |
| `registrant_country` | kw | 国家/地区（ISO 3166-1 alpha-2 代码，如 `CN`） | `adr[6]` country name |

> `adr[0]`（post office box）与 `adr[1]`（extended address）不拍平，由 raw 兜底。

### 4.2 字段命名与值域约定（已裁决）

- **命名风格**：snake_case；语义取 RDAP / vCard 官方术语（`fn`→name、`org`→organization、`tel`→phone）。
- **日期**：统一 ISO8601 带时区（如 `2027-08-13T04:00:00Z`）；ES `date` 类型。
- **域名与 NS**：入库前统一小写化（RDAP 实测 `ldhName` 返回大写）。
- **status**：沿用 RDAP 风格（小写空格分隔，如 `client transfer prohibited`）；
  若抓取源为 port 43 的 camelCase（`clientTransferProhibited`），由抓取模块归一化为 RDAP 风格后再入库。
- **`registrant_country` 值域**：存 ISO 3166-1 alpha-2 代码（如 `CN`）。
  注：RDAP 官方 `adr[6]` 语义为 country name（全名），但注册局实际返回不统一（全名/代码都有），
  抓取模块需统一归一化为 alpha-2 代码后再入库。

### 4.3 `content_hash` 参与字段

**参与**（语义字段）：`registration_date`、`expiration_date`、`last_changed_date`、
`status`、`zone_signed`、`delegation_signed`、`nameservers`、`registrar`、
`registrar_iana_id`、`registrant_name`、`registrant_organization`、`registrant_phone`、
`registrant_email`、`registrant_street`、`registrant_locality`、`registrant_region`、
`registrant_postal_code`、`registrant_country`

**不参与**（易变噪声）：`domain`（主键不变）、`fetched_at`、`query_status`、
`content_hash`、`raw_whois`

规范化规则：所有值 trim + 小写；多值字段（`status`、`nameservers`）排序后拼接；`None` 与 `""` 等价。

## 5. 存储设计

### 5.1 索引模型

| 项 | 设计 | 理由 |
|---|---|---|
| 索引名 | `whois_records` | — |
| `_id` | **ES 自动生成** | 与 `icp_lookup` 不同：同一域名会有多条历史记录，域名不能做 `_id` |
| `domain` | keyword，多文档 | 查询主键 |
| 时间序列 | 每次内容变化插入一条新文档 | 保留完整变更历史 |
| 最新记录 | 按 `domain` + `fetched_at` 倒序取第一条 | — |

### 5.2 IK 分词配置

需要 IK 中文分词的字段（索引 `ik_max_word` 细粒度 / 查询 `ik_smart` 粗粒度）：

| 字段 | 说明 |
|---|---|
| `registrar` | 注册商名（中英文混合） |
| `registrant_name` | 中文姓名 |
| `registrant_organization` | 中文机构名 |
| `registrant_street` | 中文街道地址 |
| `registrant_locality` | 城市 |
| `registrant_region` | 州/省 |

其余 `kw` / `kw[]` 字段（`domain`、`status`、`nameservers`、`registrar_iana_id`、
`registrant_phone` / `registrant_email` / `registrant_postal_code` / `registrant_country`）
用 keyword 精确匹配；域名片段模糊检索见检索设计（待补）。

沿用 `icp_lookup/tasks/packages/es.py` 的 analyzer 定义（`ik_smart_analyzer` / `ik_max_word_analyzer`），
需 ES 镜像带 IK 插件。

### 5.3 与 `icp_lookup` 的差异对照

| 维度 | `icp_lookup` | `whois_db` |
|---|---|---|
| `_id` | 域名（小写） | ES 自动生成 |
| 每域名文档数 | 1 | N（历史版本） |
| 新鲜度字段 | 无 | `fetched_at` |
| 查询语义 | 单条精确 / 关键词模糊 | 取最新 / 关键词模糊（带时间序） |
| 写入模式 | 全量替换（delete_by_query） | 增量追加（变化才写） |

---

## 6. 架构设计

### 6.1 组件

| 组件 | 技术 | 职责 |
|---|---|---|
| ES | `es_with_ik` 镜像 | 存储 WHOIS 记录历史 |
| 任务服务 | FastTask（Celery + Redis + FastAPI） | 暴露查询任务 + 定时刷新任务 |
| Web 前端 | 待定 | 域名查询页 + 关键字检索页 |

### 6.2 查询流程（Web → FastTask `run` 接口）

```
用户输入域名
  → Web 后端调 FastTask POST /run/query_whois {domain}
  → 任务逻辑：
      1. ES 查该域名 fetched_at 最大且距今 < 1d 的记录
      2. 命中 → 直接返回库中记录
      3. 未命中或已过期 → 实时抓取 WHOIS
             a. 实时结果与库中最新记录算 content_hash 比对
             b. 一致 → 仅更新 fetched_at（不新增文档）
             c. 不一致 → 插入新文档（fetched_at = 当前时间）
      4. 返回最新记录
```

> **【待裁决 Q2】** 第 3.b 步「一致时是否更新 `fetched_at`」：文档不新增则新鲜度标记无处安放。
> 备选：(a) 新增一条 `content_hash` 相同的文档（文档数膨胀）；
> (b) 维护独立的 `last_fetched_at` 映射/索引；
> (c) 直接更新原文档的 `fetched_at`（会丢失"内容未变"的审计痕迹）。

### 6.3 定时刷新流程

```
每天定时触发 → 取库中所有域名（需分批）
  → 逐个实时抓取 WHOIS
  → content_hash 比对
  → 变化则插入新记录；未变化则跳过
```

> **【待裁决 Q4】** 刷新区间：是否只刷新「距上次抓取 ≥ 1 天」的域名，还是强制全量刷新？

### 6.4 实时抓取的数据源

**【已裁决 Q1】** 抓取走**独立模块**：

- 不复用旧 `whois_lookup`（既不调用其 HTTP API，也不移植其 `whois_kit.py`）
- 该独立抓取模块**后续单独设计、单独实现**，本次设计文档不展开其内部细节
- 对当前设计的影响：字段方案与存储设计不绑定任何具体抓取实现，抓取模块只需能产出符合 §4 字段契约的数据

> 背景：旧 `whois_lookup` 的 `query_whois` 挂了 `@lazy_action(expire=86400)` 按域名缓存成功结果 24h，
> 且其 13 字段缺失 `status` / `zone_signed` / `delegation_signed` / `registrar_iana_id` 等监测关键字段，不适合直接作为监测数据源。
> 独立模块的抓取协议选型（port 43 为主 / RDAP 补充 / 两者结合）见 Q5，与模块实现方案一并后续裁决。

---

## 7. 任务模块清单（FastTask）

> 文件名 = 函数名；每个任务含 `Params` / `Result` Pydantic 模型。

| 任务 | 说明 | 状态 |
|---|---|---|
| `query_whois` | 单域名查询（走 6.2 流程） | 待实现 |
| `search_whois` | 关键字模糊检索（IK 分词 + 相关性排序） | 待实现 |
| `refresh_whois` | 批量刷新（定时任务调用） | 待实现 |
| `import_whois` | 从挂载目录导入历史数据 | 待定 |

---

## 8. 待裁决问题清单

| 编号 | 问题 | 备选方案 | 建议 |
|---|---|---|---|
| **Q1** | 实时抓取走哪条路？ | ~~A 自跑 pypywhois / B 调 whois_lookup / C 实现 RDAP~~ | ✅ **已裁决**：独立抓取模块，后续单独实现，不复用旧 whois_lookup |
| **Q2** | 内容未变化时如何记录新鲜度？ | a 新增同 hash 文档 / b 独立 last_fetched_at 映射 / c 更新原文档 fetched_at | **b**（配合 a 的取舍需评估） |
| **Q3** | `query_status` 取值集合 | ~~`ok`/`not_found`/`error`，还是再加 `timeout`/`unsupported_tld`~~ | ✅ **已裁决**：`ok` / `not_found` / `error` 三态 |
| **Q4** | 定时刷新区间 | 仅刷「距上次抓取 ≥ 1 天」/ 强制全量 | 按 `fetched_at` 增量刷 |
| **Q5** | RDAP 是否作为补充数据源？ | 仅 port43 / port43 + RDAP 补 status & dnssec | 待定（与独立抓取模块方案一并裁决） |
| **Q6** | ~~`registrar_abuse_*` 是否纳入 content_hash？~~ | — | ✅ **已废弃**：该字段已砍（raw 兜底） |
| **Q7** | 三个日期字段是否升级为 ISO 8601 带时区？ | ~~保持 `YYYY-MM-DD` / 升级~~ | ✅ **已裁决**：升级 ISO8601 带时区 |
| **Q8** | 域名来源与入库方式 | 谁往库里加域名？手工/API/CSV 导入/爬虫发现 | 需明确 |
| **Q16** | `registrant_country` 值域 | ~~ISO 3166-1 alpha-2 代码 / 国家全名~~ | ✅ **已裁决**：ISO 3166-1 alpha-2 代码 |
| **Q9** | Web 前端形态 | 独立前端 / FastAPI 自带页面 / 复用 easm-scout 前端 | 需明确 |
| **Q10** | 查询接口用 `run` 还是 `create`+`check`？ | `run` 同步（简单）/ `create`+`check` 异步（不占连接） | 实时抓取耗时长，倾向异步；但用户明确说「调用 fasttask 的 run 接口」→ **run** |
| **Q11** | 历史记录保留策略 | 永久保留 / 保留 N 天 / 只留最近 K 条 | 需明确 |
| **Q12** | 是否需要 `admin` / `tech` 联系人？ | 只要 registrant / registrant + admin + tech | 先做 registrant，admin/tech 预留 |
| **Q13** | `raw_whois` 存储位置 | ES 内（index:false）/ 对象存储 / 只保留最近 N 份 | 需明确 |
| **Q14** | 是否需要"域名 WHOIS 暴露个人敏感信息"风险识别 | 需要 / 不需要 | 建议需要（可复用 easm-scout 的 `domain_whois_expose_personal_info` 枚举） |
| **Q15** | 服务端口分配 | `whois_lookup` 占用 9018，`icp_lookup` 占用 9013 | 建议 9019，待查全量占用 |

---

## 9. 风险与注意事项

| # | 风险 | 应对 |
|---|---|---|
| R1 | RDAP `status` 与 port43 `status` 格式不一致（T1） | 建立映射表，统一为 camelCase 或 RDAP 风格后存储 |
| R2 | RDAP `ldhName` 大写（T2） | 入库前统一 `lowercase()` |
| R3 | 未注册域名被误判为已注册（上游坑 1） | 严格禁止把 pypywhois 的 `name`/`tld` 当注册人信息 |
| R4 | 查询失败被误判为未注册（上游坑 6） | 引入 `query_status` 区分 |
| R5 | 多值字段顺序不同导致假变更 | `status` / `nameservers` 数组在计算 content_hash 前排序 |
| R6 | WHOIS 服务器限流 / 超时 | 沿用上游策略：单域名超时 30s、失败重试 3 次、失败不写缓存 |
| R7 | ES 数据量膨胀（每日全量刷新 + 变化即写） | 依赖 content_hash 去重；配合 Q11 保留策略 |
| R8 | whois_kit.py 移植后与上游分叉 | 保留上游文件头注释标注来源与差异 |
| R9 | 敏感信息：registrant 姓名/电话/邮箱/地址入库 | 见 §10 |

---

## 10. 安全与合规

- `registrant_*` 字段含个人可识别信息（PII）。入库、检索与展示需遵循最小必要原则。
- **【待裁决】** 访问控制：Web 查询接口是否需要登录鉴权？检索结果是否需要对 registrant 字段做脱敏展示？
- 原始 WHOIS 全文（`raw_whois`）可能含未脱敏的敏感信息，存储与日志中需注意。
- 日志中不得打印完整的 registrant 联系信息。

---

## 11. 参考

- RFC 9083 — RDAP Query Format
- RFC 7483 — RDAP JSON Responses
- RFC 7095 — jCard (JSON vCard 4.0)
- RFC 9537 — Redacted Fields in RDAP
- RFC 9535 — JSONPath
- IANA "RDAP JSON Values" registry — <https://www.iana.org/assignments/rdap-json-values/rdap-json-values.xhtml>
- 内部项目：`icp_lookup`（ES + IK 分词 + FastTask 封装范式）、`whois_lookup`（pypywhois 归一化 + 缓存）、`easm-scout`（字段消费方）
- 调研脚本：`scripts/probe_rdap.py`（可复现本文 §3 的实测）
