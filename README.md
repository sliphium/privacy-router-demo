# PrivacyRouter · 端云协同 LLM 隐私保护助手

> 在享受云端大模型能力的同时，让敏感数据不出本机。

学生干部用 AI 处理评奖、资助、心理、成绩材料时，把原文直接粘进云端对话，等于把同学的隐私交给第三方。PrivacyRouter 在每次请求前判定敏感度，按三档路由：**涉密留本机、可遮掩的脱敏后上云、普通内容直连云端**。

## 核心特性

- **三档路由 + fail-closed**：涉密任务即使本地模型不可达也直接阻断，不会静默改走云端
- **上下文整体判定**：最多检查 12 条历史消息，历史中任一条涉敏，本轮仍按最高级别处理
- **实体脱敏与回填**：`[手机号1#a7c3]` 形式的占位符，`#` 后为每请求随机标记，模型改写或伪造都无法回填成真实数据
- **规则检测覆盖面**：手机号、身份证、银行卡、学号、姓名与名单、宿舍、地址、心理、资助、处分、合同、财务、HR、代码、PEM 私钥、云厂商密钥、数据库连接串、明文口令
- **抗变形**：全角、零宽字符、方向控制符、中文数字、URL/HTML/Base64 编码、同形字符、拼音数字
- **本地模型隐私约束**：本地应答前注入系统提示，不复述姓名、学号、联系方式、成绩与心理细节
- **文件本地扫描**：表格（xlsx/xls/csv/tsv）、文档（docx/pdf）、图片 OCR（png/jpg/jpeg/webp），原文件不上传
- **docx 保留格式导出**：脱敏后仍是可正常打开的 `.docx`，段落、表格、样式、页眉页脚结构不变
- **心理危机分级转介**：高风险使用固定话术、不调用模型；中风险本地处理、不拦截
- **链式哈希审计**：只记录指纹与统计，不落盘原文或脱敏文本
- **运行期降级**：云端失败且尚未输出内容时自动转本地，并在审计中标记 `degraded`
- **演示模式**：无 Key、无 Ollama 也能完整体验流程

## 工作原理

| 敏感度分数 | 路由 | 行为 |
| --- | --- | --- |
| `≥ localThreshold`（默认 40）或命中 critical 规则 | 本地处理 | 原文不出本机，调用本机 Ollama |
| `sanitizeThreshold ≤ 分数 < localThreshold`（默认 10 / 40） | 脱敏后使用 | 实体替换为占位符后调用云端，返回时回填 |
| `< sanitizeThreshold` | 直接上云 | 未发现敏感特征，直连云端 API |

一次请求的完整链路：

1. 检测本次请求携带的全部上下文，合并计算分数
2. 产出路由决策；命中高风险心理危机时切换为本地固定转介
3. 需要上云且存在实体时，逐个替换为带本次标记的语义化占位符，再整体复检，复检超标则升级为本地
4. 调用对应模型；云端失败且未产生输出时降级到本地重试
5. 回填占位符、隐藏无法识别的伪造占位符，写审计（只存哈希与统计）

## 快速开始

环境要求：**Node.js ≥ 20**。真实本地推理需要额外安装 [Ollama](https://ollama.com/)；只用演示模式则不需要。

```bash
npm install
cp config.example.json config.json    # Windows: copy config.example.json config.json
npm start
```

打开 `http://127.0.0.1:7860`。

默认 `demoMode: true`，本地与云端均由 Mock Provider 应答，界面会明确标注，不冒充真实模型。要用真实模型：

```bash
ollama pull deepseek-r1:1.5b
```

然后在配置面板或 `config.json` 中关闭 `demoMode`，并填入云端 `apiKey`。

## 配置

配置文件为 `config.json`（与 `server/` 同级），也可通过环境变量覆盖。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `privacyProfile` | `campus` | `campus` 校园严格策略 / `enterprise` 企业策略 |
| `demoMode` | `true` | 演示模式，Mock 应答 |
| `strictMode` | `false` | 严格模式，进一步收紧上云 |
| `thresholds.local` | `40` | 达到即本地处理 |
| `thresholds.sanitize` | `10` | 达到即脱敏后使用 |
| `ollama.baseUrl` | `http://127.0.0.1:11434` | 本机 Ollama 地址 |
| `ollama.model` | `deepseek-r1:1.5b` | 本地模型名 |
| `cloud.baseUrl` | `https://api.openai.com/v1` | 云端接口，支持裸域名 / `/v1` / 完整端点 |
| `cloud.model` | `gpt-4o-mini` | 云端模型名 |
| `cloud.apiKey` | 空 | 云端 API Key，`GET /api/config` 只返回掩码 |
| `allowLocalFallback` | `true` | 云端失败时允许降级到本地 |
| `allowDegradeToCloud` | `false` | 保留字段；**涉密内容永不因本地失败而改走云端** |
| `semanticReview` | `false` | 是否用本地模型做语义复核；复核在每次上云前同步执行，**推理型模型（如 deepseek-r1）单次可达 90 秒以上**，建议搭配小模型或保持关闭 |
| `timeoutMs` | `300000` | 单次模型调用超时 |
| `crisis.*` | 见下 | 心理危机转介配置 |

心理危机配置：

| 字段 | 说明 |
| --- | --- |
| `crisis.enabled` | 是否启用分级转介 |
| `crisis.hotline` | 心理援助热线，留空时使用全国 `12356`，并提示 `120 / 110` |
| `crisis.counselingCenter` | 学校心理中心地址或电话，留空不显示 |
| `crisis.counselorContact` | 辅导员联系方式，留空不显示 |
| `crisis.message` | 完全自定义的高风险话术，设置后覆盖默认话术 |

环境变量（优先级高于 `config.json`）：

```text
PRIVACY_ROUTER_PROFILE=campus|enterprise
PRIVACY_ROUTER_DEMO=0|1
PRIVACY_ROUTER_STRICT=0|1
CLOUD_BASE_URL=https://api.deepseek.com
CLOUD_MODEL=deepseek-chat
CLOUD_API_KEY=sk-xxx
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=deepseek-r1:1.5b
PRIVACY_TIMEOUT_MS=300000
PORT=7860
HOST=127.0.0.1
```

不想把 Key 明文写进文件，可以只设 `CLOUD_API_KEY` 环境变量启动。

## 使用

- **对话**：输入内容后先显示路由判定、评分、命中证据；本地处理显示原文答复，脱敏上云显示占位符版本
- **文件扫描**：点击或拖入文件，本地解析后返回命中统计、路由建议与脱敏文件下载
- **发送前确认**：脱敏上云前可查看「云端将收到」的完整文本，确认后才发送
- **强制脱敏重试**：本地处理结果上若全部命中项都可遮掩，可手动选择脱敏后用云端重试，并明确提示任务语义仍会外发
- **审计面板**：查看最近记录、校验哈希链、清空（写入 `audit-clear` 锚点）

## 云端接入

`cloud.baseUrl` 支持三种写法，服务端统一解析为实际请求地址：

| 填写 | 实际请求 |
| --- | --- |
| `https://api.deepseek.com` | `https://api.deepseek.com/v1/chat/completions` |
| `https://api.deepseek.com/v1` | `https://api.deepseek.com/v1/chat/completions` |
| `https://api.deepseek.com/v1/chat/completions` | 原样使用 |

常见错误会给出可操作提示：

- `401 / 403`：检查 API Key 是否有效、是否与 `baseUrl` 匹配
- `404`：检查 `baseUrl` 是否指向 OpenAI 兼容接口、模型名是否正确
- `429`：限流或余额不足

`GET /api/health` 的 `cloud` 字段区分「未填写」「配置完整」「配置不完整」：

```json
{
  "configured": true,
  "valid": true,
  "endpoint": "https://api.deepseek.com/v1/chat/completions",
  "reason": ""
}
```

> `valid` 只做静态校验（baseUrl 合法、Key 与模型名非空），**不代表网络可达或 Key 有效**；能否真正调通以一次实际请求为准。运行期失败会自动降级，并在 `meta.degraded` 与审计记录中体现。

云端在运行期失败且尚未输出任何内容时，会先下发 `fallback` 事件，再改用本地重试；一旦已产生输出则直接报错，避免拼接两个模型的回答。

## 审计与合规

- 只记录 `id`、时间、路由、评分、命中类别、脱敏数量、外发文本的 SHA-256 指纹与长度
- 每条记录带 `prevHash` 与 `hash`，形成可校验的哈希链
- 清空审计会写入 `audit-clear` 锚点，保留清空前的记录数与链尾哈希
- `GET /api/audit/verify` 校验链完整性，并返回文件权限模型
- 合规材料位于 `docs/compliance/`：隐私影响评估、学生告知书、危机处理流程

文件权限按平台区分，不把 Windows 上的 `0600` 当作已生效：

- POSIX：`config.json` 与审计文件设为 `0600`，返回 `{ "model": "posix-mode", "enforced": true }`
- Windows：`stat.mode` 对普通文件恒为 `0o666`，`chmod` 不产生访问控制，需手动设置 NTFS ACL：

```powershell
icacls data\audit.jsonl /inheritance:r /grant:r "$env:USERNAME":F
```

此时 `/api/health` 与 `/api/audit/verify` 会返回 `{ "model": "ntfs-acl", "enforced": false }`。

## 心理危机处理

| 级别 | 判定 | 行为 |
| --- | --- | --- |
| 高风险 | 自杀、自伤、轻生等明确表达 | 本地处理，**不调用模型**，返回固定转介话术，不自动上报 |
| 中风险 | 抑郁、失眠、情绪持续低落 | 本地处理，保留模型回复，仅显示轻量「获取心理支持」入口 |
| 无 | 未命中 | 正常路由 |

默认话术只推荐**全国心理援助热线 12356**，并提示 `120 / 110`；学校心理中心与辅导员联系方式默认留空，由使用方在 `config.crisis` 中填写。不在代码里写死任何地区号码。

## 测试与工具

```bash
npm test
```

覆盖检测器、脱敏与回填、路由、审计哈希链、文档/表格/图片扫描、云端配置与降级、SSE 心跳、端到端 SSE 流程。

辅助工具：

```bash
# 普通通知误报率（规则层）
node tools/fp-report.mjs

# 追加本地模型语义复核（需 Ollama，单条 30–80 秒）
node tools/fp-report.mjs test/fixtures/normal-campus-notices.txt --semantic

# OCR 独立验证（不进入默认测试，避免 tesseract worker 挂起）
node tools/ocr-check.mjs
```

## 已知限制

- `xlsx@0.18.5` 存在原型污染与 ReDoS 公告且无修复版本；当前以 8 MB 文件上限 + 仅扫描可信文件兜底
- 扫描版 PDF 没有文本层，只提示需要 OCR，不自动转图片
- 文档扫描统计不包含文本框与图片内文字；docx 导出阶段会处理 `document.xml` 中的文本框文本，因此实际脱敏范围略大于统计范围
- 批注作者、文档属性中的非身份字段不做改写；作者、最后修改者、公司、部门负责人会被清空
- Windows 上无法在进程内校验 NTFS ACL，只做显式告知
- `semanticReview` 的真实误报率依赖本机模型，建议用自己的材料跑 `--semantic` 实测
- 审计只保证链内自洽，整文件删除后重建合法链无法被本地发现，需要外部锚点配合

## 目录结构

```text
.
├── server/
│   ├── index.js                 HTTP 服务、SSE、路由编排
│   └── lib/
│       ├── detector.js          规则检测、抗变形、危机分级
│       ├── sanitizer.js         占位符生成、回填、流式缓冲
│       ├── router.js            三档决策、可用性调整
│       ├── config.js            配置合并、Key 掩码
│       ├── audit.js             链式哈希审计、权限模型
│       ├── document.js          docx/pdf 文本提取
│       ├── docx_mask.js         保留格式脱敏导出
│       ├── tabular.js           表格解析、扫描、导出
│       ├── ocr.js               tesseract.js 封装
│       └── providers/           ollama / cloud / mock
├── public/                      单页前端（HTML/CSS/JS，无构建）
├── test/                        单元与端到端测试、基准样例
├── tools/                       误报率与 OCR 验证脚本
├── tessdata/                    内置中文 OCR 语言包
├── docs/
│   ├── specs/                   设计说明
│   └── compliance/              合规材料
├── config.example.json
├── CHANGELOG.md                 版本更新记录
└── package.json
```

## 安全边界

- 服务默认只监听 `127.0.0.1`，不对外提供接口
- 云端 API Key 只存在于后端进程与 `config.json`，接口只返回掩码
- 原文件与提取文本不上传云端；文件扫描在内存中完成，不落盘
- 涉密任务本地失败即阻断；云端失败才允许向更安全的本地降级
- 审计不存储原文，避免成为第二个敏感数据仓库