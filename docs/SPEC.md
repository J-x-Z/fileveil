# FileVeil — 文件隐私审计与净化工具

> **工程设计文档 / Codex 开发规格书**  
> 版本：`v0.1-draft` · 日期：2026-11-11 · 项目代号：**FileVeil（暂定，可改名）**  
> 目标平台：Windows 10/11、macOS、Linux（第一阶段）；Android（后续）  
> 工程定位：**离线优先、开源、可解释、可验证、默认不修改原件**  
> 状态：**可立即启动 Gate 0 / Gate 1；其余阶段按验收条件逐步推进**

---

## 0. 一页摘要（先读）

**要解决的问题**：文件可能泄漏作者、用户名、设备型号、GPS、地理/时间信息、编辑历史、软件名称、来源 URL、扩展属性、Office 内部对象、PDF 历史版本及内容凭据。某些来源标记还可能存在于图像/文本/音频的内容本身。用户需要在发送文件前知道**泄露了什么、藏在哪里、清理了哪些、哪些不能证明已清除**。

**产品要做的事**：

1. **Scan**：只读扫描文件本体与平台级元数据，按标准化类别输出证据与风险说明。
2. **Sanitize**：按可审计策略生成新的净化副本，不覆盖原件；默认不改可见内容。
3. **Verify**：用与清理逻辑尽可能独立的手段重新扫描，并验证文件能打开、内容及结构符合策略。
4. **Explain / Diff**：展示清理前后差异、剩余风险及不支持的水印类别。
5. **Research**：为 C2PA、厂商文件标识、AI 水印和样本对比留出插件接口；不得伪称能万能识别或洗除。

**最重要的边界**：

- **能删除元数据 ≠ 已匿名 ≠ 清除了所有水印**。输出必须明确证据范围。
- **可验证签名、C2PA、MOTW/Quarantine** 与一般隐私字段不同；默认保留并提示风险，移除必须明确授权。
- **隐形统计水印**（如 Claude 的 SynthID-Text 类方案与 OpenAI textGrain）不是隐藏字符；无密钥/官方接口时，不作“未检测到”的权威结论。
- 隐私保护是核心，但不能以修改用户未授权文件、上传敏感内容或破坏文档为代价。

### 第一版交付定义

- **MVP：CLI + Rust Core + JPEG/PNG/OOXML 元数据扫描与保守净化 + JSON 报告 + 二次验证 + 测试与 CI**。
- **v0.1 扩展：PDF 可信后端、C2PA 本地读取验证、Windows/macOS 文件系统元数据审计**。
- **v0.2：Rust 原生 GUI、批处理和拖放**。
- **Research：AI 统计水印检测、内容级隐形水印、厂商专有指纹**：插件预留，独立于首版发布门槛。

---

## 1. 威胁模型与术语

### 1.1 需要区分的六种“水印”

| 层级 | 具体内容 | 典型风险 | MVP 目标 |
|---|---|---|---|
| F1 标准元数据 | EXIF、XMP、IPTC、PDF Info、OOXML core properties | 作者、设备、地理位置、软件、时间泄露 | **扫描 + 清理 + 验证** |
| F2 容器/结构附带数据 | PNG 文本块、JPEG APPn、ZIP/OOXML 自定义部件、PDF 附件/旧修订 | 隐藏来源或遗留内容 | **解析 + 定位；安全子集清理** |
| F3 OS 文件属性 | NTFS ADS、`Zone.Identifier`、macOS xattrs、文件时间戳 | 来源、下载地址、系统级标签 | **扫描 + 显示；敏感操作显式授权** |
| F4 真实性与签名凭据 | C2PA manifest、PDF 数字签名、Office 数字签名 | 标识来源；移除/修改可能破坏验证 | **验证 + 告警；默认不移除** |
| F5 内容级隐形水印 | 图像像素/频域、音频信号、打印机微点 | 无法用删标签消除的标记 | **仅预留检测/实验接口** |
| F6 文本统计水印 | token 选择中的统计模式（textGrain、SynthID-Text 类） | AI 来源可被密钥检测器验证，但不等于用户身份追踪 | **预留接口，不作通用检测承诺** |

### 1.2 对手与风险

- **普通接收者**：用文件属性或 ExifTool 读取作者、GPS、编辑程序。
- **具备文件取证工具的接收者**：解析 OOXML/PDF 历史、隐藏对象、附加字节、系统流。
- **掌握专有检测密钥的服务商/机构**：验证某些媒体或文本内容来源。产品不承诺能对抗此类能力。
- **恶意文件输入**：畸形压缩包、解压炸弹、PDF 对象攻击、解析器漏洞、路径遍历。

**非目标**：网络匿名、账号匿名、源代码文本风格去指纹、证明“内容绝不是 AI 生成”、匿名化照片场景中的人脸/背景、绕过访问控制/数字签名验证或取证链。若用户要求删除可见内容、宏、批注等，另归入“高影响转换”，必须展示损失并显式确认。

---

## 2. 工程约束与设计原则

1. **Offline-first**：默认无联网、不请求云端 API、不发送遥测、不开后台服务。
2. **Read-only by default**：扫描仅打开输入文件进行读取；净化只写新路径；永不默认 `--in-place`。
3. **Explainability**：每项发现须注明来源路径/对象位置、类别、置信等级、处理策略及残留风险。
4. **Integrity**：若不具备可靠改写能力，返回 `unsupported` 或 `blocked`，不可声称成功。
5. **Separation of concerns**：扫描、策略、转换、验证、UI 彼此解耦，CLI/GUI 使用同一 Rust Core。
6. **Fail closed for unknown content**：未知 ZIP 成员、未知严重结构异常，不得在“已完全清理”模式里悄悄放过。
7. **Least privilege**：不用 root / 管理员；不加载内核模块；不改系统策略；不扫描用户未选中的文件夹。
8. **Stable data contract**：报告 JSON 有 schema 版本，未来接入 Plyra 或其他软件时无需 GUI。
9. **Licensing hygiene**：参考 MAT2/ExifTool 的行为可以，复制代码或捆绑后端之前必须审计许可证和分发义务。
10. **No marketing overclaim**：不能显示“100% 无痕”、“AI 水印已清零”、“不可追溯”等无法证明的表述。

---

## 3. 技术栈（默认方案）

### 3.1 核心

- **语言**：Rust stable，使用 Cargo workspace，`Cargo.lock` 提交版本管理。
- **CLI**：`clap`；数据：`serde`、`serde_json`；错误：`thiserror` / `anyhow`（边界处）。
- **文件判型**：魔数 + 容器结构检查，扩展名只作提示。
- **二进制解析**：优先小而可审计的格式适配器；必要时采用成熟库，避免手写复杂 PDF 内核。
- **图像**：`image` 等可评估库只用于独立像素/解码验证；JPEG/PNG 安全净化优先“保留编码数据，只替换合法元数据结构”，避免无端重编码。
- **ZIP/OOXML**：`zip` + `quick-xml`（或评估后选同等级依赖），处理 Open Packaging Conventions（OPC）的 relationships 与 content types。
- **C2PA**：官方生态的 `c2pa` Rust SDK；核查校验状态，禁用任何不必要的远端 manifest 获取与网络校验证书请求。
- **PDF**：扫描可由 Rust 适配器完成基础发现；**清理必须经可靠重写后端**。开发阶段可借助隔离的 `pikepdf` helper，生产版评估 `qpdf`/libqpdf 的跨平台打包或其他等效后端。不允许只用 ExifTool 的 PDF 增量写入当作彻底清理。
- **ExifTool / MAT2**：作为可选外部对照工具与交叉验证器，而不是生产执行的必备单点依赖。

### 3.2 GUI

- **推荐**：`egui` + `eframe`（纯 Rust，桌面统一技术栈），与核心通信通过内存 API，不另起服务。
- **备选**：Tauri 2（系统 WebView、UI 设计自由度较高），但会增加前端技术栈；不得让 GUI 框架渗透 Core。
- **原则**：先把 CLI/测试做稳，再建立 GUI；GUI 只负责选择文件、配置策略、展示 Scan/Verify 报告。

### 3.3 可选的后端进程规则

后端必须遵循：固定可执行文件路径、参数数组调用（不拼 shell 命令）、子进程超时/资源限制、临时目录隔离、不允许意外联网、对返回码/输出文件做独立校验。缺少后端时明确显示该格式的净化能力 `unavailable`。

---

## 4. Repo 结构（Codex 按此建立）

```text
fileveil/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE                 # 许可证审计后选定，不提前误写
├── docs/
│   ├── SPEC.md             # 本文
│   ├── THREAT_MODEL.md
│   ├── FORMAT_SUPPORT.md   # 格式支持/风险矩阵自动维护
│   ├── SECURITY.md
│   └── VALIDATION.md
├── crates/
│   ├── fileveil-core/      # 判型、计划、发现/动作数据模型
│   ├── fileveil-scan/      # 通用扫描编排 + 证据聚合
│   ├── fileveil-policy/    # safe / deep / research 策略
│   ├── fileveil-sanitize/  # 转换流水线 + 原子输出
│   ├── fileveil-verify/    # 重扫和结构/内容验证
│   ├── fileveil-formats/   # JPEG / PNG / OOXML / PDF adapters
│   ├── fileveil-os/        # macOS xattrs, NTFS ADS, filesystem
│   ├── fileveil-c2pa/      # 可选：读取 + 验证来源凭据
│   ├── fileveil-research/  # 可选：水印试验与比对接口
│   ├── fileveil-cli/       # 二进制 fileveil
│   └── fileveil-gui/       # 后续 egui/eframe 二进制
├── tests/
│   ├── fixtures/           # 只存人工生成、可公开的样本
│   ├── integration/
│   └── golden/
├── tools/
│   └── fixture-generator/  # 人工注入已知隐私字段
└── .github/workflows/
    ├── ci.yml
    └── security.yml
```

**保持 crate 克制**：Gate 0 可以先只建立 core / formats / scan / cli / verify，剩余目录在真实代码出现时拆分；严禁为了目录架构制造空壳。

---

## 5. 公共接口（稳定目标）

### 5.1 CLI（命令格式作为目标契约，未实现前不得当作现有命令）

```bash
# 只读扫描，终端摘要
fileveil scan ./sample.docx

# 机器可读报告（标准输出；由调用方决定是否保存）
fileveil scan ./sample.docx --json

# 保守净化，不覆盖输入
fileveil sanitize ./sample.docx --profile safe --output ./sample.clean.docx

# 深度转换：每类有破坏性风险的动作明确允许
fileveil sanitize ./sample.pdf --profile deep --allow remove-attachments --output ./sample.clean.pdf

# 输出文件再次验证，与原件对照；不包含厂商不可访问的私有检测器
fileveil verify ./sample.docx ./sample.clean.docx --json

# 两组文件/多个样本的只读对比（后续 research gate）
fileveil diff ./set-a ./set-b --json

# 列出可用/不可用后端与具体支持等级
fileveil capabilities --json
```

**建议退出码**：`0` 完成且已通过所请求的可执行验证；`2` 输入/用法错误；`3` 不支持或后端不可用；`4` 检测到残留/验证未通过；`5` 可能损坏或安全阻断；`6` 取消/超时。不要因为发现了不可清理风险而仍返回“清理彻底成功”。

### 5.2 Rust 类型契约（伪接口，可据实现调整）

```rust
pub enum RiskLayer {
    EmbeddedMetadata, ContainerStructure, Filesystem,
    ProvenanceCredential, ContentWatermark, StatisticalWatermark,
}

pub enum Confidence { Verified, StrongEvidence, Heuristic, Unknown }
pub enum FindingState { Present, RemovedVerified, Remains, NotAssessed, Blocked }
pub enum Action { Preserve, Remove, Normalize, Rebuild, AskUser, Unsupported }

pub struct Finding {
    pub code: String,             // 例: jpeg.exif.gps
    pub layer: RiskLayer,
    pub location: String,         // 例: APP1/Exif/GPSInfo；默认不泄露绝对路径
    pub summary: String,
    pub confidence: Confidence,
    pub action: Action,
    pub state: FindingState,
    pub impact: Option<String>,
}

pub trait FormatAdapter {
    fn identify(&self, head: &[u8], path_hint: &std::path::Path) -> bool;
    fn scan(&self, input: &std::path::Path, limits: &Limits) -> Result<Vec<Finding>, ScanError>;
    fn sanitize(&self, request: &SanitizeRequest) -> Result<OutputArtifact, SanitizeError>;
}

pub trait Verifier {
    fn verify(&self, original: &std::path::Path, output: &std::path::Path,
              policy: &Policy) -> Result<VerificationReport, VerifyError>;
}
```

**设计要求**：方法签名不强迫在内存加载整个文件；后期可换为 `Read + Seek` 或流式 source handle。`scan` 与 `verify` 不依赖 `sanitize` 内部“自报成功”的状态。

### 5.3 报告 JSON（示例；不是真实扫描结果）

```json
{
  "schema_version": "0.1",
  "tool": "FileVeil",
  "operation": "verify",
  "input_format": "image/jpeg",
  "policy": "safe",
  "result": "partially_verified",
  "findings": [
    {
      "code": "jpeg.exif.gps",
      "layer": "embedded_metadata",
      "location": "APP1/Exif/GPSInfo",
      "confidence": "verified",
      "action": "remove",
      "state": "removed_verified",
      "summary": "GPS 坐标字段已从输出文件消失"
    },
    {
      "code": "image.unknown_content_watermark",
      "layer": "content_watermark",
      "location": "image_data",
      "confidence": "unknown",
      "action": "unsupported",
      "state": "not_assessed",
      "summary": "未执行像素/频域隐形水印检测"
    }
  ],
  "integrity": {"parseable": true, "decodeable": true, "pixel_equal": true},
  "warnings": []
}
```

- 默认报告不写原作者姓名、真实 GPS、绝对路径、文件内容、账号 ID；终端 `--show-sensitive` 才可显示。
- `clean` 不等于 `anonymous`；报告的 `result` 建议：`verified_within_scope` / `partially_verified` / `failed` / `unsupported`。
- 风险得分只能辅助排序，**不能取代逐项证据和适用范围**。

---

## 6. 策略引擎：safe / deep / research

| 策略 | 默认动作 | 必须保护的内容 | 结果措辞 |
|---|---|---|---|
| `safe`（默认） | 清除已知隐私标签；尽可能保持像素、文本、结构不变 | 数字签名、可见内容、ICC 色彩关键数据、宏、脚本、附件、OS 安全标记 | 在已支持字段内完成并验证 |
| `deep`（显式选择） | 文件结构重写、可选清理历史/注释/嵌入对象/附加数据 | 每类高影响行为逐项授权；失败回滚 | 可能影响功能/兼容性；显示变化 |
| `research`（仅实验） | 只读样本比对、未知字段/频域信号统计、插件检测 | 原件不变，实验输出独立目录 | 研究线索，绝不认定“厂商监控” |

**每条规则要有**：`id`、适用格式、触发字段、动作、是否损坏原有语义、是否影响签名、验证器、测试 fixture。以后可允许导入自定义策略 TOML，但首版先用 Rust enum 和固定内置策略，降低注入风险。

**签名策略**：

- 发现 PDF/Office 数字签名时，`safe` 模式默认**跳过该文件的任何可能破坏签名的变更**，仅给审计报告。
- 发现 C2PA 时先本地读取、检查校验结果。C2PA 是真实性来源凭据，不自动当作恶意跟踪；移除需明确授权，并警示可能破坏来源验证。即使去除了 manifest，仍可能存在内容级信号。
- macOS `com.apple.quarantine` 和 Windows `Zone.Identifier` 是安全来源标记，会影响 Gatekeeper、SmartScreen/Office 安全行为；默认扫描展示，净化副本应尽可能保留其安全属性，不能以“清理来源”为理由默默解除这些防护。不能保留时必须显著警告并阻断自动批量执行。

---

## 7. 各文件格式实现细则

### 7.1 JPEG（Gate 1 必做）

**扫描**：解析 SOI / segment / SOS / EOI，识别 `APP1 Exif/XMP`、`APP13 IPTC/Photoshop`、`COM`、其他 APPn、尾部多余字节、可识别的 JUMBF/C2PA 结构。标明是否识别成功、是否确有隐私字段。

**safe 净化**：删除明确的隐私元数据容器；**不得粗暴删除所有 APPn**：`APP2 ICC`、`APP14 Adobe` 等可能影响色彩或解码；未知段默认保留并记录。不要未经必要重编码图像；尽量保留扫描编码数据；改写后完整重新解析。

**验证**：重新扫描已知字段；独立解码；像素矩阵一致（如适用）；原件不变；尾部附加数据只在确认无有效用途后经授权处理。

### 7.2 PNG（Gate 1 必做）

**扫描**：检查 PNG signature、chunk 边界、CRC、`tEXt/zTXt/iTXt/eXIf`、其他 ancillary chunks、尾随 `IEND` 数据、可识别 C2PA 载体。

**safe 净化**：删除明确隐私性文本/EXIF；保留 `IHDR/PLTE/IDAT/IEND` 及影响色彩的 `iCCP/sRGB/gAMA/cHRM` 等关键语义信息（除非规则特批）；保留图像像素数据；任何更改后的 chunk CRC 正确。

**验证**：PNG 重新解码、尺寸/帧/像素一致、清理字段消失、CRC 全部合法。APNG 等复杂变体在未测试前显示 `limited_support`。

### 7.3 DOCX / XLSX / PPTX（Gate 2 必做）

**扫描**：识别 ZIP / OPC 结构，检查：

- `docProps/core.xml` 的作者、最后修改者、创建/修改时间；`docProps/app.xml` 的应用信息；`docProps/custom.xml` 自定义属性；
- 包内 XML 的隐藏/自定义部件、批注、修订、外部关系、超链接目标、嵌入对象、缩略图；
- ZIP 成员时间戳、文件名、关系指向、签名部件；
- 未知扩展部件必须列出，不可当作安全内容。

**safe 净化**：仅删除/改写已知隐私属性，按 OPC 规范同步修复 `.rels`、`[Content_Types].xml` 等引用（不能直接删除 ZIP 内部文件而留下悬空关系）；不删除正文、表格、公式、字体、宏、修订/批注（后两者先报告，由用户在 deep 明确选择）。

**验证**：重新解压并校验 CRC/路径、所有内部关系有效；文本/单元格/幻灯片关键内容和对象数对照；若可用，调用 LibreOffice/Office 外部兼容性检查，但**CI 不依赖单一 GUI 办公套件**。对宏启用文档、加密文档、签名文件返回保守结果或拒绝改写。

### 7.4 PDF（Gate 3 必做）

**扫描**：Info、XMP、`/Metadata`、附件、注释、表单、JavaScript、签名、增量更新/旧对象、隐藏对象。识别加密文件并阻断未经授权处理。

**safe 净化**：只在未签名、后端支持且可重写保存时清理已知字段；**必须进行非增量的完整文件重写**，否则旧值可能残留。`deep` 可选择删除嵌入附件/注释/脚本，但这会改变语义，必须逐项确认。

**验证**：重新打开 PDF，查同字段、寻找旧敏感字节残留、验证页数/基本文本抽取/渲染结果；签名失效应视为重要警告。二进制字符串扫描不能替代 PDF 对象验证，反之亦然。

> **禁用做法**：用 `exiftool -all=` 修改 PDF 后，仅检查最新元数据列表为空就宣布“彻底洗净”。ExifTool 官方文档指出，其 PDF 写入采用可逆增量更新，旧信息未必被删除。

### 7.5 TXT / Markdown / HTML（Gate 2）

只读检测零宽字符、不可见 Unicode、BOM、控制字符、HTML 注释和 `<meta>` 来源字段。变更文字/Unicode 可能破坏语义或代码，因此 `safe` 只审计、不自动“洗 AI 文本水印”。对显式可清除的 HTML 元标签可提供可预览的可选修改。

### 7.6 文件系统层（Gate 4）

- **macOS**：`xattr`、Finder 标签、`com.apple.metadata:kMDItemWhereFroms`、`com.apple.quarantine`、Resource Fork（仅审计为先）。
- **Windows**：NTFS Alternate Data Streams、`Zone.Identifier`（Mark-of-the-Web）、文件属性/ACL/时间戳（只读为先）。
- **Linux**：xattrs、SELinux/security namespace、ACL、文件时间戳（只读为先）。

文件创建时间（birth time）不一定能直接删除或一致重写；新文件还会获得新的 OS 时间戳。**必须把“文件本体元数据清除”和“宿主文件系统属性处理”分为两个独立状态**。默认遵守平台安全标记；不允许通过生成“干净文件”静默去掉恶意文件下载防护。

---

## 8. AI / 水印模块：真正的可行性划分

### 8.1 P0：C2PA 本地读取/验证

- 用 `c2pa` Rust SDK 读取 manifest 与本地校验状态；禁用自动远端 manifest 拉取、在线 OCSP 等联网行为，必要时在报告中注明离线信任验证的局限。
- 发现创建工具/来源线索、证书链及签名验证状态；报告按敏感度遮蔽具体值。
- **不以是否存在 C2PA 作为是否存在 AI 内容的判断**；没有 C2PA 也不代表非 AI 内容。
- 选择删除 C2PA 时由 `deep` 独立操作并提示法律、真实性与溯源影响；输出仍不得声称无内容级水印。

### 8.2 P1：AI 来源元数据与 Unicode

- 识别常见生成器字段（软件名称、生成参数、自定义提示词字段等）；只根据明确字段判断“存在 AI 相关来源信息”。
- Unicode/隐藏字符属于字符层审计，**不是** Claude/OpenAI 统计水印检测器；绝不把普通零宽字符错误归因于 Claude 或 GPT。

### 8.3 P2：厂商专有文本/媒体水印验证（插件接口）

- **OpenAI textGrain**：官方说明使用生成时的统计采样信号；文本检测需要符合条件的授权，不能靠 EXIF/Unicode 清理验证。仅建立可选 `ProviderWatermarkDetector` 适配器；若未来 API 可用，提示内容可能上传、耗费配额、地区和资格限制。
- **Anthropic Claude 文本水印**：采用 SynthID-Text 类 keyed scheme，官方检测接口处于 private preview；没有密钥时应输出 `not_assessed`，不得显示“无 Claude 水印”。
- **OpenAI 图像/音频 SynthID**：部分官方验证需要 API 或网站上传，产品默认离线，不自动调用；未来作为显式 opt-in 的联网插件，且默认传输前给出完整文件上传警示。
- **研究用统计分类器**：不得与厂商密钥检测器混称；输出只能是“统计异常/启发式线索”，不能作为作者身份或学术诚信判断依据。

### 8.4 P3：未知水印与 OEM 差异实验室

- 输入：同内容多次导出、同设备不同账号、不同设备同内容、跨 App 转发等**用户自愿提供**的对照样本。
- 只读实验：容器结构 diff、偏移差异、文件尾对比、颜色分布/频域统计、跨样本一致性检验；默认不解析或存档私密正文。
- 必须设置**阴性对照**与**阳性合成样本**，排除正常编码器随机性、时间戳、ICC/EXIF、压缩差异。
- **红星 OS** 可作为一组研究案例，但只有取得合法可研究的实际样本并复现后，才加入检测规则；不可凭传闻编写“万能红星指纹清理”。
- 不做未经证实的 OEM 监控结论；任何厂商归因要有可重复实验证据。

### 8.5 插件权限模型

首版只允许**静态注册、只读检测**。未来如加第三方插件，先定义签名、权限、网络禁用与资源限额；插件一旦需转换内容，必须独立声明是否改变正文/像素/签名，经过显式授权。

---

## 9. 清理流水线与异常恢复

```text
文件选择（绝对禁止自动全盘扫描）
    ↓
类型识别（魔数 + 结构 + 扩展名冲突告警）
    ↓
Scan（只读证据 + 能力表）
    ↓
Policy Plan（展示动作及其副作用）
    ↓
Sanitize（临时副本/隔离的后端，不覆盖原件）
    ↓
Verify（重新扫描 + 重新解析 + 内容保真检测）
    ├─ 成功：原子移动至新输出路径，报告 verified_within_scope
    └─ 失败：保留原件，清理临时文件，报告 failed/partially_verified
```

- 不在失败时保留“看似成功”的目标文件；如果用户明确要保留失败样本，放到单独的 `failed/` 并显著标识。
- 输出文件名默认为 `name.clean.ext`；避免覆盖已有文件，自动选择不冲突的名称。
- 默认临时文件在目标目录所在文件系统以支持原子 rename；处理权限不足/跨卷移动采用额外验证和回滚步骤。
- 出错、取消或崩溃后无孤儿进程、无输入丢失。只在 CLI `--debug` 时允许保留临时文件；调试日志默认屏蔽文件内容。
- `sanitize` 不能单独产生“完全清洁”的结论；只有验证层负责最终结论。

---

## 10. 安全设计（必须先于 GUI）

**输入攻击面**：畸形 JPEG segment、PNG chunk 溢出、ZIP bomb、ZIP Slip、OOXML XML entity/XXE、PDF 超深对象图、递归嵌套归档、超长元数据字段、同名/大小写冲突的容器成员、损坏压缩块。

**默认资源上限（可配置；根据实测调整）**：

| 项目 | 建议默认限制 |
|---|---:|
| 单文件扫描长度 | 2 GiB（可显式提高） |
| 解压总字节数 | 1 GiB |
| ZIP/OOXML 成员数 | 10,000 |
| 单个元数据字段 | 1 MiB |
| 归档嵌套深度 | 4 |
| 单任务超时 | 120 s（大文件手动调整） |
| 并发任务 | 默认 2，受内存预算约束 |

**实现要求**：

1. 不运行文档中的宏、JavaScript、外部链接；默认不自动解析外部引用、URL、网络证书或远程 manifest。
2. 子进程不得使用 shell 插值；路径必须能处理空格、中文、换行及 Unicode。
3. ZIP 路径必须规范化并拒绝 `../`、绝对路径、symlink 越界、路径大小写碰撞；不要为了扫描无条件解压到文件系统。
4. 限制 CPU/内存、内存映射、压缩比及递归；核心 scanner 做 fuzzing。
5. 所有临时副本权限默认仅当前用户可读写；不得泄漏到云同步目录除非用户主动选择。
6. 使用测试虚构数据，CI 不得上传真实照片、文档、证书、账户凭据或个人文件。
7. 生产版加入 `cargo audit`、依赖许可证扫描、可复现打包/SBOM；不自动申请管理员权限。

---

## 11. GUI 设计（Gate 5）

**布局**：左侧文件队列 → 中间“发现信息”列表 → 右侧“清理计划/风险说明”；底部对照结果。拖放、批量文件夹操作、搜索过滤均后置于稳定 Core。

**每份文件展示**：

- 状态：`可扫描`、`可安全清理`、`需确认`、`不支持`、`验证失败`。
- 风险类别：身份、位置、时间、软件来源、编辑历史、真实性凭据、未知/内容级信号。
- 证据位置：如 `docProps/core.xml / dc:creator`、`PNG / iTXt`、`NTFS / Zone.Identifier`。
- 操作：**扫描**、**查看处理计划**、**保存净化副本**、**对比验证**、**导出脱敏报告**。
- 明确说明：“未执行的类别不等于不存在”。

**轻量化**：没有常驻监控或静默后台任务；按需启动引擎和线程；GUI 不依赖在线登录。保留不透明/高对比模式以适应跨平台，视觉风格可后期更新。

---

## 12. 测试与验收标准

### 12.1 金样本（由工具生成，全部合成数据）

- `jpeg_exif_gps_author.jpg`：EXIF GPS/设备/时间、XMP、IPTC、ICC；确认只删隐私项且 ICC 和像素保留。
- `png_itxt_exif_icc.png`：文本块、eXIf、iCCP、合法 CRC；验证清理前后像素一致。
- `docx_author_comments_rels.docx`：作者、历史、批注、自定义属性、可见正文/图片；安全模式保留批注并报告。
- `xlsx_author_custom_formula.xlsx`：作者、自定义属性、公式和图表；净化后公式和工作表不变。
- `pptx_author_media.pptx`：作者、媒体文件、关系引用；清理后可打开。
- `pdf_incremental_old_author.pdf`：旧作者留在 PDF 增量历史；拒绝仅增量隐藏旧值的“伪清理”。
- `pdf_signed.pdf`、`docx_signed.docx`：安全模式检测到签名，默认阻断破坏性修改。
- `jpeg_app_unknown.jpg`：未知应用数据段；安全模式必须提示未知，不能误删。
- `zip_bomb.zip`、`zip_slip.zip`、`png_bad_crc.png`、`pdf_corrupt.pdf`：解析器拒绝、资源上限生效，不发生路径越界或崩溃。
- `c2pa_valid.jpg` / `c2pa_invalid.jpg`：使用开发测试证书/人工样本，验证结果分级；不得把“解析成功”视为“签名有效”。
- `unicode_invisible.txt`：零宽字符检测，safe 只报告。

### 12.2 不可妥协的验收

**Core/CLI**：

- `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test --workspace` 通过。
- 同样输入 + 同样策略给出稳定的发现编码与处理计划（路径等环境差异除外）。
- 原文件 SHA-256 在操作前后相同；不产生意外网络请求。
- 非法文件不会 panic、卡死或在超限时耗尽磁盘；存在可控的超时/内存上限。

**格式保真**：

- JPEG/PNG 安全模式的解码像素一致；色彩关键信息保留。
- OOXML 能重新打开，关系与内容类型引用不悬空；关键内容摘要相同。
- PDF 采用非增量重写且扫描不到测试用旧作者；加密或签名文件正确阻断。

**报告可信**：

- 每个 `RemovedVerified` 都有可执行验证规则；无法识别的格式显示不支持。
- 对未知水印、AI 统计水印，必须显示 `NotAssessed`，不得显示“未发现”。
- 正式发布每个支持格式都有至少一个阳性测试、阴性测试和恶意输入测试。

---

## 13. 实施里程碑与任务拆解

### Gate 0 — 工程基线（**现在就做**）

- [ ] 创建 Cargo workspace、CLI、核心数据模型及格式适配器 trait。
- [ ] 完成 `capabilities`、`scan --json` 空流程、`--help`；写入版本化 JSON schema。
- [ ] 文档：README、THREAT_MODEL、FORMAT_SUPPORT、SECURITY、VALIDATION。
- [ ] GitHub Actions：Windows / macOS / Linux 上运行 `fmt / clippy / test`；引入 synthetic fixture generator。
- [ ] 保证扫描不修改文件、默认无网络访问，错误码稳定。

**验收 Gate 0**：三个平台都能编译并执行 `fileveil capabilities --json`；传入未知文件得到可解释报告而非 panic；单测与 CI 绿色。

### Gate 1 — JPEG / PNG 有意义的完整闭环（**首个实用版**）

- [ ] JPEG/PNG 只读 parser 和字段表。
- [ ] EXIF/XMP/文本字段保守清理，保留必要色彩/图像数据。
- [ ] `sanitize` 输出新文件 + `verify` 独立解析与像素对比。
- [ ] ZIP/畸形二进制输入不适用时及时拒绝；覆盖边界和恶意测试。
- [ ] JSON 和终端报告显示“已验证/未检查”的区别。

**验收 Gate 1**：提供的合成 JPEG/PNG 先检出 GPS/作者等字段、再生成可打开的净化副本，像素相同，重扫显示字段消失，原件 hash 不变。

### Gate 2 — OOXML + TXT/HTML 结构审计

- [ ] DOCX/XLSX/PPTX 内部属性扫描、ZIP 安全限制。
- [ ] 处理 `docProps` 和 OPC references，完成保守写回。
- [ ] 检测批注、修订、外部关系及嵌入对象（仅报告，默认不移除）。
- [ ] HTML/Unicode 来源字段只读审计。

**验收 Gate 2**：Office 文档净化后能打开，正文/公式/图片未发生非授权变化，未清理的批注明示残留。

### Gate 3 — PDF 可信重写 + C2PA

- [ ] 选定经 CI 验证的 PDF 后端，建立子进程/FFI 边界；正式打包策略明确。
- [ ] Info/XMP/旧修订扫描和非增量重写。
- [ ] C2PA manifest 离线读取和校验，区分“存在、有效、无效、不确定”。
- [ ] 签名文件阻断；验证页数、文本内容与基础渲染。

**验收 Gate 3**：PDF 旧作者不能通过回滚增量历史恢复；签名无意修改为零；C2PA 结果不误报。

### Gate 4 — OS 属性与批量作业

- [ ] macOS xattrs、Windows ADS、Linux xattrs 的只读审计。
- [ ] 安全标记传播/保留策略及失败告警；确认不削弱系统安全默认行为。
- [ ] 批量队列、取消/恢复、冲突命名、整体资源预算。

**验收 Gate 4**：每个平台可列出支持能力；不会在未确认时去除 Quarantine/MOTW；大批量取消可清理临时文件。

### Gate 5 — 原生 GUI 和交付

- [ ] egui/eframe 文件拖放与队列。
- [ ] 证据定位、可读的风险分类、处理计划、双栏验证结果。
- [ ] Win/macOS/Linux 发行包、签名策略、软件供应链检查、英文和中文 UI。

**验收 Gate 5**：GUI 使用与 CLI 相同的报告和策略；无独立规则副本。

### Research Gate — 不阻塞发布

- [ ] 统一的只读 `WatermarkDetector` 插件契约与可信度标记。
- [ ] 多样本 Watermark Diff Lab。
- [ ] 已授权厂商检测 API 的可选插件；明确联网提示和数据生命周期。
- [ ] 真实样本与公开可复现研究才可新增专有水印规则。

**验收 Research**：能重复实验、给出置信/误差/未覆盖声明；不得把启发式分类说成厂商官方水印验证。

---

## 14. CI、发布与项目管理

- 主分支保护；PR 必须通过 Windows + macOS + Linux 测试。
- 使用 `cargo-deny`/`cargo audit`（版本与工具可替换）检查漏洞和许可证。
- 格式解析器引入 `cargo-fuzz`，先对 JPEG/PNG/ZIP 输入做覆盖导向 fuzz；定期运行长时模糊测试。
- 每种文件格式独立维护“只读扫描、safe 清理、deep 清理、签名处理、保真验证”矩阵。
- 使用 SemVer，且报告 `schema_version` 独立于应用版本。
- 首次发行许可证建议在完成依赖审计后选定（可比较 MPL-2.0、GPL-3.0-only、Apache-2.0/MIT），避免无意混入不兼容源代码。
- 变更日志应列出**哪些格式更安全了、哪些字段仍无法验证**，而不只写“新增 N 个格式”。

---

## 15. 给 Codex 的第一轮执行指令（直接复制）

> 请按 `docs/SPEC.md` 实施 FileVeil。**这轮只做 Gate 0，达到验收标准后再进入 Gate 1；不要提前做 GUI、PDF、C2PA、AI 文本水印算法或厂商私有模块。**
>
> 1. 建立尽量精简的 Rust Cargo workspace，初期 crate 以实际需要为准；实现公共风险分类、Finding、Policy、Limits、格式识别接口。
> 2. 提供 `fileveil capabilities --json`、`fileveil scan <path> --json`、`fileveil --help`，未知格式返回稳定且明确的 `unsupported` 而不是成功。
> 3. 实现只读扫描器外壳、输入验证、报告 schema、基础错误码、敏感字段默认遮蔽；严格不修改文件，不联网。
> 4. 加入合成测试样本生成器、单元测试以及 Windows/macOS/Linux CI；运行 fmt、clippy、test 并修复所有失败。
> 5. 建立 `README.md`、`docs/THREAT_MODEL.md`、`docs/FORMAT_SUPPORT.md`、`docs/SECURITY.md`、`docs/VALIDATION.md`。
> 6. 完成后汇报具体改动、执行的命令、测试结果、尚未实现的能力、进入 Gate 1 的阻塞点。**不要将未完成的检测/清理标成已支持，不要改动用户系统配置。**

完成 Gate 0 后，第二轮提示词只写：**“按 SPEC 执行 Gate 1，并以 `jpeg_exif_gps_author.jpg` / `png_itxt_exif_icc.png` 两类合成样本完成 Scan → Sanitize → Verify 全闭环。所有失败和未知情况必须报告，不得绕过验证。”**

---

## 16. 第一版要明确排除的事情

- 不训练“万能 AI 水印识别模型”；没有官方检测密钥，不假装能够读取 Claude/OpenAI 文本统计水印。
- 不重写 PDF 渲染器、不手工实现完整 PDF 安全解析引擎。
- 不为“深度清理”默认把所有 PDF 栅格化、把 JPEG 重编码、把 Office 转成图片。
- 不自动修改文件签名、Office 宏、可见水印或受保护文档。
- 不把检测到的未知 bytes 宣称为国产手机 OEM 跟踪标记。
- 不开发驻留 root/内核插件；未来 Android 版先考虑 SAF 文件授权与离线处理，不走高权限捷径。
- 不上传文档到外部 AI 模型来“判断是否有水印”。

---

## 17. 参考文献 / 工程依赖基线（2026-11-11 核对）

### 必读官方资料

1. ExifTool PDF 标签说明（增量更新导致旧信息可恢复）：https://exiftool.org/TagNames/PDF.html
2. MAT2 README（格式支持、清理局限、未知成员策略）：https://github.com/jvoisin/mat2
3. pikepdf 文档（重写会合并增量更新）：https://pikepdf.readthedocs.io/en/latest/api/main.html
4. pikepdf sanitization API（附件与 JavaScript 等）：https://pikepdf.readthedocs.io/en/latest/api/sanitize.html
5. C2PA Rust SDK / Reader：https://docs.rs/c2pa/latest/c2pa/struct.Reader.html
6. CAI 开源工具：https://opensource.contentauthenticity.org/docs/
7. egui 官方文档：https://docs.rs/egui/latest/egui/
8. Rust ZIP 库文档：https://docs.rs/zip/latest/zip/
9. Anthropic 对 Claude 文本水印的说明：https://www.anthropic.com/news/claude-text-watermark
10. OpenAI 对 textGrain / SynthID / C2PA 的说明：https://help.openai.com/en/articles/8912793-provenance-signals-in-openai-generated-content

**使用原则**：这些是技术依据，不是可以无条件复制的代码；实际选用时核验对应 crate/API 版本、平台适配及许可。本文不保证厂商专有接口长期可用。

---

## 18. 最终工程判断

**首个可交付成果不是“万能去水印”，而是一个有技术证据的离线净化闭环**：

> **Scan → Explain → Sanitize → Verify**

用户必须知道：扫描了什么、未扫描什么、删除了什么、为何不敢删除、文件功能是否保留，以及内容级/厂商私有水印是否仍未评估。

这一架构可以在未来扩展到 AI provenance、OEM 文件指纹、Plyra 集成、Android 分享菜单；但这些扩展不应阻塞核心能力发布。
