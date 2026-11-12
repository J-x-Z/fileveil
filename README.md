# FileVeil

离线文件隐私审计与净化工具，提供 Rust 原生桌面 GUI 与 CLI。当前版本为 0.3.0，报告 schema 为 0.3，可读取旧版 0.1 和 0.2 报告。

桌面版支持中文和英文界面、文件拖放、多文件队列、文件夹导入、发现信息搜索与分类筛选、处理计划、批量保存净化副本、二次验证与脱敏 JSON 报告导出。默认使用深色外观，侧栏可切换深色和中性浅色，设置内提供语言与高对比外观选项。任务支持取消与超时。

JPEG、PNG、HEIC/HEIF、AVIF、MP4/MOV、WAV、FLAC 和 DOCX/XLSX/PPTX 支持各自范围内的 Safe 净化。Deep 提供选择性 Office 内容清理，TXT/Markdown/HTML 支持显式净化副本。PDF 使用 qpdf 完整重写，独立 Poppler 检查页数、文本及受限分辨率页面渲染。C2PA 离线验签、公开 LSB 与 Stable Diffusion 图像水印检测、图片差异实验室和手机媒体容器重写已接入共享 Rust Core。具体范围见 [格式支持](docs/FORMAT_SUPPORT.md)。

## 启动桌面版

macOS 本机构建已打包为 `dist/FileVeil.app`，可以双击启动。

```sh
open /Volumes/WINDOWS/work/fileveil/dist/FileVeil.app
```

从源码构建桌面版需要 Rust 1.96 或更新版本。

```sh
cargo build --locked --release -p fileveil-gui -p fileveil-cli
python3 tools/package-desktop.py --skip-build
```

Windows/Linux 使用同一构建及打包工具生成便携目录。三平台 CI 已配置构建与发行包上传，原生执行状态见 [验证记录](docs/VALIDATION.md)。操作与打包说明见 [GUI 使用指南](docs/GUI.md)。

## 构建与使用

需要 Rust stable 和 Cargo。依赖下载发生在构建阶段，程序运行时无需网络或登录。

```sh
cargo build --release -p fileveil-cli
./target/release/fileveil --help
./target/release/fileveil capabilities --json
./target/release/fileveil scan sample.jpg --json
./target/release/fileveil sanitize sample.jpg --profile safe --output sample.clean.jpg --json
./target/release/fileveil verify sample.jpg sample.clean.jpg --json
```

Windows 下使用 `target\release\fileveil.exe`。省略 `--output` 时自动选择 `name.clean.ext`，遇到已存在的文件会选择后续可用名称。显式指定的已有输出路径会被拒绝。

`sanitize` 先扫描并制定计划，再写隔离临时文件，重新解析并验证后提交输出。图片还会通过独立解码器比较像素。Office 包会验证内部关系，并对照保留的部件内容。`verify` 可以单独检查已有副本。

`safe` 为默认策略。`deep` 使用 `--options-json` 指定可改变内容的清理项，GUI 提供对应参数。`research` 执行默认两位 RGB 低位处理，`process-image` 提供明确的模式与位数参数。扫描与报告省略作者、GPS 等字段值和输入绝对路径。Deep 与 Research 的验证范围在报告中单独记录。

## 结果与退出码

报告使用独立版本号 `schema_version = "0.3"`，格式定义见 [JSON Schema](docs/report.schema.json)。`findings` 包含稳定发现编码、证据位置、处理动作与状态。

| 结果 | 含义 |
| --- | --- |
| `verified_within_scope` | 请求范围内的可执行验证通过 |
| `partially_verified` | 已完成的检查通过，仍有需说明的保留项或检查范围限制 |
| `failed` | 文件或内容对照未通过 |
| `unsupported` | 格式或请求能力不可用 |
| `blocked` | 检测到损坏、资源超限或需要保护的结构 |

| 退出码 | 含义 |
| --- | --- |
| 0 | 请求操作完成，所请求的可执行验证通过 |
| 2 | 输入、路径或用法错误 |
| 3 | 不支持或所需能力不可用 |
| 4 | 验证未通过或仍有需处理的残留 |
| 5 | 损坏、安全阻断或资源上限 |
| 6 | 取消或超时 |

`sanitize` 返回 4 且结果为 `partially_verified` 时，输出副本已保存，保留项见报告。

报告中的 `not_assessed` 用于内容级水印、统计水印等未运行检查。C2PA 验证分别报告 COSE 签名、文件绑定、本地根信任、嵌入吊销证据和未完成的检查。来源凭据默认保护并阻断改写。Office 签名、宏和加密输入同样采用保守阻断。

## 合成样本与验证

全部样本使用虚构内容，生成器默认输出至 `tests/fixtures`，拒绝覆盖已有文件。

```sh
cargo run -p fixture-generator -- work/generated-fixtures
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

Windows/macOS/Linux 验证工作流已配置，实际执行情况记录在 [验证记录](docs/VALIDATION.md)。支持矩阵见 [格式支持](docs/FORMAT_SUPPORT.md)，安全边界见 [安全说明](docs/SECURITY.md) 与 [威胁模型](docs/THREAT_MODEL.md)。

## 许可证

FileVeil 自有源码采用 Mozilla Public License 2.0，完整条款见 [LICENSE](LICENSE)。

MPL-2.0 采用文件级 Copyleft。对外分发受覆盖源码及其修改时，相关文件继续按 MPL-2.0 提供。分发二进制时，应提供对应的受覆盖源码，并告知接收者获取方式。保留现有许可证及版权声明。[Mozilla MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/)

第三方插件的独立源码文件可以采用其选择的许可，组合分发时须履行各部分适用的许可义务。包含或修改 FileVeil 受覆盖代码的插件文件，应遵守 MPL-2.0 的源码分发要求。[Mozilla 许可 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)

第三方 Rust 依赖、字体及可选后端继续使用各自的许可证，相关原文、署名和来源保存在 [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) 与 `assets/licenses/`。发行包包含项目 LICENSE 及第三方声明，发布时应同时提供对应版本源码或明确可访问的源码获取位置。

## 图片水印处理

作者、创建时间、文本标签等已识别的元数据由默认净化操作移除。GUI 的“图片水印处理”还提供两种显式改动像素的本地处理，均生成新的 PNG 副本。

- 低位清理将 RGB 各通道最低 1、2 或 3 位清零，保留透明度。验证会核对目标低位归零、每通道误差上限和处理配方。
- 信号处理依次执行 95% 缩放回采样、σ 0.5 高斯平滑、质量 88 的 JPEG 编码回译，随后输出 PNG。报告记录尺寸、改动通道数、最大误差和均方误差。

两种模式同时重建图片容器以净化可识别元数据，保留兼容的色彩信息、透明度和系统安全来源标记。当前输入支持 8 位 RGB/RGBA PNG 与三分量 JPEG。

```sh
./target/release/fileveil process-image sample.png --mode low-bits --bits 2 --output sample.processed.png --json
./target/release/fileveil verify-image sample.png sample.processed.png --mode low-bits --bits 2 --json
./target/release/fileveil process-image sample.jpg --mode signal --output sample.signal.png --json
```

处理与配方验证完成后返回 `partially_verified` 和退出码 4。未知密钥水印的检测状态为 `not_assessed`。低位归零结论覆盖指定像素位，通用隐形水印清除效果需要对应检测器确认。

## MCP 接入

桌面可执行文件支持本地 stdio MCP 服务。设置中先选择读取目录和输出目录，再复制包含明确授权范围的 MCP 连接配置。空目录授权只开放能力查询。

```sh
/Volumes/WINDOWS/work/fileveil/dist/FileVeil.app/Contents/MacOS/fileveil-gui --mcp
```

服务提供八个工具，覆盖能力查询、扫描、Safe/Deep、验证、图片处理、公开图像水印检测、差异实验室与 AI 来源。读取与输出目录分开授权，每连接默认最多 64 次操作，原件只读，输出只能新建。路径、链接、目录替换与资源限制由服务端验证。连接方式与示例见 [桌面版指南](docs/GUI.md)。

## 0.3 高级入口与限制

```sh
./target/release/fileveil sanitize draft.docx --profile deep --options-json '{"deep":{"remove_comments":true,"accept_revisions":true}}' --output draft.deep.docx --json
./target/release/fileveil sanitize notes.html --options-json '{"text":{"remove_html_metadata":true,"remove_html_comments":true}}' --output notes.clean.html --json
./target/release/fileveil provenance image.png --trust-roots local-roots.pem --json
./target/release/fileveil detect-watermark sample.png --json
./target/release/fileveil lab control.png processed.png --json
```

GUI 工作区提供文件扫描、Deep 净化、图片处理、Diff Lab、AI Provenance 和批量验证，MCP 授权和资源上限集中在设置。主题沿用中性黑灰与灰白。

PDF 需要 qpdf。独立完整验证需要另行安装 Poppler 的 pdfinfo、pdftotext 和 pdftoppm，缺少这些工具时准确报告部分验证。支持可信的绝对路径环境配置 FILEVEIL_QPDF、FILEVEIL_PDFINFO、FILEVEIL_PDFTOTEXT、FILEVEIL_PDFTOPPM。已签名或加密的 PDF、Office 宏和签名包继续保护。

HEIC/AVIF/MP4/MOV 当前提供结构与元数据审计，净化重写和编码内容验证尚未提供。未知 OEM 字段仅报告结构线索。MP3 净化、音频信号水印、私有密钥统计水印、厂商专有水印及 CAWG 身份校验仍待实现或授权检测能力。Deep 支持无依赖的简单隐藏工作表清理。复杂 Office 修订、公式或共享字符串依赖的隐藏表和复杂 HTML 结构会明确阻断。

公开检测器覆盖 FileVeil LSB 包、Stable Diffusion 1 的 136 位公开消息及 SDXL 的 48 位公开消息，包含逐方法处理后复检。正反样本使用独立上游编码器和解码器验证。公开消息可被复制，身份或模型来源认证仍需独立证据。Diff Lab 提供低位、DCT/Haar、JPEG 编码、残差及差分预览，可输入参考组进行留一法残差关联比较。手机 OEM 归因与专有水印保持未评估。

OpenAI、Anthropic 和 Google 的专有检测器显示实际可用状态。当前版本完全离线，SynthID-Text 的参考算法需要匹配的 tokenizer、生成配置和密钥。未配置的服务与检测范围均在能力报告中列明。

最低 Rust 版本升至 1.96，以使用固定版本的官方 C2PA SDK。旧 CLI 命令和 Safe 默认行为保留，报告新增字段均可选。发行包附带 MPL-2.0、第三方声明和对应项目源码 ZIP。正式签名、公证及实际目标平台状态见验证记录。

WAV/FLAC 标准隐私标签清理保留编码音频负载，技术声道和增益信息继续保护。MP3 提供有限 ID3 审计，音频信号水印检测未提供。macOS 主程序与可选 PDF 后端的最低系统版本分别记录。本机 Homebrew qpdf 后端声明 macOS 27.0，较早系统可配置兼容的 qpdf，实际可用性由运行探测报告。

### Rust 调用方迁移

原有 scan/sanitize/verify 和图片处理函数继续保留。新范围参数使用 SanitizeOptions 与 advanced 模块，默认 Safe 行为保持原契约。新增格式和 not_assessed 结果需要同步更新调用方的穷尽 match。Report 新增可选字段后，直接构造完整结构体的调用方可改用 Report::new 并设置所需字段。0.3 读取器兼容旧 JSON，严格 schema 校验器应采用本仓库更新后的 0.3 schema。is_image 继续表示现有 JPEG/PNG 像素处理范围，媒体容器与音频通过独立能力分类判断。FilesystemOptions 新增默认关闭的 normalize_creation_time 与 remove_usage_metadata，Rust 结构体字面量可通过 ..Default::default() 保留默认选项。

## 本轮审计修正

补齐队列图片水印检测、像素与归档资源设置、大报告分页和搜索缓存。修复 MCP 目录身份授权、手机媒体嵌套元数据、Office 历史隐藏属性、极端预算计算与 Markdown 候选扫描性能问题。复现记录与测量见 [审计记录](docs/AUDIT_2026-11-12.md)。

Rust GUI 库新增 `TaskKind::DetectWatermark` 枚举项。下游对 `TaskKind` 使用穷尽匹配时，需增加该分支。`SignalObservation` 增加源样本类型与 RGB8 转换字段，用于说明统计范围。Rust 字段字面量需补充 `source_sample_model` 和 `converted_to_rgb8`，优先使用 `analyze_signal` 返回的观察结果。旧 JSON 通过默认值继续读取。CLI 命令及既有 JSON 报告字段继续兼容，新增检测证据字段可按可选字段读取。
