# 验证记录

## 可复现命令

从项目根目录执行。

```sh
cargo run -p fixture-generator -- work/regenerated-fixtures
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo build --release -p fileveil-cli
./target/release/fileveil capabilities --json
./target/release/fileveil scan tests/fixtures/jpeg_exif_gps_author.jpg --json
./target/release/fileveil sanitize tests/fixtures/jpeg_exif_gps_author.jpg --output work/jpeg.clean.jpg --json
./target/release/fileveil verify tests/fixtures/jpeg_exif_gps_author.jpg work/jpeg.clean.jpg --json
```

样本目录需要为空，生成器拒绝覆盖文件。验证输出目录 `work/` 用于本地中间产物。

## 合成样本

生成器创建虚构作者、设备、时间和 GPS 数据。JPEG 使用 EXIF、XMP、IPTC、COM 和人工构建的 ICC；PNG 使用文本、EXIF 和压缩 ICC。其他样本包括干净图片、未知 JPEG APP、损坏 CRC、Office 属性与保留内容、签名线索、ZIP 路径穿越、名称冲突和高压缩比输入。

`docx_signed.docx` 用于检测签名结构并阻断改写，证书有效性不在该样本的验收范围内。`pdf_corrupt.pdf` 用于 PDF 能力限制报告。

## 验收项目

- 扫描和净化操作前后原件 SHA-256 一致。
- JPEG/PNG 输出重新解析成功，像素一致，ICC 与编码内容保留。
- Office 输出重新解析成功，内部关系有效，非属性部件内容一致。
- 未知、保留或未检查的类别具有明确报告状态。
- 非法输入、已存在输出、签名结构及资源超限返回稳定失败代码。
- 超时和取消时终止工作进程并清理临时输出。

## 0.1 CLI 验收快照

2026-11-11 在 macOS Apple Silicon 上完成本机验证，主构建使用 Rust 1.99.0。

| 检查 | 结果 |
| --- | --- |
| `cargo fmt --all --check` | 通过 |
| `cargo clippy --locked --all-targets -- -D warnings` | 通过 |
| `cargo test --locked --workspace` | 44 个测试通过，0 失败 |
| `cargo build --locked --release -p fileveil-cli` | 通过，生成 macOS arm64 CLI |
| JPEG/PNG/DOCX/XLSX/PPTX 发行版闭环 | 5 种格式通过扫描、净化与验证 |
| 原件、图像与容器保真 | 原件 SHA-256、图像像素、ICC/编码内容和 Office 保留内容对照通过 |
| 禁网运行 | macOS `sandbox-exec` 拒绝网络权限下完成格式闭环 |
| JSON 报告 | 15 份报告通过当前 schema 所使用的字段、类型、枚举、必填项与哈希约束校验 |
| 超时与取消 | 返回 6，无目标输出与临时文件残留，原件哈希一致 |
| macOS 属性 | Quarantine、下载来源逐字节传播测试通过；资源叉可审计并阻断改写 |
| 并发与冲突 | 自动命名并发防覆盖、显式输出保护、特殊路径测试通过 |
| 依赖漏洞 | `cargo audit --file Cargo.lock` 通过 |

DOCX/PPTX 合成样本保留批注或媒体等结构，报告为 `partially_verified` 并返回 4。其净化副本通过结构与内容验证。JPEG、PNG 和 XLSX 主样本返回 `verified_within_scope`。

### Office 外部兼容性检查

使用本机 LibreOfficeDev 26.8.0.0.alpha0，以隔离用户配置和禁网沙箱打开三种 Office 原件与净化副本，全部成功导出 PDF。每对文件的抽取文本一致，72 DPI 页面渲染逐页一致，均为一页。该项覆盖这些合成样本的 LibreOffice headless 打开与渲染路径。Microsoft Office、交互式 GUI 和更广泛真实文档兼容性仍待验收。

### 跨平台检查

使用已安装的 Rust 1.98.0-nightly 工具链，对 `aarch64-unknown-linux-musl` 和 `x86_64-pc-windows-gnu` 执行 `cargo check --locked --workspace --all-targets`，均通过。Windows/Linux 原生运行和 GitHub Actions 远端执行仍待验收，CI 已配置三平台矩阵。

### 验证记录位置

- 最终格式检查、Clippy、44 个测试、构建与交叉检查日志位于 `work/validated-build/`。
- 最终源码文件哈希、CLI 二进制哈希和发行版 JSON 报告位于同一目录。
- 禁网扫描、schema 对照和 LibreOffice 页面比较位于 `work/final-acceptance/`。
- 超时与取消记录位于 `work/supervision-check/results.json`。
- 依赖审计日志位于 `work/dependency-audit.txt`。

以上记录对应 2026-11-11 的 0.1 CLI 源码与合成样本快照。0.2 桌面版的执行记录见下一节。

## 0.2 桌面版初始验收

2026-11-12 在 macOS arm64 上运行 FileVeil 0.2.0 原生应用，GUI 声明最低 Rust 版本为 1.95。本机主构建使用 Rust 1.99，报告 schema 继续使用 0.1。

| 检查 | 结果 |
| --- | --- |
| 原生文件与目录导入 | 本机窗口操作通过 |
| `cargo fmt --all --check` | 最终源码通过 |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | 最终源码通过 |
| `cargo test --locked --workspace` | 71 个测试通过，0 失败 |
| GUI 与 CLI release 构建 | 最终源码通过 |
| PNG 单文件净化与 JSON 导出 | 副本保存、验证结果和脱敏报告导出通过 |
| 中英文界面与三种主题 | 本机切换通过 |
| 7 文件批量队列 | JPEG、PNG、DOCX、XLSX、PPTX 五类样本生成副本，签名 DOCX 与坏 CRC PNG 阻断 |
| 五份批量副本的独立 CLI 验证 | 保留内容摘要一致，图片像素一致 |
| 原件校验 | 17 份合成输入文件 SHA-256 保持一致 |
| GUI worker 集成 | 8 项测试通过，覆盖五格式闭环、错误输入、特殊路径、防覆盖、超时、取消、句柄释放和进程回收 |
| 工作台与验证结果区域 | 本机连续扫描与净化操作通过 |
| 独立验证入口、JSON 预览、打开输出目录 | 本机窗口操作通过 |
| Windows GNU 目标 | `x86_64-pc-windows-gnu` Cargo check 通过 |
| Linux musl 目标 | `aarch64-unknown-linux-musl` Cargo check 通过 |
| macOS 应用包 | 生成 `dist/FileVeil.app`，采用本地 ad-hoc 签名 |
| 依赖审计 | 退出码 0，存在三条 Linux 依赖停止维护提示 |
| 许可资产 | 402 个注册表依赖、764 份许可与署名文件已收集，锁文件与文本哈希校验通过 |

DOCX/PPTX 样本保留批注或媒体等结构，报告为 `partially_verified`。原生界面显示这些保留项，副本通过独立验证。

### 桌面版复现入口

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release -p fileveil-gui -p fileveil-cli
python3 tools/package-desktop.py --skip-build
open dist/FileVeil.app
```

已有应用包可以使用 `--replace` 更新。原生界面测试使用项目内合成样本。GUI worker 的自动化入口位于 `crates/fileveil-gui/tests/jobs.rs`，工作台布局与可访问性检查位于 `crates/fileveil-gui/tests/layout.rs`。

### 桌面版记录位置

- 工作区初始 GUI 检查、71 个测试、release 构建和验收摘要位于 `work/gui-before-watermark/`，汇总见该目录的 `acceptance.json`。
- 原生导入、净化副本、导出的单文件报告和批量独立验证结果位于 `work/gui-acceptance/`。
- 输入哈希记录位于 `work/gui-acceptance/input-sha256.json`，最终发行版 CLI 对五份实际 GUI 副本的复验见 `work/gui-before-watermark/native-batch-verified.json`。
- 最终源码的跨平台 Cargo check 结果位于 `work/gui-before-watermark/crosscheck-results.json`，对应日志位于同目录的 `crosscheck-windows.log` 与 `crosscheck-linux.log`。
- 当前依赖审计与许可检查位于 `work/gui-audit.txt`、`work/gui-license-check.json`。
- 许可清单及逐文件哈希位于 `THIRD_PARTY_NOTICES.txt` 与 `assets/licenses/index.json`。

单文件导出使用 `docs/report.schema.json`，批量导出封套使用 `docs/batch-report.schema.json`。批量封套包含每个队列条目的最新可用报告。

### 后续验收与能力

原生拖放手势、Windows/Linux 原生桌面运行、Microsoft Office 交互式打开、更广泛真实文档、覆盖导向长时 fuzz、Apple Developer ID 签名、公证和项目开源许可证选择仍待验收或完成。

PDF 可信重写、C2PA 密码学验签、内容级与统计水印检测、`deep` 和 `research` 策略保持能力矩阵所列状态。当前适配器采用受限内存快照，默认单文件 64 MiB。EXIF 方向、APNG、签名、宏、加密及资源叉等情况由核心保守处理。

## 图片处理、主题调整与 MCP 追加验收

2026-11-12 整合默认深色、柔和浅色快捷切换、设置内语言选择、图片信号处理和本地 stdio MCP。报告 schema 更新为 0.2，读取兼容旧版 0.1 报告。

工作区统一格式检查、严格 Clippy 和 97 项测试通过。测试包含九项图片引擎回归、两种图片模式的真实 GUI worker/CLI 路由、四项输出配方会话回归、两项主题与语言位置回归，以及 MCP 协议的两项单元测试和五项真实 stdio 集成测试。日志位于 `work/gui-final/checks.json` 及对应 `check-*.log`。

低位模式使用已知合成 LSB 载荷检查 RGB 目标位归零、Alpha 保留和 1/2/3 位误差界。信号模式检查固定缩放、平滑、JPEG 回译配方及重新解码的像素对照。ICC、PNG 显示记录、隐私标签移除、安全来源标记、已有输出保护、损坏输入和配方篡改也有对应回归。

图片处理结果为 `partially_verified`，`image.processing.executed` 使用 `applied_verified` 状态，`image_processing.detector_status` 为 `not_assessed`。元数据移除使用 `removed_verified`。未知密钥水印的清除效果需要对应检测器验证。

MCP 协商 2025-11-25，兼容 2025-06-18。协议测试覆盖初始化、五工具发现、扫描、净化、两模式图片处理、验证、防覆盖、参数错误、繁忙请求、取消与连接结束清理。服务输出用于 MCP JSON 消息，成功和部分验证结果使用 `isError=false`。

最终 Windows GNU 与 Linux musl GUI 全目标 Cargo check 均通过，记录位于 `work/gui-final/crosscheck-results.json`。

### 最终黑灰材质与原生操作

最终深色界面采用中性黑灰，浅色采用中性灰白，应用标志及桌面图标均为灰阶。macOS 窗口背景透明并启用原生模糊，标题栏绘制与内容配色一致，原生窗口控制保留。高对比保持不透明，其他平台采用不透明背景。

视觉修改后，GUI 的 23 项单元测试及 2 项布局回归通过，主题文本在黑色与白色桌面背景上合成后的对比检查通过。macOS 实际点击完成深浅切换、设置内中英语言切换、MCP 配置入口检查，以及两种图片模式的保存闭环。GUI 生成的两份 PNG 与官方 SDK 闭环中经过独立 PNG 解码的结果逐字节一致，最终 CLI 配方复验通过，记录位于 `work/gui-final/native-image-results.json`。

使用官方 Python MCP SDK 2.3.0 直接启动最终签名应用内的可执行文件，完成初始化、五工具发现和 14 次工具调用。协议版本为 2025-11-25，协议异常为 0，17 份合成原件保持一致，暂存目录清理通过。完整记录位于 `work/gui-final/mcp-sdk-final/summary.json`，其中保存实际受测可执行文件 SHA-256。

最终源码和应用包文件摘要位于 `work/gui-final/source-sha256.json`、`package-sha256.json`，打包及签名摘要位于 `package.json`。原生拖放手势、Windows/Linux 原生运行、正式签名与公证等验收范围沿用前述待完成项目。

## 0.3 Gate 记录

本轮沿用原工程和原 Cargo target，首次提交为 `2ee856a`。提交前检查 1283 个候选文件，未发现私钥或令牌标记，未发现 20 MiB 以上候选文件。target、work、dist、Python 缓存均被忽略。作者沿用另外两个本地项目的相同署名，并检查了已登录 GitHub 账号。由该提交导出的干净源码使用共享 target 执行 locked/offline workspace check，退出码 0，记录在 `work/v03/clean-check.log`。

| Gate | 已实际完成的检查 | 尚需区分的范围 |
| --- | --- | --- |
| A | 完整官方 MPL-2.0、SPDX、第三方许可、首次提交、干净源码 check；MCP 权限单元 7 项、真实 stdio 8 项、jobs 9 项；8 样本 Lab FD 继承 | 依赖 RSA 已记录限定公钥验证调用范围的审计例外，原始失败日志保留 |
| B | PDF 13 项、真实独立生成 15 页 PDF 的页数/文本/逐页渲染一致；C2PA 真实 ES256 PNG/JPEG 签名、根信任、篡改、禁远程引用；明确授权删除凭据后的 SDK/像素/结构复验 | 传统 PDF 签名信任与 CAWG 身份验证未验收，后续 PDF/文本/WAV/BMFF 验签结果见追加记录 |
| C | Deep 格式回归、独立 XML 与 Python ZIP 互操作；HTML tokenizer 源范围处理；平台属性与修改时间；WAV/FLAC 音频负载保持；CoreAudio 独立解码两项通过 | 复杂修订、隐藏表公式依赖、复杂 HTML、MP3 重写保持明确支持限制 |
| D | LSB 检测 6 项、Diff Lab 6 项、C2PA/来源 9 项；Advanced 13 项包含真实 MCP 虚拟别名、原件/硬链接防护、旧报告读取与显式凭据移除 | 合成检测器覆盖公开测试协议，私有统计水印和 OEM 归因仍未评估 |
| E | macOS sips 实际编码并解码 HEIC/AVIF，AVFoundation 编码并读取 MP4/MOV，四格式 CLI 审计且原件哈希一致；Windows GNU 全目标 check；macOS 0.3 原生 framebuffer 2720×1700 捕获 | 三平台 CI 首轮发现 Clippy 问题并修复，后续真实执行结果继续记录 |

PDF 测试包括 Info/XMP/custom、旧增量作者无残留、附件/JS 保留、签名和加密保护、损坏与预算、可见内容篡改拒绝、Deep 选择性移除以及 Widget/复杂动作链保护。旧增量修订通过重新序列化和对象结构检查，保留的任意流内容有独立残留说明。

音频单元测试 7 项通过。macOS 独立验收用 9216 帧合成 PCM，经 CoreAudio 生成 FLAC，清洗前后独立解码为 WAV，使用 Python wave 对比 PCM 样本逐字节相同。技术声道、ReplayGain/R128 等字段保留，运行时内容验证声明其编码字节范围。日志为 `work/v03/audio-tests.log`、`audio-native-tests.log`。

当前全部证据保存在 `work/v03/`，历史 0.1/0.2 日志保持原样。新增测试通过既有 GUI worker、CLI 和授权 MCP 入口调用真实后端。原始全 workspace 首轮因旧 schema/未支持 Deep/PDF 的测试预期发生变化而失败，对应预期已更新，后续完整回归以本节追加结果为准。

本机未找到 Developer ID Application 身份，正式签名及公证待相应凭据。Apple Development 身份存在，当前开发包继续采用 ad-hoc 签名。可选本机 qpdf 后端 Mach-O 要求 macOS 27.0，主程序最低系统要求单独记录。

### 0.3 最终本机收敛验收

最终单轮 `cargo test --locked --workspace --offline` 为 228 项通过、0 项失败、6 项忽略，31 个测试目标，日志为 `work/v03/final-closure-tests.log`。随后 PDF 空附件结构误报修复通过 20 项定向回归，四媒体公样新增一项循环检测回归及一个显式重生成器，记录在 `pdf-attachment-report-tests.log`、`provenance-media-tests.log`。最终源码的全目标 Clippy、6 项打包单元测试与真实 CLI JSON Schema/旧报告包络验证分别记录在 `final-closure-clippy.log`、`final-closure-packaging-tests.log`、`final-closure-schemas.log`。

该轮六项忽略包括三个显式公样重生成器，以及需要本机 PDF 输入、CoreAudio 或 Python ZIP/XML 的三项互操作测试。四媒体增量再增加一个重生成器。对应原生音频、真实 PDF、Office ZIP/XML 和媒体解码已另行执行并记录，忽略状态保留以支持离线跨平台测试。

来源验签公样覆盖 JPEG、PNG、PDF、TXT、Markdown、WAV、HEIC、AVIF、MP4 和 MOV。检查 COSE 签名、原始文件绑定、显式本地根、签名声明篡改和编码负载篡改。TXT A.8 与 Markdown A.9 使用固定 SDK 的实验性功能，非 NFC 纯文本绑定、歧义 Markdown 包装和旧 PDF 修订范围保持单独状态。

安全回归覆盖四格式标准 XMP 来源引用的默认保护，即使 URI 不含 c2pa 字符也会阻断 Safe。新发行 CLI 独立入口再次验证 JPEG/PNG/PDF/WAV 的扫描、无输出阻断、原件哈希，以及前三格式显式 Deep 移除和再次验证。隔离关闭 Poppler 后，共享 Metadata/Contents 的 PDF 仍在修改前阻断。证据位于 `work/v03/independent-credential-guards-p0vdk9ve/`，该目录包含运行二进制摘要及逐命令报告。

macOS 原生交互完成以下闭环。

- 已知合成 LSB PNG 检出，1 位处理后对应检测器未检出。原件哈希保持一致，独立 CLI 对实际 GUI 输出完成复验。
- 两样本 Diff Lab 实际计算直方图、低位、熵、DFT/DCT 和像素差分。灰阶图表可展开，导出 JSON 通过 Schema 验证。
- 签名 Markdown 与 PDF 默认保护，Deep 明确选择移除来源凭据后生成新副本，GUI 再次验证和报告导出成功。Markdown 正文字节不变，PDF 独立页数、文本与页面渲染一致。
- JPEG/PNG 批量任务实际生成两份副本，CLI 检查内容、像素及原件哈希，原件逐字节匹配已提交测试样本。
- 中文/英文、灰黑深色/灰白浅色切换、MCP 读取与输出授权分离及配置生成完成实际点击验收。测试授权已清空，当前设置保留中文深色默认。

交互证据包括 `native-gui-lab-report.json`、`native-gui-processing-verified.json`、`native-gui-markdown-report.json`、`native-gui-pdf-report.json`、`native-document-summary.json` 和 `native-batch-verified.json`，均在 `work/v03/`。原生 GUI 测试发现并修复了队列无障碍激活、受保护扫描类型丢失、格式间范围误传、来源状态上下文及陈旧设置说明。

四份带 C2PA 的移动媒体样本分别经 macOS ImageIO/sips 与 AVAssetReader 独立解码。HEIC/AVIF 为 8×6，MP4/MOV 为 64×64 两帧，记录在 `signed-media-native-interop.log`、`signed-image-native-interop.json`。移动媒体当前提供审计与验签，净化重写保持格式矩阵中的限制。

许可清单收敛为 639 个 registry 包、1215 份许可/署名文本，逐文件摘要核对通过。macOS 包同时包含 GUI、CLI、项目许可证、第三方声明、对应源码 ZIP 和 qpdf 后端。打包器已执行随包后端探测和 ad-hoc 签名验证。Gatekeeper 实际评估为 rejected，Developer ID Application 身份数量为零，正式发行签名和公证仍需凭据。

上一轮产品源码提交为 `e4d9acb`，对应 CI 运行配置提交为 `2660b1e`。三平台原生验收、GUI framebuffer、包内 CLI 与签名状态均已实际通过工作流检查，见 [平台工作流](https://github.com/J-x-Z/fileveil/actions/runs/43153669093)。同一 Cargo.lock 的依赖漏洞与许可审计已通过，见 [安全工作流](https://github.com/J-x-Z/fileveil/actions/runs/43144954833)。安全审计继续保留本文安全说明中的 RSA 限定例外。

含 NUL 的有效 UTF-8 TXT/Markdown 普通扫描提供只读候选审计，GUI 可据此进入 Deep 的显式控制符清理。默认 Safe 改写保护与基于文件签名的 identify 判型继续由各自入口检查。新增格式正反例两项、正常扫描后实际点击 Deep/展开文本范围的 headless GUI 回归一项，均通过，记录在 `text-candidate-tests.log`、`text-candidate-gui-tests.log`，原有 Core 控制符清理回归也通过。

对应 macOS 包的干净源码恢复验收复用现有 target，锁定离线 workspace check 通过。逐文件对照、应用/CLI/源码归档摘要和最终 Gatekeeper 结果位于 `work/v03/` 的恢复收据与 `final-package-receipt.json`，该证据独立于源码归档保存。

### 三平台最终原生 CI

最终工作流的三个原生任务均为 `success`，每个平台执行 32 个 Rust 测试目标。实际测试数量受平台条件编译影响。

| 运行环境 | 通过 | 失败 | 忽略 | 实际 GUI framebuffer | 包内 GUI 与 CLI |
| --- | --- | --- | --- | --- | --- |
| macOS Apple Silicon | 233 | 0 | 7 | 1060×700，3 帧 | 构建、打包、后端探测及 CLI 验证通过 |
| Linux x86_64 | 229 | 0 | 6 | 1280×850，3 帧 | 构建、打包、后端探测及 CLI 验证通过 |
| Windows x86_64 | 223 | 0 | 6 | 1024×768，3 帧 | 构建、打包、后端探测及 CLI 验证通过 |

三平台均检查最终副本、原件 SHA-256、真实 JSON Schema 与旧报告包络。Windows 原生测试确认授权目录句柄拒绝重命名、junction 无法扩展授权，Job Object 在正常退出、超时、取消及句柄丢弃时结束 worker 与其派生进程。MD、TXT、PDF 经授权 MCP 完成扫描、显式本地根验签、默认保护、Deep 凭据移除及再次验证。

Windows 验收发现 qpdf 12.4.2 会误解 argv 中的 verbatim 绝对路径。后端现在在操作自有私有目录中执行，文件参数使用内部固定名称，绝对路径继续用于受限读写、大小监视和清理。DOS 与私有 canonical cwd 的原生 qpdf 对照输出 SHA-256 相同，MCP 输入权限继续使用卷 GUID 和持有句柄。

Windows GUI CI 使用已校验 SHA-256 的 Mesa 26.2.6 MinGW x64 llvmpipe。三个原生 framebuffer 均已实际查看，使用中性黑灰界面并正确显示中文。Windows 包只包含 qpdf30.dll，不包含 CI 的 Mesa DLL。两份 Windows 可执行文件 Authenticode 状态均为 `NotSigned`。macOS ad-hoc 签名严格验证通过，Gatekeeper 评估为 rejected。正式平台签名与公证继续等待凭据。

最终测试及原生证据保存在 `work/v03/ci-evidence/2660b1e-*`，三平台测试汇总为 `2660b1e-tests-summary.json`。Windows 与 Linux 的 CI 成品保存于 `work/v03/ci-release/`，收据记录下载源、归档摘要、二进制清单匹配及许可证核对。Linux 交付归档采用保留 GUI/CLI 执行权限的 tar.gz，原始 Actions ZIP 单独保留为证据。

### 手机媒体净化闭环回归

2026-11-12 增加 HEIC/HEIF、AVIF、MP4/MOV 偏移保持重写。19 项 BMFF 测试覆盖实际编码样本、共享 extent、保护与加密结构、损坏偏移、未知 UUID 保留、篡改和幂等。Engine 的三个正常入口回归覆盖 Scan → Sanitize → Verify、原件字节不变、签名保护和 Deep 文件属性。

macOS 独立 ImageIO/AVAssetReader 回归实际通过，覆盖 HEIC、AVIF、H.264 MOV、H.264 MP4 和 H.264/AAC MP4。清理前后的解码 RGBA、PCM、视频帧、轨道变换及采样时序完全相同。运行时报告明确保留编码负载与结构的验证范围，平台解码属于此回归证据。记录保存在 `work/v03-final/media-*.log`，原始媒体由仓库内平台编码脚本生成。

### 公开图像水印与离线 AI 来源回归

2026-11-12 增加 Stable Diffusion 1/SDXL 实际公开消息检测、原分辨率信号观察、灰阶预览和用户参考组。独立 Python 上游编码器及解码器在 NASA 512×512 自然照片上确认 PNG 和 JPEG 4:4:4 正样本分别匹配 136/136 与 48/48 位。Rust CLI Signal 处理后的输出由同一独立上游解码器复检，分别匹配 86/136 与 26/48 位，均低于对应检测阈值。普通 JPEG 4:2:0 重编码、未知消息与干净照片作为阴性或编码对照。版本、哈希及分数位于 `crates/fileveil-engine/tests/fixtures/watermark/upstream-evidence.json`，可复现脚本与第三方 MIT 声明随源码保留。

Lab、公开检测器、CLI/MCP 分组入口及 GUI 结果显示均有针对性回归。OpenAI、Anthropic、Google 的专有检测器保持明确的未配置或受限状态。当前版本未配置在线凭据，检测全程离线。

### Deep、系统属性与 PDF 状态修正

2026-11-12 增加 Word 旧网格/编号历史、受支持表格行修订、w14 冲突与自定义 XML 修订范围，以及现代 PowerPoint 批注、作者和显式关系清理。复杂纵向合并、仍有活动内容的删除行及未选关系继续安全阻断。25 项 Deep 回归全部通过，包含 Python 独立 ZIP CRC/XML 验证，以及 python-docx 打开新增 Word 输出。

Engine 系统属性与 Deep 选项回归 15 项通过，覆盖下载日期、最近使用时间属性、新副本创建时间规范化、原件不变及时间被篡改时禁止发布。创建时间选项在 macOS 本机 APFS 已验证，Windows 将由原生 CI 回归，Linux 对该选项明确报告不支持。PDF 签名扫描状态回归通过，成功扫描与禁止改写独立记录，保护副本输出。

本轮本机 `cargo test --locked --offline --workspace` 汇总 269 项通过、0 失败、8 项忽略，共 33 个目标。忽略项中的手机媒体独立解码和 Deep Python 互操作已分别显式执行通过。workspace Clippy `-D warnings`、格式检查、6 项打包测试、11 份实际报告和 2 份旧版报告 schema 验证通过。

macOS 本机使用正式打包应用实际点击完成公开 SDXL 检测、Signal 副本、输出检测、原件/副本 Diff Lab、H.264/AAC MP4 Safe 副本和文件选择器二次验证。深浅主题均目视核验。界面输出再次交由独立上游水印解码器核对为 48/48 → 26/48，视频副本由 AVAssetReader 独立对照音频、视频和时序完全相同。记录在 `work/v03-final/macos-native-ui.json`。随后补齐新增提示的中文翻译和频域图数值格式，46 项 GUI 单元测试和 GUI Clippy 通过。

### 剩余功能最终三平台验收

最终产品源码 `ec1e611` 的 [CI 43232451167](https://github.com/J-x-Z/fileveil/actions/runs/43232451167) 已实际完成且全部成功。

| 平台 | 通过 | 失败 | 忽略 | 原生界面与发行包 |
| --- | --- | --- | --- | --- |
| macOS Apple Silicon | 269 | 0 | 8 | framebuffer、手机媒体独立解码、打包与包内 CLI 通过，本机 CUA 操作通过 |
| Windows x86_64 | 259 | 0 | 6 | SendInput 实际点击水印页与检测，SDXL 48/48，4 个真实指针事件，打包及包内 CLI 通过 |
| Linux x86_64 | 265 | 0 | 6 | X11 XTEST 实际点击水印页与检测，SDXL 48/48，4 个真实指针事件，打包及包内 CLI 通过 |

Windows 使用 CI 专用 Mesa 软件 OpenGL，Linux 使用 Xvfb。CI 驱动未进入 Windows 发行包。三平台每平台 33 个测试目标，原件不变检查均通过。Windows/Linux 原始 GUI 状态、控制器记录、截图和测试日志绑定源码 SHA，位于 `work/v03-final/ci-pointer-43232451167/acceptance-receipt.json`。

三个分发归档位于 `dist/`，附 `SHA256SUMS`。每包包含对应源码、MPL-2.0 与必要第三方许可，MIT 水印适配文件保留其原许可。Windows/Linux 归档逐文件对照 CI 产物，Linux 可执行位保留为 0755。macOS 仍为 ad-hoc 签名，严格签名验证通过，Gatekeeper 拒绝；当前有 Apple Development 身份但缺 Developer ID Application。Windows Authenticode 状态为 NotSigned。正式发行签名与公证待相应发行凭据。

本轮仅清理可重新生成的 Cargo 缓存，实际释放 7.4 GiB。开始可用 17.4 GiB，构建、归档和保留旧发行包后可用 20.8 GiB。源码、原测试证据、原有 Windows/Linux 包及本轮替换前的 macOS 包均保留。最终包收据为 `work/v03-final/delivery-receipt.json`。

OEM 私有水印、专有密钥 AI 检测器仍需真实样本或授权检测能力。复杂受保护媒体结构、签名和加密内容继续按报告阻断。真实 Microsoft Office 显示保真尚待应用端验收。


### 多轮审计本机回归

本轮产品源码 `c5c2be6` 完成本机锁定离线 workspace 测试，共 290 项通过、0 失败、8 项忽略、33 个测试目标。macOS ImageIO/AVAssetReader 手机媒体独立解码、Python ZIP/XML 与 python-docx 互操作的忽略测试已另行显式执行并通过。最后补充的搜索缓存原地变更、失败重扫后的当前计划及双语队列错误原因修正通过 53 项 GUI 定向回归。

格式检查与 workspace 全目标 Clippy `-D warnings` 通过。6 项打包单测通过，11 份实际报告、2 份旧报告及批量封套通过 JSON Schema 检查。依赖审计沿用已记录的 RUSTSEC-2023-0071 限定例外，保留四项维护状态提示。

本轮回归覆盖 MCP 大小写与 Home 祖先授权、FIFO 与文件身份替换、极端预算数值、媒体嵌套 XMP、Office 历史隐藏属性、大报告分页、失败重扫后的资格控制和实际 worker 队列检测。原件不变、已有副本与处理配方保留均由对应测试检查。详细复现、性能测量与剩余边界见 [审计记录](AUDIT_2026-11-12.md)。本机证据保存在 `work/v03-audit/`。


### 多轮审计最终三平台与发行包

最终产品源码 `ad1fa18` 的 [CI 43248558309](https://github.com/J-x-Z/fileveil/actions/runs/43248558309) 已完成，三项原生任务全部 `success`。

| 平台 | 通过 | 失败 | 忽略 | 原生验收 |
| --- | --- | --- | --- | --- |
| macOS Apple Silicon | 291 | 0 | 8 | framebuffer、独立媒体解码、包内 CLI 与本机 CUA 操作通过 |
| Windows x86_64 | 279 | 0 | 6 | SendInput 实际点击、SDXL 48/48、数值共识、原件不变、包内 CLI 通过 |
| Linux x86_64 | 286 | 0 | 6 | X11 XTEST 实际点击、SDXL 48/48、数值共识、原件不变、包内 CLI 通过 |

各平台均执行 33 个 Rust 测试目标。Windows 使用 CI 专用 Mesa 软件 OpenGL，Linux 使用 Xvfb。Windows/Linux 均记录 4 个操作系统指针事件，实际激活图片页与检测按钮。三平台截图已查看。原始日志、截图、控制器和包内 CLI 证据位于 `work/v03-audit/ci-evidence/ci-43248558309/`。

[依赖安全与许可工作流 43246794118](https://github.com/J-x-Z/fileveil/actions/runs/43246794118) 已成功。检查 645 个依赖，沿用 RUSTSEC-2023-0071 的已记录限定例外和四项维护状态提示，许可证检查通过。该工作流后的产品提交未修改锁文件及依赖清单。

macOS 实际批量检测导出包含公开水印阳性与干净阴性两份报告，批量 Schema 与原件摘要检查通过。最终包实际验证了 1 MP 预算阻断、中文原因、失败重扫停用旧计划和恢复 32 MP 后重新扫描。双语、深浅主题均通过本机交互检查。记录位于 `work/v03-audit/macos-native-ui.json`。

三份发行归档及 `SHA256SUMS` 已更新至 `dist/`，摘要复验全部通过。每包内 1380 份源码对应 `ad1fa18`，MPL-2.0、MIT 水印适配及 qpdf 声明已核对。Windows 内嵌源码 ZIP 规范化了五个 checkout CRLF 差异，GUI、CLI 与其余资源保持 CI 原字节，原始 CI 成品保留。Linux 可执行位为 0755。后续文档和 LF checkout 规则追记独立于产品运行代码。

macOS ad-hoc 严格签名验证通过，Gatekeeper 拒绝，当前 Developer ID Application 身份为 0，Apple Development 为 1。Windows Authenticode 为 NotSigned。正式发行签名及公证仍待相应凭据。发行收据为 `work/v03-audit/delivery-receipt.json`，旧归档保存在 `work/v03-audit/previous-release/`。复用现有 target，收尾时磁盘可用约 21.1 GiB。
