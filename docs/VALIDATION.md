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
| B | PDF 13 项、真实独立生成 15 页 PDF 的页数/文本/逐页渲染一致；C2PA 真实 ES256 PNG/JPEG 签名、根信任、篡改、禁远程引用；明确授权删除凭据后的 SDK/像素/结构复验 | PDF 签名信任、PDF C2PA、真实签名 BMFF、CAWG 身份验证未验收 |
| C | Deep 格式回归、独立 XML 与 Python ZIP 互操作；HTML tokenizer 源范围处理；平台属性与修改时间；WAV/FLAC 音频负载保持；CoreAudio 独立解码两项通过 | 复杂修订、隐藏表公式依赖、复杂 HTML、MP3 重写保持明确支持限制 |
| D | LSB 检测 6 项、Diff Lab 6 项、C2PA/来源 9 项；Advanced 13 项包含真实 MCP 虚拟别名、原件/硬链接防护、旧报告读取与显式凭据移除 | 合成检测器覆盖公开测试协议，私有统计水印和 OEM 归因仍未评估 |
| E | macOS sips 实际编码并解码 HEIC/AVIF，AVFoundation 编码并读取 MP4/MOV，四格式 CLI 审计且原件哈希一致；Windows GNU 全目标 check；macOS 0.3 原生 framebuffer 2720×1700 捕获 | 三平台 CI 首轮发现 Clippy 问题并修复，后续真实执行结果继续记录 |

PDF 测试包括 Info/XMP/custom、旧增量作者无残留、附件/JS 保留、签名和加密保护、损坏与预算、可见内容篡改拒绝、Deep 选择性移除以及 Widget/复杂动作链保护。旧增量修订通过重新序列化和对象结构检查，保留的任意流内容有独立残留说明。

音频单元测试 7 项通过。macOS 独立验收用 9216 帧合成 PCM，经 CoreAudio 生成 FLAC，清洗前后独立解码为 WAV，使用 Python wave 对比 PCM 样本逐字节相同。技术声道、ReplayGain/R128 等字段保留，运行时内容验证声明其编码字节范围。日志为 `work/v03/audio-tests.log`、`audio-native-tests.log`。

当前全部证据保存在 `work/v03/`，历史 0.1/0.2 日志保持原样。新增测试通过既有 GUI worker、CLI 和授权 MCP 入口调用真实后端。原始全 workspace 首轮因旧 schema/未支持 Deep/PDF 的测试预期发生变化而失败，对应预期已更新，后续完整回归以本节追加结果为准。

本机未找到 Developer ID Application 身份，正式签名及公证待相应凭据。Apple Development 身份存在，当前开发包继续采用 ad-hoc 签名。可选本机 qpdf 后端 Mach-O 要求 macOS 27.0，主程序最低系统要求单独记录。
