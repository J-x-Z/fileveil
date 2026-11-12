# FileVeil 桌面版

0.4 桌面版使用 Rust 原生 egui/eframe 界面，扫描、净化和验证复用 FileVeil Core。报告使用 schema 0.4，并可读取 0.1–0.3 报告。运行时无需账号或网络连接，文件处理在后台工作进程执行。

## 构建与启动

GUI 构建需要 Rust stable 1.96 或更高版本。

```sh
cargo build --locked --release -p fileveil-gui -p fileveil-cli
./target/release/fileveil-gui
```

Windows 使用 `target\release\fileveil-gui.exe`。Linux 需要桌面显示会话及系统图形库。程序内置中文与拉丁字体，字体许可文本随项目提供。

## 使用流程

1. 将文件拖入窗口，或使用文件选择按钮添加文件。
2. 从左侧队列选择文件，执行扫描。
3. 在发现列表查看风险类别、证据位置、动作与状态，并在处理计划中核对保留项。
4. 保存净化副本，选择新的输出位置。成功后查看验证结果及残留信息。
5. 使用对比验证检查已有副本，或导出当前脱敏 JSON 报告。

文件队列适合依次处理多份文件。后台任务可以取消，资源设置可调整单文件大小、图像像素、归档与 Lab 聚合预算及任务超时。关闭窗口时会结束当前工作进程并清理该任务的临时文件。

默认外观为中性黑灰，侧栏提供浅色与深色快捷切换，浅色采用中性灰白背景。设置窗口集中提供语言、三种外观及资源选项。界面支持中文与英文。搜索用于过滤发现信息，清空队列用于移除当前会话中的文件条目。界面中的本地文件选择信息与导出的脱敏报告采用各自展示范围。

## 报告与保真

- JPEG/PNG 会重新解析并独立解码，比较像素与保留结构。
- DOCX/XLSX/PPTX 会检查 ZIP/OPC 关系和保留部件摘要。
- Quarantine、MOTW 等安全来源标记与可读取的系统属性传播至副本。
- `partially_verified` 表示已执行的验证通过，同时存在报告列出的保留项或检查范围限制。副本已经保存。
- `not_assessed` 表示该检查没有执行，适用于内容级与统计水印等类别。

TXT、Markdown 和 HTML 可在 Deep 工作区选择净化范围。PDF 完整重写与 C2PA 离线验签已接入共享核心，专有水印及复杂内容限制见格式矩阵。

单文件导出符合 [报告 schema](report.schema.json)。导出全部报告时使用 [批量报告 schema](batch-report.schema.json)，`reports` 数组包含队列中各文件的最新可用报告。

## 桌面打包

打包工具需要 Python 3.11 或更高版本。从项目根目录运行，工具会先构建当前主机的 release GUI。

```sh
python3 tools/package-desktop.py
```

已有 release 二进制可以直接打包。

```sh
python3 tools/package-desktop.py --skip-build
```

macOS 输出 `dist/FileVeil.app`，可通过 Finder 打开，或执行以下命令。

```sh
open dist/FileVeil.app
```

该应用包使用本地 ad-hoc 签名。Apple Developer ID 签名、公证和正式分发验收仍待完成。Linux 与 Windows 在各自主机构建便携目录，包含可执行文件和已有的许可说明。

默认保护已有输出。更新本工具创建的同名 FileVeil 包时使用 `--replace`。工具检查包标识，保存新包之前保留旧包，发布失败时尝试恢复旧包。

```sh
python3 tools/package-desktop.py --skip-build --replace
```

`--target-directory` 指定 Cargo 构建目录，`--output-directory` 指定打包目录，`--icon` 可为 macOS 包提供 PNG 或 ICNS 图标。全部默认资产保存在项目目录。

## 验收范围

macOS arm64 的实际窗口交互、批量队列检测、报告导出、资源预算和应用包验证已记录在 [验证记录](VALIDATION.md)。Windows 与 Linux 原生 CI 执行窗口渲染、指针点击、实际水印检测、文件操作和打包。原生拖放手势、更广泛的物理 GPU 与桌面环境、正式签名和系统级文件关联需要对应平台验收。

## 资源预算

桌面队列采用串行隔离任务，最多导入 2000 个文件。单次文件夹导入检查最多 10000 个条目，默认只导入所选文件夹的直接文件，可在设置中启用子文件夹。保留报告的发现条目达到 100000，或估算堆内存达到 128 MiB 时停止后续队列任务。估算涵盖报告 JSON 数组、字符串和发现列表，完成当前任务后检查，可能超过阈值一个报告。导出报告并清除已完成项后可继续。默认单文件 64 MiB、图像 32 MP、归档与 Lab 聚合 128 MiB、单任务 120 秒。设置范围分别为 1–512 MiB、1–64 MP、1–1024 MiB 和最长 3600 秒。像素和归档预算约束输入规模，进程的总内存还包括解码与处理缓冲。

队列与界面设置按当前会话管理。原件和净化副本保存在用户选择的位置，JSON 报告由用户显式导出。

## 图片水印处理

从所选图片的处理计划中打开“图片水印处理”。选择低位清理或信号处理，核对参数后点击“处理并保存副本”，再选择新的 PNG 路径。作者、时间、文本元数据随容器重建同步净化。原文件保留。

低位模式可选 RGB 最低 1、2 或 3 位，单通道最大数值改动分别为 1、3 或 7。透明度保持一致。信号模式使用 95% 缩放回采样、σ 0.5 高斯平滑和质量 88 的 JPEG 回译，最终保存 PNG。它会影响图片细节，报告显示实际改动通道数、最大变化和均方误差 MSE。

验证结果为部分验证通过，涵盖可解析性、处理参数、像素配方、安全属性与原件哈希。通过“验证副本”可按当前输出保留的配方再次检查。未知密钥水印检测状态保持 `not_assessed`。

输入范围为 8 位 RGB/RGBA PNG 与三分量 JPEG。APNG、方向保护、来源凭据、资源叉及不兼容色彩配置由核心给出明确结果。

## 本地 MCP 服务

设置中点击“复制 MCP 连接配置”，将配置加入支持本地 stdio 的 MCP 客户端。macOS 应用包的示例如下。

```json
{
  "mcpServers": {
    "fileveil": {
      "command": "/Volumes/WINDOWS/work/fileveil/dist/FileVeil.app/Contents/MacOS/fileveil-gui",
      "args": ["--mcp", "--mcp-read-root", "/absolute/selected-input", "--mcp-write-root", "/absolute/new-copies", "--mcp-max-operations", "64"]
    }
  }
}
```

服务由客户端按需启动，标准输出用于 MCP 消息。设置中独立选择读取和输出目录，复制配置后重连生效。空授权仅允许能力查询。服务端约束目录范围和文件链接，输出只能新建，每连接默认最多 64 次操作。示例目录必须换成实际选择的绝对路径。

签名密钥默认没有 MCP 授权。在设置中使用“授权签名密钥”逐个选择，或为服务添加可重复的 `--mcp-signing-key /absolute/owner.key`。所选 Ed25519 或 ES256 私钥还须位于授权读取目录内。证书、信任策略和对照文件也受读取授权约束。MCP 提供 Heritage 操作，密钥生成使用 GUI 或 CLI。

扫描、净化、验证和图片处理沿用串行隔离 worker。执行中可通过 MCP 取消通知终止任务，客户端关闭连接时回收任务与暂存目录。输入上限和超时可以在工具参数内设置，默认分别为 64 MiB 和 120 秒。

| MCP 工具 | 主要参数 |
| --- | --- |
| `fileveil_capabilities` | 空对象 |
| `fileveil_heritage` | `path`、`action`，可选 `output`、`options_json` |
| `fileveil_scan` | `path` |
| `fileveil_sanitize` | `path`，可选 `output`、`profile`、`options_json` |
| `fileveil_process_image` | `path`，可选 `output`、`mode`、`low_bits` |
| `fileveil_verify` | `original`、`output`，Deep 使用同一 `profile`/`options_json`，图片处理使用 `mode`/`low_bits` |
| `fileveil_detect_watermark` | `path`，公开 LSB 与 Stable Diffusion 检测 |
| `fileveil_lab` | `paths`，2–8 个已授权样本 |
| `fileveil_provenance` | `path`，可选已授权本地 PEM `trust_roots` |

`mode` 可取 `low_bits` 或 `signal`，默认低位处理使用 2 位。文件操作工具可传 `max_file_mib` 与 `timeout_seconds`。图片处理结果含 `image_processing` 参数与误差统计，未知水印检测状态保持 `not_assessed`。

`fileveil_heritage` 的 `action` 可取 `detect`、`mark`、`clean`、`verify`、`trace`、`lab`、`c2pa_mark`。`options_json` 是共享 `HeritageRequest` 的 JSON 字符串，密钥参数使用已授权的本地路径。

macOS 的常规主题使用中性半透明背景和原生窗口模糊，浮层和卡片使用细灰边与低强度阴影。高对比模式保持不透明，其他平台采用不透明中性材质回退。应用内标志与桌面图标使用灰阶。

## 工作区

顶部标签切换文件扫描、Heritage 引擎、Deep 净化、图片水印、Diff Lab、AI Provenance 和批量验证。文件队列保持在左侧。Deep 参数按 Office、PDF、文本和文件系统分组，明确选择内容变更项，保存副本后可再次验证。复杂依赖将显示实际阻断原因。

图片工作区提供公开 LSB、SD1/SDXL 检测器和 Experimental Signal Processing 参数入口。扫描队列后可点击“检测队列图片”，串行检测已扫描的 JPEG/PNG，支持取消、逐项结果和导出全部报告。检测保留原扫描证据及已保存副本的验证配方。扫描失败会暂停该文件的后续改写资格。Diff Lab 选择 2–8 个对照样本后执行实际统计分析并导出报告。AI Provenance 可以选择本地 PEM 信任根，分别查看签名、资产绑定和信任状态。私有检测器未配置时显示真实能力状态。

原生 GUI 自动验收入口为 `fileveil-gui --smoke-test-report work/native-gui.json`。它创建实际窗口，在第三帧请求 eframe 读取渲染后的 framebuffer，保存 PNG 和平台报告后退出。该结果覆盖窗口与渲染路径，人工交互与更广泛设备验收另行记录。

## Heritage 引擎

选择左侧文件后进入“Heritage 引擎”。“添加标记”“清理标记”“验证”“来源链”和“标记实验室”调用共享后台任务，结果显示实际检测、签名、资产绑定、信任与保留风险。添加和清理均要求选择新的输出路径。

添加标记时填写作品 ID、作者、版本与时间声明。“使用当前时间声明”由用户点击填入当前 Unix 时间，可信时间戳状态单独报告。Ed25519 可选择 SELF 本地签名或 NATI 发行策略、多个密钥与阈值，首个密钥对应本条记录的持有人。修改记录可以选择上一版本，转移记录填写接收方公钥 ID。“生成签名密钥”保存未加密二进制 `.key` 文件，默认名为 `FileVeil-signing.key`，应按本地私钥管理。

可选公开图像标记使用 FileVeil 自主扩展的 DCT 协议，会改变像素和 JPEG 编码。清理页可明确选择处理该信号，执行后重新检测。选择 C2PA 证书签名时，填写相同声明并选择 ES256 PEM 证书链和私钥，当前创建入口支持 JPEG、PNG、PDF。

验证与来源链页可选择 Ed25519 信任策略 JSON 和 C2PA 本地根证书 PEM。Ed25519 策略中的公钥字段取自密钥生成报告，示例中的占位值须替换为实际公钥。

```json
{
  "trusted_issuers": [
    {"key_id": "<64位小写十六进制公钥ID>", "ed25519_hex": "<64位小写十六进制公钥>"}
  ],
  "minimum_issuer_signatures": 1
}
```

报告默认隐藏作者、作品声明值及旧指纹解码标识，可在界面明确选择披露。“标记实验室”可选择最多八个阴性对照，执行实际编码、缩放与裁剪实验，呈现各检测器结果。历史 Red Star、Woolim 与 Pyongyang 结构的真实样本和密码学边界见 [格式支持](FORMAT_SUPPORT.md)。

## 便携包运行依赖

Windows CI 包包含官方 qpdf 12.4.2 的 `backends/qpdf.exe`、匹配的 `qpdf30.dll` 以及上游 Apache-2.0 许可证和声明。目标系统需要 Microsoft Visual C++ 2015–2022 x64 runtime。Linux 包使用系统安装的 qpdf 及其共享库，安装发行版的 qpdf 软件包即可启用 PDF 解析和重写。也可以通过绝对路径 `FILEVEIL_QPDF` 显式配置后端。便携包的 `fileveil-package.json` 记录构建时实际执行的 qpdf 版本探测结果及运行依赖。

独立 PDF 验证需要 Poppler 的 `pdfinfo`、`pdftotext` 和 `pdftoppm`。后端缺失时，报告会反映实际可用的验证范围。Linux 桌面需要窗口系统、`libxkbcommon-x11.so.0` 和 OpenGL 驱动。Windows GUI CI 使用固定 SHA-256 校验的 Mesa llvmpipe 软件 OpenGL，并在 framebuffer 证据中记录该运行条件。Mesa DLL 仅用于 CI 验收，发行目录由打包器按明确文件清单生成。

Windows packages include official qpdf 12.4.2 binaries and upstream Apache-2.0 notices. Microsoft Visual C++ 2015–2022 x64 runtime is required. Linux packages use the system qpdf installation and its shared-library dependencies. `fileveil-package.json` records the actual build-time backend probe. Independent PDF checks additionally require Poppler tools. Windows CI framebuffer evidence identifies its Mesa llvmpipe software renderer.

macOS 包的 LSMinimumSystemVersion 按主程序实际 Mach-O 最低版本记录，可选 qpdf 后端另存 Resources/pdf-backend.json。本机 Homebrew 后端要求 macOS 27.0。较早系统可通过 FILEVEIL_QPDF 配置兼容后端，能力查询会实际探测后端能否执行。当前检测到 Apple Development 身份，Developer ID Application 身份数量为 0，正式签名和公证待提供相应凭据。

完整发行包同时包含 GUI/MCP 与 CLI。macOS 的 CLI 位于 Contents/MacOS/fileveil，便携包中与 GUI 并列。使用 --skip-build 打包时，需要先构建同版本的 fileveil-gui 和 fileveil-cli。

净化范围按已扫描格式启用。切换文件会保留各格式的选择，实际任务仅携带当前格式适用的参数，再次验证沿用创建副本时的范围。AI 来源工作区分别显示凭据签名、资产绑定、本地根信任与吊销验证状态。TXT/Markdown 的实验性来源包装限制见格式矩阵。

## 大报告与检测边界

发现列表按每页 100 条显示，搜索和类别筛选覆盖完整列表。处理计划将相同编码与动作的发现合并计数。界面复用报告与搜索缓存，避免每帧复制全部 JSON。

SD1/SDXL 检测器 1.1.0 对精确、非融合和 FMA 数值路径分别评分。分类分歧时显示无法判断，并在证据中保留匹配位数范围。单图统计报告说明源样本类型及 RGB8 转换，统计异常需要对照样本解释。

## 0.5 水印与版权操作

工作区以 Clean、Mark、Verify、Trace、Lab 命名，保留既有黑灰、灰白与半透明外观。Mark / Trace 内的五个操作使用共享 Core，2.0 像素水印需要作品、副本和明确的密钥来源。Verify / Clean / Trace / Lab 的水印密钥需单独选择。系统密钥通过公钥 SHA-256 标识选择，生成动作由用户明确触发。

Trace 可导出检查点、证据包、RFC 3161 查询，也可验证响应文件。交接先由发送方导出签名提案，接收方使用自己的密钥联签，双方密钥可分别保留在各自设备。显式证据包包含作者和作品声明原文，默认结果报告只显示摘要。

Settings 的 MCP 授权分别管理读取目录、输出目录、密钥文件和系统密钥公钥标识。默认授权均为空。新工具 fileveil_mark、fileveil_clean、fileveil_verify_watermark、fileveil_trace、fileveil_watermark_lab、fileveil_evidence 与原九个工具同时提供。高级参数继续使用同一 HeritageRequest JSON。
