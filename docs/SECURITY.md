# 安全说明

## 运行约束

- 仅处理用户指定的文件路径，扫描以只读方式打开输入。
- 运行时不发起网络请求，不执行文档中的宏、脚本或 URL。
- 净化输出先写目标文件系统上的隔离临时目录，通过验证后以防覆盖方式提交。
- 已有输出文件会被保护，失败或取消时清理当前任务的临时输出。
- 操作系统安全来源标记保留至副本，无法保证传播时阻断提交。
- 默认报告屏蔽元数据值与输入绝对路径，避免将正文或凭据写入日志。

## 默认资源预算

| 项目 | 限额 |
| --- | --- |
| 输入文件 | 64 MiB |
| CLI / GUI 可配置输入上限 | 1–512 MiB |
| Office 解压总量 | 128 MiB |
| Office 成员数量 | 10,000 |
| 单个元数据字段 | 1 MiB |
| ZIP 最大压缩比 | 1000 |
| 图像像素数 | 32,000,000 |
| 默认单任务时限 | 120 秒，GUI 可调整至 3600 秒 |
| GUI 文件队列 | 2,000 个文件 |
| 单次目录导入 | 检查最多 10,000 个条目 |
| GUI 保留发现预算 | 累计达到 100,000 条后停止后续任务 |

当前适配器使用受限的内存快照。GUI 队列串行处理文件，后台 worker 承担解析与转换，界面负责调度和显示。默认目录导入覆盖所选目录的直接文件，设置中可启用子目录。会话中的队列和设置在应用退出时结束。

## 输入处理

JPEG/PNG 检查长度和结构。PNG 检查块 CRC。ZIP 不解压至任意文件系统路径，拒绝路径穿越、绝对路径、符号链接和名称冲突，限制解压预算并读取 CRC。XML 拒绝 DTD 和不支持的编码。Office 数字签名、宏和加密输入会阻断可能破坏内容的处理。

APNG 和其他未完成保真验证的复杂变体会报告支持限制。EXIF 方向信息需要保护显示效果，无法保真的情况会阻断净化。未知结构保留并报告。

## 系统属性

Unix 扩展属性按可读取能力进行审计和传播。资源叉等可能携带有效内容的结构会触发保守处理。Windows 流传播能力以本地操作系统接口为准，MOTW 与其他用户可读取流需要保留。系统时间戳会随新文件创建而变化。

## 依赖与发布

构建使用提交的 `Cargo.lock`。CI 配置包括跨平台格式检查、Clippy 和测试。独立安全工作流运行依赖漏洞与许可证检查。项目采用 MPL-2.0。工作流执行和目标平台打包验收结果记录在验证文档，正式签名与公证需要相应发布凭据。

## 后台任务与导出

GUI 与 CLI 共享 Core 数据模型、格式适配器、策略和验证逻辑。GUI 将任务参数经标准输入发送给本应用的隔离 worker，以参数数组启动进程。父进程拥有输出文件系统上的私有暂存目录，验证通过后发布新副本。超时、接受取消或关闭任务句柄时终止并回收 worker，同时清理当前暂存目录。

GUI 的八项 worker 集成测试覆盖正常闭环、失败输入、特殊路径、并发输出冲突、超时、取消与进程回收。macOS 原生界面测试完成七文件队列，其中签名文档和坏 CRC 输入被阻断。

单文件 JSON 导出使用 0.2 报告契约，保留旧版 0.1 的读取兼容。批量导出使用 `batch_export` 封套，其 `reports` 数组保留每个条目的最新报告。导出由用户显式触发，默认屏蔽元数据值与输入绝对路径，并保护已有报告文件。

## 依赖检查记录

### 0.1 CLI 快照

2026-11-11 的 CLI 锁定依赖检查包含 96 个注册表依赖，`cargo audit --file Cargo.lock` 返回 0，记录位于 `work/dependency-audit.txt`。该快照使用 Rust 1.99 构建，CLI 工作区声明最低版本 1.88，1.88 的实际构建未执行。

### 0.2 桌面版

2026-11-12 对桌面版锁文件执行 `cargo audit --file Cargo.lock`，退出码为 0。408 个锁定包中的 402 个为注册表依赖。审计包含三条 Linux 依赖停止维护提示，分别为 `zvariant` 的 RUSTSEC-2026-0370、`zbus_names` 的 RUSTSEC-2026-0371、`zvariant_derive` 的 RUSTSEC-2026-0372。详细记录位于 `work/gui-audit.txt`。

402 个注册表依赖全部声明许可表达式，手动 AND/OR/WITH 表达式检查通过 `.github/deny.toml` 的允许列表。本机尚未运行 `cargo-deny`，自动检查由安全工作流执行。GUI 及字体引入的 Boost、SIL Open Font 和 Ubuntu Font 许可已纳入允许列表和随包文本。

`THIRD_PARTY_NOTICES.txt` 与 `assets/licenses/` 收集 764 份许可和署名文件，包含原始文本、来源及 SHA-256。发布归档缺少许可文本的组件补充上游文件并记录来源。`dispatch 0.2.0` 的发布包和上游提交声明 MIT，补充文件提供原始作者署名、标准 MIT 条款及来源说明。GUI 字体许可文本随应用资源打包。

GUI 声明最低 Rust 版本 1.95，本机主构建使用 Rust 1.99。1.95 的实际构建和 Windows/Linux 原生运行仍待验收。依赖数据库在开发审计时更新，FileVeil 运行时使用离线处理。

0.2 快照之后，项目已采用 MPL-2.0。macOS 应用使用本地 ad-hoc 签名，Apple Developer ID 签名、公证和正式分发验收仍待完成。

## 工程依据

- 图像验证使用独立解码接口，并在解码前检查像素预算。库的内存预算属于尽力限制，应用同时施加文件长度、像素数与进程时限。[ImageReader](https://docs.rs/image/latest/image/struct.ImageReader.html) 与 [Limits](https://docs.rs/image/latest/image/struct.Limits.html)
- Office 包通过 ZIP 读取器逐项读取，应用检查路径、成员数量、解压量与内部关系。[ZipArchive](https://docs.rs/zip/latest/zip/read/struct.ZipArchive.html)
- XML 事件解析与命名空间处理用于审计 OPC 结构。[quick-xml Reader](https://docs.rs/quick-xml/latest/quick_xml/reader/struct.Reader.html)
- 验证通过后采用禁止覆盖的临时文件提交接口。[NamedTempFile](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html#method.persist_noclobber)
- 依赖许可证允许列表采用 cargo-deny 配置格式，私有且未发布的工作区包单独处理。[cargo-deny license configuration](https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html)

## 图片处理与 MCP

显式图片处理使用独立的 Research 配方与发布检查。输出 PNG 经重新解析、解码、配方重算、透明度、色彩记录、原件哈希及可读取属性检查后发布。标准 safe 发布接口仍要求内容一致，图片处理产物由专用接口验证报告与文件摘要。父进程的发布步骤核对 worker 已验证的文件摘要和属性，像素处理在可终止的隔离 worker 中执行。

本地 stdio MCP 服务通过明确的工具参数接收文件路径，采用当前用户权限。写入工具创建新副本并保护已有输出。工具调用沿用隔离工作进程、资源预算、超时及取消语义，连接结束时清理活动任务。协议标准输出只包含 MCP JSON 消息，报告沿用元数据值与绝对输入路径脱敏。

报告 schema 0.2 新增可选 `image_processing` 字段，保存处理配方和像素变化统计。读取兼容旧版 0.1 报告。低位检查可证明指定 RGB 位归零，未知密钥水印检测保持 `not_assessed`。

## 0.3 安全边界

MCP 默认没有任何文件目录授权，能力发现可直接使用。用户在 Settings 或启动参数中配置独立读取根与输出根，默认每连接最多 64 次操作并串行执行。授权拒绝文件系统根、整个用户主目录及其祖先、敏感凭据目录、路径穿越、符号链接和多硬链接输入。根目录、父目录、输入身份和发布目标在操作期间复核。

Unix 使用逐组件 no-follow 打开和继承的只读文件描述符，macOS 目录暂存使用持有 vnode 的 /.vol 引用。Windows 使用无重解析点且禁止删除共享的祖先/文件句柄。worker 通过可信启动通道取得绑定输入，客户路径随后被替换时继续读取原授权对象。输出目录和私有暂存有独立身份绑定，发布采用 no-clobber，禁止原件写入。

父进程拥有 PDF helper 快照和正式输出暂存，worker 接收受限数据。Unix 独立进程组和 Windows Job Object 负责整个进程树的取消、超时与回收。这里的隔离覆盖进程生命周期、授权文件绑定和资源预算，完整通用 OS 沙箱的覆盖另行评估。

PDF 后端只接收已授权内存快照写入的私有文件，执行可信绝对路径配置或随包 qpdf。qpdf 以严格模式解析，限制子进程时间、输出、对象、元数据和流预算。独立 Poppler 是可选验证工具，未随 macOS 包分发。缺少独立检查时报告部分验证。文档脚本与外部资源不会执行。

C2PA 使用固定官方 SDK 的本地密码学验证，禁用远程 manifest、在线 OCSP 和身份 URI 读取。默认保护凭据。Deep 显式移除使用已授权私有副本，报告保留签名丢失后果与范围，不向 SDK 传入客户原始路径。静态检测器只接收只读快照，无联网插件或动态库加载入口。

报告 schema 0.3 增加可选 pdf、provenance 和 advanced 字段，并保留 0.1/0.2 读取兼容。默认省略真实元数据值，合成 LSB 载荷仅输出摘要。Diff Lab 按输入顺序编号，报告文件摘要和统计量。未知 OEM 字段仅输出类别、偏移和结构线索。

许可证清单覆盖新增 C2PA 与解析依赖，原有第三方文本和署名保留。r-efi、self_cell 等可选许可表达式按兼容许可分支满足要求。macOS qpdf 及其库保留各自 Apache/BSD 类声明。Linux 使用系统 qpdf，Windows 包含必要的官方 qpdf 核心文件。对应项目源码 ZIP 与 MPL-2.0 随发行包提供。

### 0.3 RSA 依赖审计例外

原始 `cargo audit --file Cargo.lock` 发现 rsa 0.9.10 的 RUSTSEC-2023-0071，原始失败日志保存在 `work/v03/dependency-audit.log`。该问题涉及 RSA 私钥操作的计时侧信道。当前固定 C2PA SDK 及上游 0.92 均经 c2pa_raw_crypto 使用 rsa 0.9，兼容升级路径尚未提供。

FileVeil 的生产接口使用 Reader 公钥验签和私有副本上的凭据删除。当前生产调用中没有 RSA 签名、解密、私钥载入或 signer 注册。本地信任输入严格接受 X.509 证书，合成签名测试使用临时 ES256 密钥。因此 CI 仅对 RUSTSEC-2023-0071 添加记录性例外，其他漏洞仍阻断检查。该例外依据当前公钥验证调用范围，上游升级至 rsa 0.10 或增加 RSA 私钥功能时须重新处理。漏洞本身仍存在于传递依赖代码中。

其余四条维护状态提示为 proc-macro-error、zvariant、zvariant_derive 和 zbus_names。许可证表达式审计与漏洞审计分别记录结果。[RustSec 公告](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)

### 多轮审计加固

MCP 按打开的目录身份检查 Home 及其祖先，覆盖大小写别名、Windows 长路径和 macOS 物理 Data 卷路径。敏感路径同时复核规范化与实际路径，授权的具体工程目录继续可用。

Unix 文件快照使用 no-follow 与 nonblocking 打开，拒绝非普通文件，避免 FIFO 替换导致同步打开无限等待。原件复核以固定 64 KiB 缓冲比较字节并核对原始文件身份。公开预算的极端数值采用饱和计算，Lab 在读入和解码前验证分组与剩余聚合预算。

GUI 对保留报告施加 128 MiB 估算堆内存阈值，完成任务后暂停后续队列，保留结果以便导出。现有进程组和 Job Object 提供生命周期回收，当前没有操作系统级 RSS 或 CPU 硬配额。媒体扫描仍可能构造整文件副本，应按设备可用内存设置输入上限。
