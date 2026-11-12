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

构建使用提交的 `Cargo.lock`。CI 配置包括跨平台格式检查、Clippy 和测试。独立安全工作流运行依赖漏洞与许可证检查。正式分发前应完成工作流执行、目标平台打包验证及项目许可证选择。

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

项目开源许可证待选择。当前 macOS 应用使用本地 ad-hoc 签名，Apple Developer ID 签名、公证和正式分发验收仍待完成。

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
