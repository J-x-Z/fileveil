<!-- SPDX-License-Identifier: MPL-2.0 -->
# FileVeil

[English](README.md) | [简体中文](README.zh-CN.md)

**清理元数据。标记作品归属。验证来源凭据。测试水印。**

[![CI](https://github.com/J-x-Z/fileveil/actions/workflows/ci.yml/badge.svg)](https://github.com/J-x-Z/fileveil/actions/workflows/ci.yml)
[![许可证 MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue)](LICENSE)
![公开 Alpha](https://img.shields.io/badge/status-public%20alpha-orange)

FileVeil 是一个使用 Rust 编写的**离线优先、跨平台文件隐私与水印工具箱**。它可以检查隐藏元数据、生成经过验证的净化副本、嵌入自己的签名来源记录，并研究图像水印在编辑或清理后的保留情况。

**Windows · macOS · Linux | 原生桌面 GUI · CLI · 本地 MCP**

**English · 简体中文 · 日本語 · 한국어 · Español · Français · Deutsch · Português · Русский**

在 Settings 中选择界面语言。技术报告字段值及未识别的后端消息可能显示为英文。

> **Alpha 提示**　FileVeil 目前处于实验阶段。验证结果仅适用于报告中明确列出的检查范围，其他隐藏水印或识别特征仍可能存在。请保留原始文件，并在分享重要文件前检查处理结果。

## 可以做什么

| 工作流 | 功能 |
| --- | --- |
| **Clean · 净化** | 检查并移除受支持的 EXIF/XMP、文档属性、部分编辑历史、文件系统元数据及已知水印载体。生成新副本并验证修改结果。 |
| **Mark · 标记** | 添加具有版本标识的图像水印，可选择隐形嵌入，并添加签名文件记录、作品 ID 和副本 ID。 |
| **Verify · 验证** | 检查受支持的水印信号、Ed25519 签名、内容绑定、C2PA 凭据及可独立验证的证据。 |
| **Trace · 追踪** | 建立带签名的版本和交接记录，支持密钥轮换、双方共同签署的交接及外部检查点。 |
| **Lab · 实验室** | 对比图像、可视化信号差异，并测试水印对 JPEG/AVIF/WebP 重压缩、裁剪、旋转、缩放、噪声及其他变换的耐受能力。 |

文件默认在本地处理，无需账户，也不收集遥测。FileVeil 保留原始输入，将净化或标记后的副本写入新路径。GUI、CLI 和 MCP 共用 Rust 处理核心。

### 文件支持概览

- **图片**　JPEG、PNG，以及 HEIC/HEIF、AVIF 的元数据重写。像素处理可使用兼容的可选本地编解码器。
- **文档**　PDF（qpdf 后端）、DOCX、XLSX、PPTX，以及部分 TXT、Markdown 和 HTML 清理。
- **媒体**　MP4/MOV 容器元数据、WAV/FLAC 元数据，以及有限的 MP3 只读审计。
- **来源凭据**　在受支持格式上离线验证 C2PA，并使用用户提供的签名凭据为 JPEG、PNG 和 PDF 创建 C2PA 凭据。
- **水印**　FileVeil v1/v2、受支持的公开 Stable Diffusion 1/SDXL 水印特征，以及部分历史文件标记。

各格式的检查与清理能力存在差异，详见[逐格式支持矩阵](docs/FORMAT_SUPPORT.md)。

## 下载与运行

从 [v0.5.0-alpha.3 Alpha 发布页](https://github.com/J-x-Z/fileveil/releases/tag/v0.5.0-alpha.3)下载 Windows、macOS 和 Linux 软件包。

- **macOS Apple Silicon** — `.dmg` 支持将应用拖入 Applications 安装，也提供 `.zip`。
- **Windows x64** — `.exe` 安装程序或便携 `.zip`。
- **Linux x64** — `.deb` 软件包或 `.tar.gz`。

macOS 构建使用临时签名（ad-hoc），Gatekeeper 会拒绝该构建。Windows 软件包未签名，可能显示未知发行者提示。目前缺少面向公开分发的正式签名证书。也可以从源码构建。

构建需要 Rust **1.96+** 和 Cargo。PDF 重写使用 **qpdf**，独立的 PDF 显示与文本检查使用可选的 Poppler 工具。部分 HEIC/AVIF 和媒体功能依赖本地安装的编解码器或 FFmpeg。可选后端不可用时，FileVeil 会明确报告能力状态。

```bash
git clone https://github.com/J-x-Z/fileveil.git
cd fileveil
cargo build --locked --release -p fileveil-gui -p fileveil-cli

# 启动桌面应用
./target/release/fileveil-gui

# 查看当前系统上可用的功能
./target/release/fileveil capabilities --json
```

在 Windows 上，请运行 `target\release\` 中对应的 `.exe` 文件。打包方式和桌面工作流详见 [GUI 指南](docs/GUI.md)。

## 快速开始

**扫描并净化文件**

```bash
./target/release/fileveil scan photo.jpg --json
./target/release/fileveil sanitize photo.jpg --profile safe --output photo.clean.jpg --json
./target/release/fileveil verify photo.jpg photo.clean.jpg --json
```

**为图片签名并嵌入水印**

```bash
./target/release/fileveil heritage-keygen --output owner.key --json
./target/release/fileveil mark photo.png --output photo.marked.png \
  --key owner.key --work-id demo-work --copy-id demo-copy \
  --created-at 2026-11-13T00:00:00Z --pixel --json
./target/release/fileveil verify photo.marked.png --watermark-key owner.key --json
./target/release/fileveil clean photo.marked.png --output photo.clean.png \
  --pixel --watermark-key owner.key --json
```

CLI 还提供 `trace`、`lab`、`provenance` 以及证据导出和验证功能。签名验证与水印验证分别检查不同证据。恢复出的作品 ID 本身不足以确立法律意义上的著作权归属。

## Watermark Engine 2.0 实测结果

我们使用来自四类内容的 **200 张真实图片**，对 v0.4 和 v0.5 进行了对比。每张图片执行 **40 项固定操作**，每种配置共进行 8,000 次恢复测试。

| 配置 | 作品与副本 ID 正确恢复率 | 嵌入后图像平均 SSIM |
| --- | ---: | ---: |
| v0.4 | **77.74%** | 0.9290 |
| v0.5 · Quality 12（默认） | **89.09%** | 0.9704 |
| v0.5 · Robust 20 | **95.90%** | 0.9512 |

基准包含无损对照和较困难的图像变换，各操作的表现差异较大。更强的鲁棒性可能增加画质损失和计算耗时。上述数据来自**固定测试集**，其他图片和处理条件仍需单独评估检测与清理效果。详见[完整方法与逐操作数据](docs/WATERMARK_BENCHMARK.md)。

## 隐私、局限与安全

- **默认离线**　无需云账户，不收集遥测，也不会上传选中的文件。
- **保留原件**　处理结果写入新文件，并执行适合相应格式的验证。
- **明确验证范围**　`verified_within_scope`、`partially_verified` 和 `not_assessed` 分别说明范围内验证通过、部分验证和未评估的状态。
- **水印检测覆盖范围**　专有 OEM/AI 密钥水印、完整的视频水印清除、部分受保护文档结构及少见媒体变体仍超出当前能力范围。
- **签名与来源边界**　密码学有效性、文件内容绑定、发行者信任和著作权归属需要分别判断。

详细说明见[安全模型](docs/SECURITY.md)、[威胁模型](docs/THREAT_MODEL.md)和[验证记录](docs/VALIDATION.md)。涉及安全的问题请私下报告，公开 issue 中仅使用可公开的样本与信息。

## 研究与兼容性

FileVeil 结合自主水印研究与公开格式兼容工作，其中包括针对 Red Star OS 及相关设备所使用的历史文件追踪机制的研究。历史格式读取器采用独立 Rust 实现，应用发行包不包含历史二进制样本。详见[研究笔记](docs/LEGACY_RESEARCH.md)与[协议说明](docs/HERITAGE_RESEARCH.md)。

## 参与贡献

欢迎提交可复现的问题报告、兼容性发现、基准数据集、翻译和范围明确的 pull request。请在 [issue](https://github.com/J-x-Z/fileveil/issues) 中提供操作系统、FileVeil 版本、文件格式、预期行为，以及最小化的非敏感样本或经过脱敏的报告。提交 PR 前请确认相关行为。随着 Alpha 版本发展，项目会补充社区贡献指南。

## 许可证

FileVeil 自有源码采用 **[Mozilla Public License 2.0](LICENSE)**。依赖、字体、工具和研究样本保留各自的许可证，详见[第三方声明](THIRD_PARTY_NOTICES.txt)。
