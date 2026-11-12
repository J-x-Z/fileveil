<!-- SPDX-License-Identifier: MPL-2.0 -->
# Watermark Benchmark

## 固定数据与复现

`tests/fixtures/benchmark-corpus.json` 固定 200 个不同的 Wikimedia Commons 图片文件，包含逐图 SHA-256、来源页面、原图 URL、作者与来源声明的许可。人工按联系表和源文件标题复核后，内容为 70 张照片、40 张实际软件截图、38 张插画、52 张文字文档。查询分层单独保留，分类结果与查询关键词分别记录。

源文件共 93,245,848 字节，约 88.93 MiB。大图使用明确标识的上游有界缩略图，原图尺寸与实际下载尺寸同时记录。下载文件保持原字节，基准转换为 RGB8、保持宽高比并将最长边限制在 1024，短边至少 512。来源包含相关书页、同一软件和相邻拍摄场景，统计范围为该固定语料。整体人群误报率与独立场景泛化能力仍待更大语料标定。

第三方图片遵循逐项来源许可。仓库保存来源清单与结果，图片留在忽略的 `work/` 目录。MPL-2.0 覆盖项目自有代码。源文件改变时 SHA-256 复核会停止重放。

```sh
python3 tools/benchmark-fetch.py --replay tests/fixtures/benchmark-corpus.json
CARGO_INCREMENTAL=0 cargo build --locked --release -p fileveil-engine --example benchmark_engine
python3 tools/benchmark-watermarks.py --protocol v1 --profile full --limit 200
python3 tests/support/benchmark_metrics_test.py
```

本次环境使用 NumPy 2.2.6、Pillow 12.0.0、OpenCV 4.12.0。AVIF 与 WebP 由真实编解码器执行，再以解码后的像素输入 Rust 信号算法。格式入口的能力矩阵独立于该像素算法基准。

## 操作和指标范围

每图执行 40 项固定操作，覆盖 JPEG 10–90/95、PNG、WebP 30/70/lossless、AVIF 35/70、50/75/150% 缩放、50/75% 中心与偏移裁剪、90/180/270°及 5/15°旋转、模糊、固定随机种子噪声、亮度/对比度/饱和度、连续编辑和组合处理。`screen_resample` 是明确标识的截图式重采样模拟。真实软件截图来自语料中的截图组。`metadata_strip` 是像素保持控制，文件系统和 Core 元数据操作另有正常入口集成测试。

Rust runner 使用 JSONL 长生命周期进程，每次仅保留当前图像。攻击中间文件位于自动回收的临时目录。结果保留为 JSONL、JSON 和 CSV，支持明确的 `--resume`。首次声明结果绑定语料、执行文件、算法与测量范围；公开测试密钥只用于开发基准。

检测成功要求协议帧有效且恢复正确作品摘要，2.0 同时比较发行副本摘要。阴性、错误密钥和不同作品/副本编号分别统计。0.4 的公开协议将错误密钥场景记录为不适用。失败嵌入保留在端到端分母中。

PSNR 与 SSIM 基于 RGB8，SSIM 使用 11×11、sigma 1.5 高斯窗口和有效内部区域。几何攻击对参考图应用已知相同几何变换。0.4 BER 通过独立系数观测计算，成功帧使用检测器选择的几何，失败帧使用明确标识的 512 名义网格。2.0 的已知载荷诊断比较最佳导频候选和 441 位编码帧，候选选择仅依赖导频或有效 MAC。纠错重构差异率另行记录。

CPU 为 Rust 进程 `getrusage` 增量，写操作包含 PNG 输出编码。RSS 为该协议 worker 的进程生命周期高水位。整个脚本耗时还包含真实重编码和质量计算，同机并发负载会影响墙钟。性能比较优先采用同主机 CPU 记录。

## 0.4 实测基线

固定算法源为 `400fbe5` 的 `robust.rs`，SHA-256 `56abbb63267e60df1ed949427aac8be4a0a3457a59b49f3b56a63c098ae38c2c`，强度 32。200 张图片完成 8800 条记录，其中 8000 条为 40 项正控操作。正确恢复 6219/8000，约 77.7375%。

| 操作 | 正确恢复 |
| --- | --- |
| 原图、PNG、WebP lossless | 各 200/200 |
| JPEG 10 / 20 / 30 / 70 / 95 | 110 / 188 / 196 / 199 / 200 |
| WebP 30 / 70 | 147 / 195 |
| AVIF 35 / 70 | 131 / 198 |
| 中心 75% / 偏移 75% / 中心 50% 裁剪 | 195 / 0 / 150 |
| 90° / 180° / 270° / 5° / 15° 旋转 | 各 0/200 |
| 模糊 sigma 2 / 亮度调整 / 连续编辑 | 162 / 171 / 197 |
| 旋转与缩放及 JPEG 组合 | 0/200 |

嵌入成功 200/200，阴性检出 0/200。定向清理后完整帧检出 0/200，其中严格 `not_detected` 为 130/200，`indeterminate` 为 70/200。清理后的状态分布与完整帧破坏率分别记录。

嵌入平均 PSNR 为 36.7855 dB，SSIM 为 0.928953。Rust 累计 CPU 为 98.4743 s，协议 worker 峰值 RSS 为 102.375 MiB。整个脚本耗时 901.3 s。完整逐操作数值保存在 `tests/fixtures/benchmark/v1-baseline-summary.json` 和 CSV，原始 8800 条记录保存在 `work/v05-benchmark/results/v1-s32-full-200.jsonl`。
