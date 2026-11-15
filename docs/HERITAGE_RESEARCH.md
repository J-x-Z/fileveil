# 文件标记机制的公开证据与技术映射

本记录核对公开研究、作者提供的样本目录与 FileVeil 原创 DCT 协议。读取日期为 2026-11-12。原始二进制与设备系统未在本次研究中执行。

## Red Star OS

Florian Grunow 的 2015 年实验观察到 DOCX 在接入系统后即发生字节变化，示例标记位于 offset 80，长度为 32 字节并带有 `EOF`。该长度与位置只适用于文中的具体 DOCX 示例。文中关于音频滤波及部分密码函数的描述包含初步推测。[作者原始实验](https://insinuator.net/2015/07/redstar-os-watermarking/)

后续 Niklaus Schiess 的技术论文明确描述 `scnprc` 启动 `opprc`，后者按文件类型写入标记，JPEG 在结束标志后附加记录。记录包含经过硬编码 DES 密钥处理的硬盘序列信息，可以随转移累积。`rtscan.ko` 通过 `/dev/res` 保护相关文件和进程。论文同时指出记录可伪造，列表首项也未必对应最初创作者。[原始技术论文，第 2—4 页](https://mirror.adversec.com/dprk/docs/governmental_control_of_digital_media_distribution_in_north_korea-nschiess.pdf)

作者的公开仓库提供 `preview_bottle_original.jpg`、`preview_bottle_firstuser.jpg`、`preview_bottle_seconduser.jpg` 和 `love.docx`。目录记录的三个 JPEG 长度分别为 28,616、28,647、28,671 字节，说明不能将 DOCX 示例的 32 字节长度直接推广到所有媒体记录。仓库还提供研究脚本与 32C3 幻灯片。[作者样本目录](https://github.com/takeshixx/redstar-tools/tree/master/watermarked) [32C3 原始资料入口](https://dprktech.adversec.com/post/lifting-the-fog-on-red-star-os/)

## Woolim 与后继手机研究

Woolim 的 `NATISIGN` 用于机构批准的内容，`SELFSIGN` 用于设备生成的内容。作者公布的结构包含 256 字节 RSA 签名、520 字节加密身份数据、长度及填充字段和 8 字节后缀，总长 792 字节。2016 年博客将身份字段描述为 IMEI 与 Android ID，后续论文描述为 IMSI 与 IMEI，解读时需保留具体样本和版本范围。[作者原始分析](https://insinuator.net/2016/12/woolim-lifting-the-fog-on-dprks-latest-tablet-pc/) [原始论文，第 3 页](https://mirror.adversec.com/dprk/docs/governmental_control_of_digital_media_distribution_in_north_korea-nschiess.pdf)

Project Reveal 的代码章节进一步描述文件尾部签名、IMEI 与部分设备的 IMSI、多设备身份列表以及相同签名库的跨设备比较。报告列出已获得 dump 的设备，并明确 Pyongyang 2425 缺少完整 dump，未完成同等深度分析。主报告对签名工具的跨代兼容性有实际观察。[Project Reveal 原始代码章节，第 6—13 页](https://www.nktechlab.org/wp-content/uploads/2025/05/2022-Reveal-Android-Code-Section-ENG.pdf) [主报告，第 17—19 页](https://www.nktechlab.org/wp-content/uploads/2025/05/2022-Reveal-ENG.pdf)

Digital Trenches 将文件标记、数字签名与终端检查置于信息控制背景，讨论设备列表可能揭示的传播关系，同时说明缺乏全面硬盘序列数据库的证据。这类传播关系需要结合实际样本和设备记录验证。[作者报告，第 35—36 页](https://www.hrnk.org/wp-content/uploads/2020/08/Williams_Digital_Trenches_Web_FINAL.pdf)

## FileVeil 的技术映射

- 历史证据支持研究结构化标记、可累积记录、设备字段和签名校验。签名、结构识别及真实身份归因分别需要对应证据。
- 现代作品引用使用用户提供引用的 SHA-256 前 128 位，避免自动填入设备身份。公开摘要可被复制、枚举或伪造，匹配结果不能认证作者、设备或所有权。
- `fileveil_heritage_dct_v1` 为独立实现的像素域扩展。当前公开研究未提供足以复现 Red Star 像素滤波机制的算法规格，FileVeil 的 DCT 方法按自身公开协议验证。

## 原创 DCT 协议与实测范围

32 字节帧由 8 字节 `FVHDCT1\n`、16 字节作品摘要、4 字节大端 IEEE CRC32 和 `[1,0,0,0]` 版本字段组成。按 MSB 优先写入重复的 16 × 16 个图像块，每块为 8 × 8 像素。亮度采用 `0.299R + 0.587G + 0.114B`，正交 DCT 的 `(u,v)=(2,3)` 与 `(3,2)` 系数差编码一位。

嵌入在 512 × 512 参考网格计算残差，映射回原尺寸，支持 RGB8 与 RGBA8，Alpha 保持逐样本一致。嵌入要求短边至少 512，强度范围为 16—64。检测接受短边至少 256，通过重复软投票恢复帧，检查 magic、CRC 与版本。协议有效时才返回作品摘要。

检测最多检查六个网格和 17,664 个相位候选。标准网格为 512、448、384、320、256 的正方形，原生网格限制每轴最多 768，原生网格额外搜索每轴八个像素相位。滑动 DCT 采用分离卷积，帧恢复成功即返回。magic 接近而帧校验失败时保留 `indeterminate`。

显式清理会在检测到的网格与像素相位上中和本协议系数差。RGB 量化可能保留精确零附近的旧符号，因此使用与作品无关的 ±4 近零棋盘格保护间隔，再执行全搜索复检。清理会改变像素，其验证范围为本协议具名检测器。

NASA 自然照片回归包括 JPEG 质量 70/90、384/768 缩放、384 区域的对齐及非块对齐裁剪、裁剪后缩放，以及 1024 × 768 非正方形图的 JPEG 85。原图、公开 SD 标记与合成渐变/噪声作为阴性对照。样本覆盖范围内恢复正确摘要，PNG、JPEG 70 和非块对齐裁剪的显式清理后复检未恢复帧。单张照片及其变体不足以估计任意图片的误报率与对各种图像变换的耐受能力。

破坏性变体也保留实际结果。JPEG 10、90 度旋转与非对齐 256 区域裁剪未恢复帧，sigma 2 模糊返回 `indeterminate`，均未返回其他作品的摘要。

独立 Python 实现使用 OpenCV 的完整 DCT/IDCT，验证 Rust 标记、JPEG 70 和非块对齐裁剪，验证 Rust 清理后 PNG/JPEG 不再恢复帧，并反向验证 Python 编码可由 Rust 解码。源代码位于 `tests/support/heritage_robust_oracle.py`，实测记录位于 `work/v04-research/robust-tests.log`、`robust-numeric-tests.log`、`robust-independent.log` 与 `robust-oracle/oracle.json`。

在 macOS arm64 上直接测量 debug CLI worker，512 × 512 阴性自然图完整扫描的 user CPU 为 0.42 s、峰值 RSS 为 25.9 MiB，阳性标记图为 0.06 s、18.2 MiB。两项各测一次，包含 worker 启动、PNG 解码、结构审计和报告序列化。原始输入哈希、二进制及算法源码哈希与测量边界保存在 `work/v04-research/robust-performance.json`。该观察来自未优化 debug 构建。
