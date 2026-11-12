# 格式支持

此矩阵适用于 0.4 GUI、CLI 与本地 MCP。报告使用 schema 0.4，并可读取 0.1–0.3 报告。运行时后端可用性以 `fileveil capabilities --json` 为准。

| 格式 | 扫描 | Safe | Deep | 验证及限制 |
| --- | --- | --- | --- | --- |
| JPEG | EXIF/XMP/IPTC/COM、ICC、APP、尾部、C2PA | 可识别元数据 | 同 Safe，可选文件系统属性 | 编码结构与独立解码像素对照，ICC/Adobe/未知段保留，复杂方向与来源凭据阻断 |
| PNG | 块边界、CRC、文本、EXIF、ICC、C2PA | 可识别元数据 | 同 Safe，可选文件系统属性 | 独立像素对照，APNG 与来源凭据阻断 |
| DOCX | 属性、修订、批注、隐藏文本、部件、关系 | 已知属性与 ZIP 元数据 | 显式批注、受支持的文本与表格行修订、旧表格/编号历史、w14 冲突修订、直接隐藏文本、自定义 XML、受支持嵌入对象、外部超链接、内部编辑标识 | OPC/CRC、未选部件字节对照、独立 XML 解析，复杂修订与语义依赖阻断 |
| XLSX | 属性、批注、隐藏表、公式、外部关系 | 已知属性与 ZIP 元数据 | 可选批注、自定义 XML、受支持嵌入结构、无依赖隐藏表 | 保留普通内容，公式/共享字符串/图表等依赖阻断隐藏表删除 |
| PPTX | 属性、批注、媒体、关系 | 已知属性与 ZIP 元数据 | 可选旧版/现代批注与作者、自定义 XML、受支持嵌入结构 | 关系与显式 commentRel 同步清理，未选内容保留，复杂内容关系阻断 |
| TXT/Markdown | UTF-8、BOM、控制符、隐藏标记、标准来源凭据 | 显式字符选项，来源凭据保护 | 同 Safe，可明确移除受支持凭据包装 | 对照所选转换，保留 ZWJ/ZWNJ 和合法双向文本，报告部分验证 |
| HTML | 文本、来源字段、注释 | 显式 meta/注释/字符选项 | 同 Safe | WHATWG tokenizer 源范围清理，保留 script/style/textarea 与语义字段，复杂上下文阻断 |
| PDF | Info/XMP、自定义字典、附件、JS、动作、历史、签名、C2PA 与隐藏结构线索 | qpdf 完整非增量重写，来源凭据保护 | 显式附件、JS、注释和可移除来源凭据范围 | 对象图、旧 xref 检查，独立 Poppler 页数/文本/受限分辨率渲染，签名或加密保护 |
| HEIC/HEIF、AVIF | box/item/EXIF/XMP、设备、时间、GPS、未知字段与偏移 | 清理标准 EXIF/XMP、显示名称，偏移保持的容器重写 | 同 Safe，可选文件系统属性 | 保留编码图像、色彩、方向、item 关联；共享/受保护 extent 和来源凭据阻断，未知私有字段报告残留 |
| MP4、MOV | box、QuickTime 来源、设备、位置、时间、软件和 UUID | 清理可识别标签、设备与时间字段，重写容器 | 同 Safe，可选文件系统属性 | 保留编码音视频、配置、采样表和时序；关联媒体 ID 及技术字段保留，未知厂商字段报告残留 |
| WAV、FLAC | 标签与容器审计；WAV C2PA 离线验签 | 标准隐私标签清理，凭据结构保护 | 同 Safe，可选文件系统属性 | 保留音频负载字节与技术声道/增益标签；WAV C2PA 块阻断改写，FLAC 私有 C2PA 类应用标识保守保护，运行时未解码信号 |
| MP3 | 有限 ID3 与帧头审计 | 不可用 | 不可用 | 音频重写及信号水印未评估 |
| 普通 ZIP 及未知二进制 | 能力报告或安全拒绝 | 不可用 | 不可用 | 普通 ZIP 保持独立于 Office 判型 |

Safe 默认保护内容和来源凭据。Deep 的每个内容变更项独立选择，使用范围验证并报告部分验证。Office 宏、签名、加密、复杂关系和不支持的修订结构阻断处理。Microsoft Office 真实应用兼容性仍需目标环境验收。

PDF 后端使用 qpdf JSON v2 和完整重写，舍弃旧增量版本与不再引用的对象。压缩流、未知私有结构、附件和未解析含义继续作为残留线索报告。独立 Poppler 工具全部存在且页数、文本、逐页渲染都通过时，Safe 可以报告范围内验证通过。工具缺失、超预算或主动选择内容损失会报告部分验证。PDF 数字签名的存在可审计，其密码学信任状态保持未评估并默认阻断改写。成功扫描的结果单独标明 scan_status=complete，safe_rewrite_allowed 与 rewrite_restrictions 记录改写约束，整体扫描可为部分验证。

## 来源与水印

官方 C2PA SDK 0.91.11 在 PNG/JPEG 合成签名样本上验证 COSE 签名、资产绑定和显式本地根信任，分别报告无效、无法验证与未评估。默认关闭远程 manifest、网络吊销与身份 URI 访问。HEIC、AVIF、MP4、MOV 的真实编码合成媒体已嵌入公开签名，完成离线 COSE 验签、BMFF 哈希绑定、本地根信任及声明和媒体载荷篡改回归。默认签名媒体继续保护。无签名媒体支持上述范围内的容器重写，原件只读。macOS 独立 ImageIO/AVAssetReader 回归比较解码像素、PCM、视频帧、变换与时序，运行时报告将解码验证标记为未评估。PDF、TXT、Markdown 与 WAV 也有公开合成签名样本，分别验证签名、绑定及显式本地根。CAWG 身份断言和私有文本统计水印检测尚未提供。

TXT/Markdown 使用固定版本 SDK 的实验性 A.8/A.9 功能。A.8 文本保持原始 Unicode 字节，非 NFC 纯文本的资产绑定标为无法验证。A.9 Markdown 按原始字节验证绑定。A.9 移除仅支持首物理行中完整、专用的凭据注释包装，其他上下文、损坏或多个包装保留并报告阻断。默认保护凭据，Deep 明确选择移除后核对可见文本字节及凭据结构。PDF 的 C2PA 凭据与传统 PDF 数字签名分别报告，传统签名继续默认保护。

WAV 已用独立公开合成签名样本验证 COSE 签名、资产绑定、本地根信任及音频字节篡改。标准 `C2PA` RIFF 块默认保护，重复块报告无法验证。音频凭据移除未提供。FLAC 的标准 C2PA 路径采用前置 ID3v2 GEOB，当前文件格式适配器拒绝此包装的改写。原生 FLAC APPLICATION 块中的 `c2pa`/`C2PA` 标识仅作私有候选保护，其布局和真实性未评估。[C2PA 2.4 音频嵌入规范](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_embedding_manifests_into_id3)

静态只读检测器契约声明格式、样本数量、密钥、网络、方法版本、证据类型、误报/漏报限制和复验能力。synthetic_lsb_v1 使用公开 RGB LSB 包及 SHA-256 校验。Stable Diffusion 1 和 SDXL 适配器兼容上游 U 通道 Haar/dwtDct 路径，分别比对 136 位和 48 位公开消息。正控含 NASA 自然照片上的独立上游嵌入 PNG 和 JPEG 4:4:4，反控含原照片、未知消息与普通 JPEG 4:2:0 重编码。检测结果包含方法、匹配位数、阈值与公开消息摘要，公开消息不提供密码学身份认证。未知方案保持未评估。

Research 的 Experimental Signal Processing 提供 RGB 低 1–3 位清理和固定缩放/模糊/JPEG 回译，输出 PNG。验证包括配方、像素误差、Alpha/ICC、安全标记及各公开检测器的前后结果。整体报告保持部分验证。

Diff Lab 接受 2–8 张显式图像，提供像素差分、RGB 直方图、低位分布、信息熵、固定采样 DCT/DFT、原分辨率块 DCT/Haar、LSB χ²/相邻相关、JPEG 量化/采样结构、低位/残差/差分预览和配对残差 NCC。参考组支持留一法对照，重复相同输入从参考中排除。实验需要干净、编码和传感器噪声对照，统计异常仅构成研究线索。

## Heritage 来源记录

现代 Ed25519 来源记录支持 JPEG APP15、PNG 私有附属块、PDF 注释载体及 DOCX/XLSX/PPTX 的 ZIP 注释。Mark、Detect、Verify、Clean 使用共享核心，默认结构载体可逆，清理后核对保留内容与原件哈希。来源链支持创建、修改、发行和持有人转移，首个签名密钥对应本条记录的持有人。发行信任采用本地 Ed25519 公钥 JSON，C2PA 信任采用独立的 X.509 PEM 根证书。

C2PA 创建的正常 GUI、CLI 与 MCP 入口支持 JPEG、PNG、PDF，使用显式提供的 ES256 证书链与私钥。离线签名验证、资产绑定和本地信任分别报告，可信时间戳及在线吊销状态保持各自范围。

可选 JPEG/PNG 像素标记使用 FileVeil 自主扩展的公开 DCT 协议，会改变像素并重编码 JPEG。对应清理有处理后复检。小于 256×256 的图像跳过该信号步骤，结构签名仍可验证。公开作品引用消息可以复制，身份和发行信任由签名验证单独评估。

Red Star 检测和清理已有真实 JPEG/DOCX 样本对照，支持两种公开 DES 密钥配置。Woolim SELFSIGN 仅确认公开结构，RSA 与身份密文解密保持未评估。Pyongyang NATISIGN 使用哈希匹配原库的静态 ABI，320B 结构须通过 schema、基础长度、扩展名和已解析编码内容终点四项检查后才允许显式清理，并报告部分验证。其他长度与旧 272B 假设受到保护。真实设备签名样本和跨设备 ABI 兼容性待验证，细节见 [历史格式研究](LEGACY_RESEARCH.md)。

## 平台属性与工作流

可选移除 macOS 下载来源及下载日期、最近使用时间属性、Finder 标签、Unix user.* 属性和 NTFS 私有流。Quarantine、Mark-of-the-Web、未知受保护属性默认保留，资源叉阻断重写。修改时间与创建时间采用独立选项。macOS/Windows 可显式将新副本创建时间规范化至 2000-01-01 UTC 并在发布前复验，Linux 对此选项报告不支持并停止输出。访问时间、文件系统变更时间、日志、快照和备份历史有独立范围限制。

GUI 工作区覆盖文件、Heritage、Deep、图片、Diff Lab、AI Provenance 与批量验证。语言、MCP 授权与资源预算集中在设置，中性黑灰和灰白主题保持一致。实际平台运行状态见 [验证记录](VALIDATION.md)。

## 官方检测接口核对

2026-11-12 核对 OpenAI 官方文档，图片和音频存在 Content Provenance API，检测范围包括相应 C2PA 或 SynthID 信号。接口需要上传所选文件，文本检测需要组织申请审批。本地版本仅记录接口能力与授权需求，网络执行保持关闭。当前 API 文档未确认 textGrain 这一名称，因此能力输出使用 OpenAI 文本检测接口描述。[OpenAI 官方文档](https://developers.openai.com/api/docs/guides/content-provenance)

Anthropic 官方说明 Claude 文本水印采用 SynthID-Text 方法族，检测 API 处于受限私有预览，适用资格和授权由服务方决定。该方案通过词选择产生信号，零宽字符清理具有独立适用范围。本地版本未配置该检测后端。[Anthropic 官方说明](https://www.anthropic.com/news/claude-text-watermark)

外部接口不会因普通本地扫描自动启用。未来实际接入需要逐次明确内容上传范围，真实 API 授权和端到端结果验收仍待提供相应条件。
