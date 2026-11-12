// SPDX-License-Identifier: MPL-2.0
//! Presentation-only translations. Format rules and report values stay in the shared core.
use fileveil_core::{Action, Confidence, Finding, FindingState, Outcome, RiskLayer};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    #[default]
    Chinese,
    English,
}

pub fn tr(language: Language, english: &str) -> &str {
    if language == Language::English {
        return english;
    }
    match english {
        "MCP permissions" => "MCP 授权",
        "Choose readable folders and folders for new output copies" => {
            "选择可读取的目录，以及可新建净化副本的输出目录"
        }
        "Readable folders" => "可读取目录",
        "Output folders" => "可创建副本的目录",
        "Add readable folder" => "添加可读目录",
        "Add output folder" => "添加输出目录",
        "Operations per MCP connection" => "每个 MCP 连接的操作上限",
        "Update the client configuration and reconnect to apply permission changes" => {
            "修改授权后更新客户端配置并重新连接生效"
        }
        "MCP configuration requires Unicode paths" => "MCP 连接配置需要有效的 Unicode 路径",
        "Could not serialize MCP configuration" => "无法生成 MCP 连接配置",

        "PNG rebuilding intentionally changes image samples and omits original privacy metadata and non-color ancillary records." => {
            "PNG 重建会按所选参数改变图像样本，并清理原始隐私元数据和非色彩附带记录。"
        }
        "Color profiles, applicable PNG display records, alpha samples and readable platform attributes are preserved." => {
            "保留色彩配置、适用的 PNG 显示记录、透明度和可读取的平台属性。"
        }
        "Unknown content and statistical watermark detectors were not run. Low-bit checks establish sample-bit clearing only." => {
            "未知内容水印与统计水印检测未运行。低位检查验证指定图像样本位的清理结果。"
        }
        "Local MCP server" => "本地 MCP 服务",
        "Use stdio to call FileVeil from an MCP client" => {
            "通过 stdio 接入 MCP 客户端并调用 FileVeil"
        }
        "Copy MCP configuration" => "复制 MCP 连接配置",
        "MCP configuration copied" => "MCP 连接配置已复制",
        "Could not locate MCP executable" => "无法定位 MCP 可执行文件",
        "Image watermark processing" => "图片水印处理",
        "Low-bit clearing" => "低位清理",
        "Signal processing" => "信号处理",
        "Processing parameters verified" => "处理参数校验通过",
        "Changed samples" => "改动通道数",
        "Maximum change" => "最大变化",
        "Unknown keyed-watermark detection remains unassessed" => "未知密钥水印检测未运行",
        "Not verified yet" => "等待副本验证",
        "Report memory budget reached. Export reports and clear completed items to continue" => {
            "已达到报告内存预算，导出报告并清除已完成项后可继续处理队列"
        }
        "No safe cleanup plan is available" => "当前文件没有可执行的安全净化计划",
        "Ready to clean" => "可净化",
        "Scan complete" => "已扫描",
        "No new regular files were added" => "所选路径没有可添加的新文件",
        "Some symbolic links, unreadable paths or special files were skipped" => {
            "已跳过符号链接、无法读取的路径或特殊文件"
        }
        "Import limit reached. The queue supports 2000 files and 10000 inspected entries" => {
            "已达到导入限额，队列最多 2000 个文件，单次检查最多 10000 个目录条目"
        }
        "No supported fields to remove" => "当前支持范围内没有待移除字段",
        "Scan a file to see its plan" => "扫描文件后显示处理计划",
        "Files are processed locally. Reports redact metadata values." => {
            "文件在本机处理，导出报告隐藏元数据值。"
        }
        "PDF rewriting and credential signature verification are unavailable." => {
            "PDF 改写与来源凭据验签尚待后续支持。"
        }
        "File privacy, before you share" => "分享之前，检查文件隐私",
        "Offline file privacy" => "离线文件隐私",
        "Offline privacy audit" => "离线隐私审计",
        "Offline" => "离线运行",
        "No uploads" => "本地处理",
        "Files" => "文件",
        "File queue" => "文件队列",
        "Queue" => "队列",
        "Add files" => "添加文件",
        "Add folder" => "添加文件夹",
        "Open files" => "打开文件",
        "Open folder" => "打开文件夹",
        "Scan" => "扫描",
        "Scan selected" => "扫描所选",
        "Scan queue" => "扫描队列",
        "Scan all" => "扫描全部",
        "Scan files" => "扫描文件",
        "Scanning" => "正在扫描",
        "Sanitize" => "净化",
        "Sanitizing" => "正在净化",
        "Verify" => "验证",
        "Verifying" => "正在验证",
        "Verify copy" => "验证副本",
        "Compare copy" => "对照副本",
        "Choose a copy to verify" => "选择需要验证的副本",
        "Save clean copy" => "保存净化副本",
        "Save sanitized copy" => "保存净化副本",
        "Save clean copies" => "保存净化副本",
        "Save all copies" => "保存全部副本",
        "Sanitize selected" => "净化所选",
        "Sanitize queue" => "净化队列",
        "Clean copies" => "净化副本",
        "Output folder" => "输出文件夹",
        "Choose output folder" => "选择输出文件夹",
        "Choose folder" => "选择文件夹",
        "Next to originals" => "原文件所在文件夹",
        "Same as original" => "原文件所在文件夹",
        "Export report" => "导出报告",
        "Export reports" => "导出报告",
        "Export all reports" => "导出全部报告",
        "Export JSON report" => "导出 JSON 报告",
        "Redacted JSON report" => "脱敏 JSON 报告",
        "JSON report" => "JSON 报告",
        "Report exported" => "报告已导出",
        "Save report" => "保存报告",
        "Copy report" => "复制报告",
        "Copy JSON" => "复制 JSON",
        "View JSON" => "查看 JSON",
        "Copied" => "已复制",
        "Reveal in folder" => "在文件夹中显示",
        "Show in folder" => "在文件夹中显示",
        "Open output folder" => "打开输出文件夹",
        "Remove" => "移除",
        "Remove selected" => "移除所选",
        "Clear" => "清空",
        "Clear queue" => "清空队列",
        "Clear completed" => "清除已完成项",
        "Cancel" => "取消",
        "Cancel task" => "取消任务",
        "Cancel remaining" => "取消剩余任务",
        "Stop" => "停止",
        "Retry" => "重试",
        "Close" => "关闭",
        "Done" => "完成",
        "Dismiss" => "关闭提示",
        "Settings" => "设置",
        "Appearance" => "外观",
        "Language" => "语言",
        "English" => "English",
        "Chinese" => "中文",
        "Light" => "浅色",
        "Dark" => "深色",
        "High contrast" => "高对比",
        "Theme" => "主题",
        "System" => "跟随系统",
        "Resource limits" => "资源上限",
        "File size limit" => "文件大小上限",
        "File size limit (MiB)" => "文件大小上限（MiB）",
        "Maximum file size" => "单文件大小上限",
        "Task timeout" => "任务时限",
        "Timeout" => "超时",
        "Timeout (seconds)" => "任务时限（秒）",
        "seconds" => "秒",
        "MiB" => "MiB",
        "Safe profile" => "保守策略",
        "Profile" => "策略",
        "Safe" => "保守净化",
        "Ready" => "就绪",
        "Pending" => "等待处理",
        "Queued" => "排队中",
        "Working" => "正在处理",
        "Running" => "处理中",
        "Completed" => "已完成",
        "Cancelled" => "已取消",
        "Timed out" => "已超时",
        "Error" => "错误",
        "Failed" => "失败",
        "Unsupported" => "不支持",
        "Blocked" => "已阻断",
        "Needs review" => "需复核",
        "Ready to scan" => "可扫描",
        "Ready to sanitize" => "可安全净化",
        "Verified" => "已验证",
        "Partially verified" => "部分验证",
        "Verified within scope" => "范围内验证通过",
        "Verification failed" => "验证失败",
        "Details" => "详情",
        "Evidence" => "证据",
        "Findings" => "发现信息",
        "Finding details" => "发现详情",
        "Selected file" => "所选文件",
        "No file selected" => "尚未选择文件",
        "Select a file" => "选择文件",
        "Select a file to inspect its findings" => "选择文件查看发现信息",
        "Drop files here" => "将文件拖放到这里",
        "Choose files to inspect their metadata" => "选择文件，查看其中的元数据",
        "Drop files or add them to begin" => "拖放文件或添加文件以开始",
        "Add files to begin" => "添加文件以开始",
        "Add files to get started" => "添加文件以开始",
        "Supported formats" => "支持的格式",
        "JPEG, PNG, DOCX, XLSX, PPTX" => "JPEG、PNG、DOCX、XLSX、PPTX",
        "Text and HTML are audit-only" => "文本与 HTML 提供只读审计",
        "Run a scan to see findings" => "扫描后查看发现信息",
        "No findings match this filter" => "没有符合筛选条件的项目",
        "No findings match the filter" => "没有符合筛选条件的项目",
        "No findings" => "暂无发现信息",
        "No report yet" => "暂无报告",
        "All" => "全部",
        "All findings" => "全部发现",
        "All categories" => "全部类别",
        "Removable" => "可移除",
        "Retained" => "已保留",
        "Not assessed" => "未评估",
        "Images · PDF · Office · Text · Media" => "图片 · PDF · Office · 文本 · 音视频",
        "Removed" => "已移除",
        "Search" => "搜索",
        "Search findings" => "搜索发现信息",
        "Search queue" => "搜索文件队列",
        "Filter" => "筛选",
        "Category" => "类别",
        "Status" => "状态",
        "Location" => "位置",
        "Confidence" => "置信度",
        "Action" => "动作",
        "Plan" => "处理计划",
        "Cleaning plan" => "净化计划",
        "Sanitization plan" => "净化计划",
        "Review plan" => "查看处理计划",
        "Review before saving" => "保存之前查看处理计划",
        "Known privacy fields" => "已知隐私字段",
        "Preserved data" => "保留的数据",
        "Remaining risks" => "保留项与风险",
        "Warnings" => "提示",
        "Verification" => "验证结果",
        "Comparison" => "前后对照",
        "Before" => "处理前",
        "After" => "处理后",
        "Original" => "原件",
        "Output" => "输出",
        "Output copy" => "输出副本",
        "Integrity" => "完整性",
        "Parseable" => "结构可解析",
        "Decodeable" => "图像可解码",
        "Pixels equal" => "像素一致",
        "Pixels identical" => "像素一致",
        "Content equal" => "保留内容一致",
        "Content preserved" => "保留内容一致",
        "Original unchanged" => "原件哈希一致",
        "Security markers preserved" => "安全来源标记保留",
        "Not checked" => "未检查",
        "Passed" => "通过",
        "Yes" => "是",
        "No" => "否",
        "Input SHA-256" => "输入 SHA-256",
        "Original SHA-256" => "原件 SHA-256",
        "Output SHA-256" => "输出 SHA-256",
        "Source file" => "输入文件",
        "Show full path" => "显示完整路径",
        "Format" => "格式",
        "Size" => "大小",
        "Operation" => "操作",
        "Capabilities" => "支持能力",
        "About" => "关于",
        "Version" => "版本",
        "Metadata values are redacted" => "元数据值已脱敏",
        "Reports omit metadata values and absolute paths" => "报告省略元数据值和绝对路径",
        "Files are processed locally" => "文件在本机处理",
        "The output is verified before saving" => "副本通过验证后保存",
        "Unassessed categories remain outside the verification scope" => {
            "未评估类别仍在验证范围之外"
        }
        "Unknown structures are preserved and reported" => "未知结构会保留并列入报告",
        "Digital signatures and provenance credentials can block rewriting" => {
            "数字签名和来源凭据可能阻断改写"
        }
        "PDF rewriting and C2PA signature validation are unavailable" => {
            "PDF 重写与 C2PA 验签能力待实现"
        }
        "Content and statistical watermark detection are not assessed" => {
            "内容级和统计水印检测未评估"
        }
        "This queue is kept only for this session" => "文件队列仅保留在本次会话中",
        "Coverage is limited to the listed fields. Content watermarks, privileged platform attributes, ACLs and filesystem timestamps are outside verification scope." => {
            "验证范围限于报告列出的字段。内容级水印、特权平台属性、ACL 和文件系统时间戳仍在验证范围之外。"
        }
        "Filename extension disagrees with the parsed file format" => {
            "文件扩展名与解析识别的格式不一致。"
        }
        "One or more supported privacy fields remain in the output" => {
            "输出中仍有受支持的隐私字段。"
        }
        "JPEG provenance container requires a dedicated offline credential verifier before rewriting" => {
            "JPEG 来源凭据需要专用离线验证器，当前阻断改写。"
        }
        "PNG provenance metadata requires a dedicated offline credential verifier before rewriting" => {
            "PNG 来源凭据需要专用离线验证器，当前阻断改写。"
        }
        "PNG provenance container requires a dedicated offline credential verifier before rewriting" => {
            "PNG 来源凭据需要专用离线验证器，当前阻断改写。"
        }
        "XMP orientation metadata requires semantic-preserving rewriting" => {
            "XMP 方向信息需要保留显示语义，当前阻断改写。"
        }
        "Non-default EXIF orientation requires orientation-preserving metadata rewriting" => {
            "EXIF 方向信息需要保留显示方向，当前阻断改写。"
        }
        "PNG text orientation metadata requires semantic-preserving rewriting" => {
            "PNG 文本方向信息需要保留显示语义，当前阻断改写。"
        }
        "APNG frame-preserving verification is unavailable" => {
            "APNG 帧保真验证能力待实现，当前阻断改写。"
        }
        "Unknown ZIP extra fields require an explicitly supported preservation strategy" => {
            "未知 ZIP 附加字段需要受支持的保留策略，当前阻断改写。"
        }
        "Office digital signatures or executable macros require preserving the entire package" => {
            "Office 数字签名或可执行宏需要保护整个文档包，当前阻断改写。"
        }
        "Office signature or macro relationship blocks rewriting" => {
            "Office 签名或宏关系阻断改写。"
        }
        "Batch processing" => "批量处理",
        "Recursive folder import" => "递归导入文件夹",
        "Include subfolders" => "包含子文件夹",
        "Skip symbolic links" => "跳过符号链接",
        "Select all" => "全选",
        "Deselect all" => "取消全选",
        "Selected" => "已选",
        "Open" => "打开",
        "Save" => "保存",
        "Reset" => "重置",
        "Reset limits" => "重置上限",
        "Loading" => "正在载入",
        "Continue" => "继续",
        "A task is running" => "任务正在运行",
        "Finish or cancel the current task before continuing" => "完成或取消当前任务后继续",
        _ => english,
    }
}

pub fn outcome(language: Language, value: Outcome) -> &'static str {
    let english = match value {
        Outcome::VerifiedWithinScope => "Verified within scope",
        Outcome::PartiallyVerified => "Partially verified",
        Outcome::Failed => "Verification failed",
        Outcome::Unsupported => "Unsupported",
        Outcome::Blocked => "Blocked",
        Outcome::NotAssessed => "Not assessed",
    };
    tr(language, english)
}

pub fn action(language: Language, value: Action) -> &'static str {
    let english = match value {
        Action::Preserve => "Preserve",
        Action::Remove => "Remove field",
        Action::Normalize => "Normalize",
        Action::Rebuild => "Rebuild",
        Action::AskUser => "Review retained data",
        Action::Unsupported => "Unavailable",
    };
    if language == Language::English {
        return english;
    }
    match value {
        Action::Preserve => "保留",
        Action::Remove => "移除字段",
        Action::Normalize => "规范化",
        Action::Rebuild => "重建",
        Action::AskUser => "复核保留项",
        Action::Unsupported => "能力不可用",
    }
}

pub fn layer(language: Language, value: RiskLayer) -> &'static str {
    if language == Language::English {
        return match value {
            RiskLayer::EmbeddedMetadata => "Embedded metadata",
            RiskLayer::ContainerStructure => "Container structure",
            RiskLayer::Filesystem => "Filesystem attributes",
            RiskLayer::ProvenanceCredential => "Provenance credentials",
            RiskLayer::ContentWatermark => "Content watermarks",
            RiskLayer::StatisticalWatermark => "Statistical watermarks",
        };
    }
    match value {
        RiskLayer::EmbeddedMetadata => "嵌入元数据",
        RiskLayer::ContainerStructure => "容器结构",
        RiskLayer::Filesystem => "文件系统属性",
        RiskLayer::ProvenanceCredential => "真实性与来源凭据",
        RiskLayer::ContentWatermark => "内容级水印",
        RiskLayer::StatisticalWatermark => "统计水印",
    }
}

pub fn state(language: Language, value: FindingState) -> &'static str {
    if language == Language::English {
        return match value {
            FindingState::Present => "Present",
            FindingState::RemovedVerified => "Removal verified",
            FindingState::AppliedVerified => "Processing verified",
            FindingState::Remains => "Retained",
            FindingState::NotAssessed => "Not assessed",
            FindingState::Blocked => "Blocked",
        };
    }
    match value {
        FindingState::Present => "已检出",
        FindingState::RemovedVerified => "移除已验证",
        FindingState::AppliedVerified => "处理已验证",
        FindingState::Remains => "已保留",
        FindingState::NotAssessed => "未评估",
        FindingState::Blocked => "已阻断",
    }
}

pub fn confidence(language: Language, value: Confidence) -> &'static str {
    if language == Language::English {
        return match value {
            Confidence::Verified => "Verified",
            Confidence::StrongEvidence => "Strong evidence",
            Confidence::Heuristic => "Heuristic",
            Confidence::Unknown => "Unknown",
        };
    }
    match value {
        Confidence::Verified => "已验证",
        Confidence::StrongEvidence => "较强证据",
        Confidence::Heuristic => "启发式线索",
        Confidence::Unknown => "未知",
    }
}

pub fn finding_title(language: Language, finding: &Finding) -> String {
    let (chinese, english) = match finding.code.as_str() {
        "image.processing.executed" => ("图像处理已执行", "Image processing applied"),
        "jpeg.exif" | "png.exif" => ("EXIF 元数据", "EXIF metadata"),
        "jpeg.exif.gps" | "png.exif.gps" => ("GPS 位置字段", "GPS location fields"),
        "jpeg.exif.identity" | "png.exif.identity" => {
            ("设备与身份字段", "Device and identity fields")
        }
        "jpeg.xmp" => ("XMP 元数据", "XMP metadata"),
        "jpeg.iptc" => ("IPTC 元数据", "IPTC metadata"),
        "jpeg.comment" => ("JPEG 注释", "JPEG comment"),
        "jpeg.icc" | "png.icc" => ("ICC 色彩配置", "ICC color profile"),
        "jpeg.photoshop_resources" => ("Photoshop 附加资源", "Photoshop resources"),
        "jpeg.thumbnail" => ("JPEG 缩略图", "JPEG thumbnail"),
        "jpeg.unknown_app" => ("未知 JPEG 应用段", "Unknown JPEG application segment"),
        "jpeg.trailing_data" | "png.trailing_data" => ("文件尾部附加数据", "Trailing data"),
        "jpeg.provenance" | "png.provenance" => ("来源凭据结构", "Provenance container"),
        "png.text" => ("PNG 文本元数据", "PNG text metadata"),
        "png.ztxt" => ("PNG 压缩文本", "PNG compressed text"),
        "png.itxt" => ("PNG 国际文本", "PNG international text"),
        "png.time" => ("PNG 修改时间", "PNG modification time"),
        "png.animation" => ("APNG 动画结构", "APNG animation"),
        "png.unknown_ancillary" => ("未知 PNG 附加块", "Unknown PNG ancillary chunk"),
        "ooxml.zip_metadata" => ("ZIP 时间与附加元数据", "ZIP timestamps and metadata"),
        "ooxml.signature_or_macro" => ("Office 签名或宏", "Office signature or macro"),
        "ooxml.external_relationship" => ("外部关系与超链接", "External links and relationships"),
        "ooxml.comments" => ("Office 批注", "Office comments"),
        "ooxml.revisions" => ("修订历史", "Tracked revisions"),
        "ooxml.hidden_content" => ("隐藏内容", "Hidden document content"),
        "ooxml.embedded_object" => ("嵌入对象", "Embedded objects"),
        "ooxml.embedded_media" => ("嵌入媒体与缩略图", "Embedded media and thumbnails"),
        "ooxml.custom_xml" => ("自定义 XML 部件", "Custom XML parts"),
        "ooxml.unknown_property" => ("未识别的属性内容", "Unrecognized property content"),
        "ooxml.unknown_part" => ("未知 Office 部件", "Unknown Office package part"),
        "ooxml.custom.properties" => ("Office 自定义属性", "Office custom properties"),
        "filesystem.resource_fork" => ("macOS 资源叉", "macOS resource fork"),
        "filesystem.quarantine" => ("macOS 隔离来源标记", "macOS quarantine marker"),
        "filesystem.motw" => ("Windows 下载来源标记", "Windows Mark-of-the-Web"),
        "filesystem.download_origin" => ("下载来源属性", "Download-origin attribute"),
        "filesystem.finder_tags" => ("Finder 标签", "Finder tags"),
        "filesystem.extended_attribute" => ("平台扩展属性", "Platform extended attribute"),
        "text.bom" => ("文本 BOM", "Text byte-order mark"),
        "text.invisible_unicode" => ("不可见 Unicode 字符", "Invisible Unicode character"),
        "text.control_character" => ("控制字符", "Control character"),
        "html.comment" => ("HTML 注释线索", "HTML comment marker"),
        "html.meta" => ("HTML 元标签线索", "HTML metadata tag candidate"),
        "watermark.statistical" => ("统计水印检测范围", "Statistical watermark coverage"),
        "image.content_watermark" => ("内容级水印检测范围", "Content watermark coverage"),
        "format.unsupported" => ("格式支持限制", "Format support limitation"),
        _ => {
            if let Some(property) = finding.code.strip_prefix("ooxml.core.") {
                return format!("Office {}", property_title(language, property));
            }
            if let Some(property) = finding.code.strip_prefix("ooxml.app.") {
                return format!("Office {}", property_title(language, property));
            }
            return finding.code.clone();
        }
    };
    if language == Language::Chinese {
        chinese
    } else {
        english
    }
    .into()
}

fn property_title(language: Language, property: &str) -> &str {
    if language == Language::English {
        return property;
    }
    match property {
        "creator" => "作者",
        "lastModifiedBy" => "最后修改者",
        "created" => "创建时间",
        "modified" => "修改时间",
        "title" => "标题属性",
        "subject" => "主题属性",
        "description" => "描述属性",
        "keywords" => "关键词属性",
        "category" => "分类属性",
        "contentStatus" => "内容状态属性",
        "identifier" => "标识符属性",
        "lastPrinted" => "上次打印时间",
        "revision" => "修订编号",
        "language" => "语言属性",
        "version" => "版本属性",
        "Application" => "编辑软件",
        "AppVersion" => "软件版本",
        "Company" => "公司属性",
        "Manager" => "管理者属性",
        "Template" => "模板属性",
        "TotalTime" => "编辑时长",
        _ => property,
    }
}

pub fn finding_summary(language: Language, finding: &Finding) -> String {
    if finding.state == FindingState::RemovedVerified {
        return if language == Language::Chinese {
            "输出重扫已确认这项受支持字段完成移除。".into()
        } else {
            "Output rescan verified removal of this supported field.".into()
        };
    }
    if language == Language::English {
        return finding.summary.clone();
    }
    let summary = match finding.code.as_str() {
        "pdf.document_info" => "PDF 文档信息字典含标准或自定义隐私字段。",
        "pdf.xmp" => "PDF XMP 元数据流可携带作者、软件、时间和来源。",
        "pdf.attachments" => "PDF 包含附件或嵌入文件，Deep 可明确选择相应清理范围。",
        "pdf.active_content" => "PDF 含 JavaScript 或主动动作结构，扫描期间不会执行。",
        "pdf.external_actions" => "PDF 包含外部动作或链接，其目标不会被访问。",
        "pdf.digital_signature" => "PDF 签名结构受到保护，密码学信任状态另行标记为未评估。",
        "pdf.incremental_history" => "PDF 记录增量保存或旧版本线索，净化通过完整非增量重写处理。",
        "pdf.hidden_content_clues" => "PDF 存在隐藏或可选内容线索，需要结合文档语义复核。",
        "pdf.opaque_content" | "pdf.private_structure" => {
            "PDF 含不透明流或私有结构，元数据删除验证覆盖已声明范围。"
        }
        code if code.starts_with("bmff.metadata.") || code == "bmff.exif" => {
            "媒体容器含设备、时间、来源或厂商元数据结构，报告省略字段值。"
        }
        code if code.starts_with("bmff.structure.") => {
            "媒体容器中检测到私有、未知或需要进一步解释的结构，偏移用于复核。"
        }
        "bmff.audit.scope" => "已完成有限媒体容器结构审计，编码负载和私有字段含义未评估。",
        "image.processing.executed" => {
            "已重新解码输出，并按所选参数核对图像处理结果。未知水印的清除状态仍待对应检测器确认。"
        }
        "jpeg.exif" | "png.exif" => {
            "EXIF 可记录作者、设备、拍摄时间和位置，处理动作会保留受保护的显示语义。"
        }
        "jpeg.exif.gps" | "png.exif.gps" => "EXIF 中检测到 GPS 字段结构，报告省略具体坐标。",
        "jpeg.exif.identity" | "png.exif.identity" => {
            "EXIF 中检测到设备、作者或时间字段，报告省略字段值。"
        }
        "jpeg.xmp" => "XMP 可记录编辑工具、作者和来源信息。",
        "jpeg.iptc" => "IPTC 元数据可记录作者、版权和描述信息。",
        "jpeg.comment" => "JPEG 注释可携带文字元数据。",
        "jpeg.icc" | "png.icc" => "ICC 配置影响色彩显示，保守策略保留其字节内容。",
        "jpeg.photoshop_resources" => "Photoshop 资源可能包含剪切路径等有效结构，需要保留并复核。",
        "jpeg.thumbnail" => "嵌入缩略图已保留，可能包含独立于主图像的数据。",
        "jpeg.unknown_app" => "未知应用段已保留，其含义和隐私影响需要复核。",
        "jpeg.trailing_data" | "png.trailing_data" => {
            "文件结束标记之后仍有附加字节，保守策略保留这些数据。"
        }
        "jpeg.provenance" | "png.provenance" => {
            "检测到 JUMBF/C2PA 来源凭据线索，密码学签名有效性未评估，改写会被阻断。"
        }
        "png.text" | "png.ztxt" | "png.itxt" => "PNG 文本块可记录作者、软件、说明和生成参数。",
        "png.time" => "PNG 修改时间块可暴露文件处理时间。",
        "png.animation" => "APNG 动画结构尚未完成帧保真验证，当前阻断净化。",
        "png.unknown_ancillary" => "未知附加块已保留，其用途和隐私影响需要复核。",
        "ooxml.zip_metadata" => "ZIP 成员时间、注释和受支持附加元数据会规范化。",
        "ooxml.signature_or_macro" => {
            "检测到数字签名或宏结构，保守策略保护整个 Office 包并阻断改写。"
        }
        "ooxml.external_relationship" => "外部链接已保留，扫描期间不会打开或访问目标。",
        "ooxml.comments" => "批注可能记录作者身份和历史内容，当前保守策略保留批注。",
        "ooxml.revisions" => "修订可能包含旧内容和修改者信息，当前保守策略保留修订。",
        "ooxml.hidden_content" => "文档隐藏内容已保留，发送前需要复核。",
        "ooxml.embedded_object" => "嵌入对象已保留，其内部元数据尚未评估。",
        "ooxml.embedded_media" => "嵌入媒体与缩略图已保留，其内部元数据尚未评估。",
        "ooxml.custom_xml" => "自定义 XML 部件已保留，可能包含用户或应用数据。",
        "ooxml.unknown_property" => "未识别的属性内容已保留，需要复核。",
        "ooxml.unknown_part" => {
            "未知 Office 部件已保留，证据位置提供 ZIP 成员序号，成员名称已脱敏。"
        }
        "ooxml.custom.properties" => "Office 自定义属性可能记录个人或应用信息。",
        "filesystem.resource_fork" => "资源叉可能携带有效内容，当前可审计并阻断副本改写。",
        "filesystem.quarantine" => "macOS 隔离标记影响安全来源判断，净化副本会保留该标记。",
        "filesystem.motw" => {
            "Windows 下载来源标记影响系统和 Office 安全行为，净化副本会保留该标记。"
        }
        "filesystem.download_origin" => "下载来源属性已保留，可能包含来源地址，报告省略具体值。",
        "filesystem.finder_tags" => "Finder 标签已保留，可能包含个人分类信息。",
        "filesystem.extended_attribute" => {
            "平台属性已保留，其隐私影响需要复核，报告省略名称和具体值。"
        }
        "text.bom" => "检测到 UTF-8 BOM，当前提供只读字符审计。",
        "text.invisible_unicode" => "检测到不可见 Unicode 字符，字符变更可能影响文字或代码语义。",
        "text.control_character" => "检测到控制字符，当前提供只读字符审计。",
        "html.comment" => "检测到 HTML 注释标记线索，当前提供只读审计。",
        "html.meta" => "检测到 HTML 元标签线索，当前提供只读审计。",
        "watermark.statistical" => "未执行需要密钥或专有检测器的统计水印检测。",
        "image.content_watermark" => "未执行像素域或频域的内容级水印检测。",
        "format.unsupported" => "当前离线引擎未提供这个格式的受支持解析器。",
        _ if finding.code.starts_with("ooxml.core.") || finding.code.starts_with("ooxml.app.") => {
            "检测到已知 Office 隐私属性，报告省略具体值。"
        }
        _ => return finding.summary.clone(),
    };
    summary.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn languages_keep_unknown_labels_and_translate_controls() {
        assert_eq!(tr(Language::Chinese, "Scan queue"), "扫描队列");
        assert_eq!(tr(Language::English, "Scan queue"), "Scan queue");
        assert_eq!(tr(Language::Chinese, "future-label"), "future-label");
    }

    #[test]
    fn unknown_watermark_findings_remain_unassessed() {
        let finding = Finding::unassessed(
            "watermark.statistical",
            RiskLayer::StatisticalWatermark,
            "content",
            "Keyed statistical watermark detection was not performed",
        );
        assert_eq!(state(Language::Chinese, finding.state), "未评估");
        assert!(finding_summary(Language::Chinese, &finding).contains("未执行"));
    }

    #[test]
    fn verified_removals_do_not_describe_fields_as_present() {
        let mut finding = Finding::new(
            "ooxml.core.creator",
            RiskLayer::EmbeddedMetadata,
            "OPC/properties/core.creator",
            "Known Office privacy property is present",
            Action::Remove,
        );
        finding.state = FindingState::RemovedVerified;
        assert_eq!(finding_title(Language::Chinese, &finding), "Office 作者");
        assert!(finding_summary(Language::Chinese, &finding).contains("完成移除"));
        assert!(finding_summary(Language::English, &finding).contains("verified removal"));
    }
}
