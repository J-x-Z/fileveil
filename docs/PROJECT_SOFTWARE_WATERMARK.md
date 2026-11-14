<!-- SPDX-License-Identifier: MPL-2.0 -->
# 项目持续签名与软件水印

以下命令面向当前开发版 CLI。GUI 的 Projects 提供项目配置与注册表，Lab 提供软件水印和二进制取证入口。所有验证结论以 JSON 报告的具体范围为准。

新工作区优先提供中英文文案。其余七种界面语言中的部分新术语回退英文，技术报告字段保留协议原值。

## 项目登记与增量续签

Registry 默认策略为 `manifest-only`。Project 的默认文件模式为 `external`，`copy_external_files=false`。原件只读，独立发行目录保存带 Ed25519 签名的清单、证据与版本关联。可执行文件和安装包按完整 SHA-256 登记，平台代码签名受到保护。

公开项目配置可以纳入版本控制。签名私钥、索引和状态独立保存。首次登记指定密钥后，后续同步从私有状态读取绑定。多项目复用身份时，在各项目首次登记中选择同一密钥或系统密钥引用。

在项目目录内运行以下示例。`--source .` 登记当前目录，也可以指定已经存在的构建产物目录。

```sh
mkdir -p ../fileveil-private
fileveil heritage-keygen --output ../fileveil-private/author.key
fileveil project init fileveil.project.json \
  --work-id demo-project --author "作者" --copy-id development \
  --source . --output dist/fileveil-release \
  --key ../fileveil-private/author.key \
  --build-argv-json '["cargo","build","--release"]'
fileveil project sync fileveil.project.json --build --version v1
fileveil project watch fileveil.project.json
fileveil project verify fileveil.project.json
```

`sync --build` 先执行已配置的构建命令，成功后再续签。普通 `sync` 和 `watch` 处理已有文件。Watch 使用元数据探针、防抖和周期性完整哈希检查，默认轮询约 2 秒、完整复查约 15 分钟，并根据实测耗时退避。`--full-rescan` 强制重新读取 SHA-256。配置发生变化时，先用 `project init --update` 显式批准。

增量索引记录新增、修改、删除和可识别的重命名，未变化文件跳过重复处理。连续执行相同输入保持幂等。处理过的副本与原件分开保存，避免反复叠加有损水印。自定义私有状态目录时，各次命令需要传入同一个 `--state-directory`。

集中登记与批量验证使用 Registry。

```sh
fileveil registry init --author "作者"
fileveil registry add . --name Demo --policy manifest-only \
  --key ../fileveil-private/author.key
fileveil registry list
fileveil registry sync --all
fileveil registry verify --all
```

`asset-watermark`、`compiler-watermark`、`hybrid` 是显式策略。编译器策略需要真实的输入、输出和工具链配置，编译产物验证通过后才进入项目发行清单。移除登记引用保留工程和历史。

## 本地发布与 GitHub Actions

`registry ci` 生成 `fileveil-ci.json` 和调用可复用工作流的 YAML。`--write-directory` 使用新目录，并保护现有文件。下面示例将 `target/release` 作为发行输入。

```sh
fileveil registry ci --name Demo --work-id demo-project --author "作者" \
  --copy-id release --artifacts target/release --output fileveil-release \
  --build-argv-json '["cargo","build","--release"]' \
  --test-argv-json '["cargo","test","--locked"]' \
  --engine-ref main --runner ubuntu-latest --write-directory ci-bundle
```

将生成的配置和工作流放入目标仓库对应位置。`engine-ref` 可以选择已核验的提交或标签。生成器输出的本地命令含路径模板，需要填入本机 FileVeil CLI 和脚本路径。

GUI 从选中的注册项目导出实际 `policy`、`rules` 和 `compiler` 配置，并显示当前生成策略。ManifestOnly、资产水印、编译器水印和混合策略的处理范围分别保存在配置中。

Asset/Hybrid 的规则缺省使用共享图片规则，显式 `[]` 保留空规则。编译目标的输入和输出要求仓库相对路径。工具链声明与实际 job 使用的工具分别记录。

本地统一入口使用已有文件密钥，并将持久状态放在工程外。私钥原路径与解析后的路径都需要位于工程、发行输入和输出目录之外。证据输出目录需要尚不存在。

```sh
python /path/to/fileveil/tools/project-ci-local.py \
  --fileveil /path/to/fileveil/target/debug/fileveil \
  --config fileveil-ci.json --key ../fileveil-private/author.key \
  --state-directory ../fileveil-private/ci-state \
  --evidence-directory evidence-v1 --version v1
```

ManifestOnly 和资产策略下，入口复用后处理脚本执行配置中的 build/test，随后同步、验证并导出证据。Compiler/Hybrid 自动串接 Prepare、IRMark、FinalBuild 与 FinalSign，最后将签名历史写回原配置的 `output_directory`。LLVM 与 pass 使用配置中已有的显式路径，也可通过 `--llvm-directory` 和 `--plugin` 覆盖，本地入口不会下载 SDK。

编译中间文件使用 FileVeil 现有忽略的 `work` 目录，完成后清理。本轮最终产物持久保存于私有状态目录旁的 `compiler-artifacts/<edition>/<run>/artifacts`，供后续 Project Verify 和续签读取。默认状态目录位于密钥旁的 `.fileveil-ci-state/<edition>/state`，也可显式指定 `--state-directory`。未指定证据目录时，每轮在状态旁新建 `evidence/<run>`，返回的 receipt 列出实际证据与发行位置。显式 `--evidence-directory` 继续保护已有目录。本地入口在清理中间目录后再次执行 Project Verify，完整性、签名、信任和历史均有效后才返回成功。已被项目清单引用的最终产物需继续保留。

相同编译输入、资产、身份、版本及时间请求命中私有已验证缓存时，复用原来的最终字节与持久来源目录。入口仍重新准备输入并核对摘要，复验既有签名后导出新的证据包。`compiler_cache_hit` 标明此次复用，避免随机水印 nonce 使同版本重复运行产生不同发布内容。缓存产物发生变化时拒绝复用。

独立调用底层 `project-postprocess.py` 时，`--after-build` 接收已完成的构建产物，`--build-context` 记录独立上游 job 的观测范围。Compiler/Hybrid 还需要 `--compiler-context`，用于核对已标记产物与构建记录。

GitHub Actions 使用 `FILEVEIL_SIGNING_KEY_BASE64` Secret 保存整个 FileVeil 私钥文件的 Base64 编码。工作流仅接受 Linux、macOS、Windows 的临时托管 runner。ManifestOnly/Asset 使用独立的 Build 和 FinalSign 两个 job。Compiler/Hybrid 已实现以下四阶段流程，真实 GitHub Actions 执行与三平台 SDK、插件加载仍待 CI 验收。

| 阶段 | 实际操作 | 签名 Secret |
| --- | --- | --- |
| Build | 执行配置的构建命令，生成无标记 LLVM IR 和 baseline，冻结输入及 SHA-256 | 无 |
| IRMark | 从固定来源构建 FileVeil 与 LLVM pass，验证中转输入，对 IR 植入签名水印并复检 | 仅注入 IR 签名步骤 |
| FinalBuild | 在新的独立 job 中编译标记 IR，按显式授权运行 baseline/marked 测试向量，执行配置的测试命令并冻结最终字节 | 无 |
| FinalSign | 字节审计核对最终二进制中的已认证 packet、作品声明、IR 绑定和产物摘要，续接项目历史并签署完整发行清单 | 仅注入最终后处理步骤 |

编译阶段使用固定 LLVM 23.1.5 官方 SDK，并校验下载 SHA-256。签名阶段使用工作流构建的受信 pass，公开配置中的本机 LLVM/plugin 路径只作为声明保留。FinalSign 通过只读结构解析验证产物，构建推导与测试结果保留为上游观测范围。未授权原生执行时，测试向量状态为 `not_assessed`。`--after-build` 配合独立构建结果使用，配置与调用工作流的 `policy` 必须一致。

调用工作流需要 `contents: read` 和 `actions: read`，附加 Release 证据的 job 单独申请 `contents: write`。生成配置中不包含私钥，受 Secret 保护的 job 不执行项目的构建或测试命令。

## 证据与历史恢复

`fileveil-evidence.zip` 包含本轮 generation 的签名清单、证据、提交标记及已生成的副本，还包含完整保留历史的 `manifest.json`、`evidence.json` 和 `COMMITTED` 元数据，以及验证摘要和构建上下文。默认 ManifestOnly 下，原始发行二进制仍由项目自身的发行流程保留。

历史元数据连续性与历史资产字节分别评级。报告中的 `historical_asset_bytes` 为 `not_assessed`，本轮内容按其签名清单复核。`history_assessment_scope` 会区分完整保留链与私有检查点范围。

同一作品继续使用统一 Work ID。CI 以 `SHA256("FileVeil CI edition v1\0" + work_id + "\0" + copy_id + "\0" + platform)` 的前 32 个十六进制字符派生各 edition 的 `project_id`。平台取 `linux`、`darwin`、`win32` 等实际构建记录。不同副本与平台各自续接历史，同一配置与平台的跨标签运行串行处理。

CI 的 `history.zip` 与证据 artifact 默认保留 14 天，build 中转 artifact 保留 1 天。公开历史包只承载已签名的历史元数据，适合独立备份。恢复操作要求目标目录尚不存在，并与配置的发行目录一致。

```sh
python /path/to/fileveil/tools/project-ci-stage.py \
  receive history.zip fileveil-release --history-only
```

恢复后使用相同 Work ID、发行副本 ID、平台和签名身份验证并续签。云端续跑还需要让工作流取得恢复后的历史输入。`history_restore_scope` 记录本轮历史恢复范围，缺失或未恢复的部分需要列为历史缺口。过期、删除或历史索引丢失时，连续性需要已有历史包或外部检查点支撑。原链连续性无法建立时需要阻断续链声明。14 天保留策略提供的是短期恢复窗口。

## 软件水印的四种模式

| 模式 | 实际输入与输出 | 清理与验证范围 |
| --- | --- | --- |
| `source` | 输出前缀与 C/C++ 原文逐字节一致，源码副本另含独立 CRT helper、初始化器和原生数据区 | 正确密钥解出 challenge 后重生成完整副本，字节一致且原前缀摘要匹配签名时恢复原文 |
| `ir` | 对显式 LLVM IR 运行本地 pass，输出标记后的 IR | 保留已有 constructor、`llvm.used` 等项，检查规范 IR 恢复摘要及其签名绑定 |
| `compiler` | C/C++ 或显式 IR 经 pass 与本机编译器产生新二进制 | 通过签名绑定的无标记源码/IR受控重编，可选运行指定测试向量比较 |
| `structure` | 对支持的无平台签名容器加入已绑定原始摘要的编码 footer，或审计已有数据区 | 已知 footer 可恢复原字节，已知非执行 section 载体可以清理，语义候选保留 |

插件需要匹配本机平台、架构和 LLVM major。构建产物附有 ABI 元数据。下面使用 macOS 的 LLVM 路径，输入 `main.c` 应为已有的可构建程序。

```sh
export FILEVEIL_LLVM_DIR=/opt/homebrew/opt/llvm
fileveil software build-plugin tools/software-watermark --output work/llvm-pass
export FILEVEIL_SOFTWARE_PLUGIN="$PWD/work/llvm-pass/FileVeilWatermark.dylib"
fileveil software mark main.c --mode compiler --output marked-app \
  --key ../fileveil-private/author.key --work-id demo-project --copy-id release
fileveil software inspect marked-app
fileveil software verify marked-app --key ../fileveil-private/author.key
fileveil software clean marked-app --mode compiler --reference main.c \
  --output cleaned-app --key ../fileveil-private/author.key
```

Source 输出选择 `.c/.cpp`，IR 输出选择 `.ll`。Source 清理保护后来修改的代码和不完整的标记。平台签名的 section 清理受到保护。`__FILE__`、宏、包含路径和链接设置需要使用一致的受控配方验证。`--allow-execution` 显式允许本地程序执行，`--test-arguments-json` 提供测试向量。默认审计只读取二进制与已知记录。

## 密码学与研究来源

软件声明由 Ed25519 签名，作者、Work ID、副本 ID 等声明使用域分离派生密钥进行 ChaCha20-Poly1305 AEAD 加密。编译器接收公开 pass packet，签名私钥留在 Rust 侧。签名、解密、信任和内容绑定分别报告。Project 外部签名清单进一步绑定最终二进制的完整 SHA-256，并通过 Work ID、发行副本和版本记录建立关联。

CRT 设计直接提炼自 Dalla Preda/Ianni 的公开论文机制。论文利用执行时变量中的模素数余数表示整数，再以中国剩余定理恢复标识。本项目的 Rust/C++ 为独立实现，未复制作者程序代码。完整论文算法复现、动态轨迹选点和深度语义混合属于未验证范围。[Exploiting number theory for dynamic software watermarking](https://link.springer.com/article/10.1007/s11416-023-00489-8)

当前 helper 使用九个互素模数、密钥派生的 witness/challenge、仿射余数运算和原子写入。运行探针实际取得九个余数后执行 CRT 恢复，并检查错误 challenge 对照。静态 carrier 可以复制，CRT 辅助代码也可以被针对性修改或删除。未知水印检测、抵抗任意重写和任意程序语义等价仍属实验范围。签名有效只证明相应声明及摘要通过密码学检查，信任身份另由明确公钥锚决定。

## 已取得的实证范围

- Rust 1.99、LLVM 23 的 `no_std` 导出 `u64` 函数经显式 IR Mark、Clean、重链接为 macOS 原生 dylib，12 个向量在原始、标记、清理版本中一致，原 IR 保持不变，独立 Python 验签与解密通过。任意 Cargo 工程自动集成及生产级 rustc 插件状态为 `not_assessed`。
- Rust 1.98.0-nightly 自带 LLVM 22.1.7 的同一夹具另经 LLVM 22.1.8 本机 pass 完成显式 IR 植入、清理与重链接。macOS ARM64 dylib 的相同 12 个边界向量一致，独立验签、解密及实际九残差 CRT 探针通过，错误 challenge 未恢复目标 witness，原源码和 IR 摘要保持不变。
- LLVM 21.1.8 与 23.1.2 各有 24 条矩阵记录，每组包含 12 条 macOS ARM64 原生 baseline/marked/clean 运行和 12 条 x86_64/ARM64 ELF、COFF 交叉对象检查。LLVM 23 另验证了 12 个链接后的 ELF/PE 及 strip。Windows/Linux 在这组矩阵中的范围为交叉产物结构和链接检查。
- 原生 CLI Lab 的 O0/O2/O3/LTO 四条 case 均保留已知载体，strip、重链接和受控清理重建复检通过。四个干净重建对照均未检出该已知载体。实际 CRT 探针运行在由同一 IR 编译的 shared companion 中，最终 EXE 内部探针的直接调用状态为 `not_assessed`。
- 本地 CI 组件验收通过隔离构建传输、跨路径公开历史恢复和 CI Secret 后处理签名，累计验证三个 generation。独立旧版 `verify-evidence.py` 通过两个 generation 的签名检查。这些记录的范围为本地组件流程。
- 本地统一入口已验证 Manifest 的 CMake 构建和四项 CTest，以及 C/C++ 两个编译目标的同版本重复发布。第二次复用相同 generation 与持久来源，分别生成新证据目录，进程退出后的独立 Project Verify 四项状态均有效，八个夹具源文件保持原摘要。

下表来自本地 `work/software-cli-acceptance/20261114T205602/lab-summary.json`。它测量单个夹具的 Clang 构建子进程，四条 case 的标记文件均为 50,456 B，干净重建均为 50,008 B，增加 448 B。

| 优化 | Mark 构建 CPU / 秒 | Clean 构建 CPU / 秒 | Mark 峰值 RSS / MiB |
| --- | --- | --- | --- |
| O0 | 0.15 | 0.14 | 47.09 |
| O2 | 0.18 | 0.18 | 52.17 |
| O3 | 0.17 | 0.16 | 52.42 |
| LTO | 0.19 | 0.18 | 69.47 |

该快照的 CLI SHA-256 为 `b34efd4df17bad172e56fe4fe0d136fce549665b738af7cb6183a99b63b0679a`。这些 case 覆盖指定夹具和测试向量，检测率、误报率、速度及内存对任意工程的推广效果尚未评估。

## MCP 授权范围

`fileveil_software_inspect/detect/verify/compare` 提供受限字节审计，`fileveil_software_clean` 允许显式 `structure` 净化副本。编译器、插件加载配置和程序执行请求受到阻断。Project/Registry 的同步、状态和验证继续使用已有授权目录、读写分离与独立签名密钥 grants，连接本身不会扩大权限。默认处理离线执行。
