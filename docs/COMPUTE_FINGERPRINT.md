<!-- SPDX-License-Identifier: MPL-2.0 -->
# Compute Fingerprint Lab — Experimental

This opt-in desktop Lab and `fileveil compute` compare sampled embedding rows with supplied Philox seeds and candidate CUDA parallel layouts. Ordinary file scans never run this module. A match is evidence for a compatible initialization layout under stated assumptions, not a physical GPU identity, training location, complete training-hardware history or calibrated attribution probability.

## Reproduction and technical basis

We inspected [Checkpoint Forensics at b633870](https://github.com/macrogrants/checkpoint-forensics/tree/b633870c4a8b0f85d70026b7f77f7d0858358f89), its published sample hashes and CPU replay, and [the independent reproduction at 8f8ed78](https://github.com/peterjliu/checkpoint-forensics-repro/tree/8f8ed78cf731195bab9f990a6523e65ecd5b7108). The relevant framework mechanism is PyTorch's [`calc_execution_policy` and grid-stride initialization](https://github.com/pytorch/pytorch/blob/main/aten/src/ATen/native/cuda/DistributionTemplates.h). Our Rust implementation independently calculates Philox4x32-10, its Box–Muller normal draws and the positional mapping. Three Random123 known-answer vectors and five independent Python Philox/layout tests pass.

The adapter assumes a sufficiently large CUDA `normal_` tensor with 2,048 threads per SM, a supplied seed and aligned generator offset. Framework versions, partitions and other execution configurations can share or change this layout. Correlation cannot distinguish chips with equivalent execution layouts. The first grid's values are layout-independent, so at least three distinct rows beyond all candidate grid sizes are required. Duplicate effective shard rows are rejected. The winning median must exceed 0.98, separate from the runner-up by 0.1 and pass a wrong-seed control. These gates are conservative heuristics, not a calibrated statistical confidence interval; the report provides per-row range, runner-up and control scores separately.

## Local experiment

On macOS ARM64, the same published, hash-checked BF16 rows were examined with Rust and the independent Python implementation. Four selected rows per model were sampled; every SM count from 16 through 256 was compared.

| Published sample | Best layout (SMs) | Rust median correlation |
| --- | ---: | ---: |
| DeepSeek-V3-Base | 132 | 0.9999986 |
| DeepSeek-V4-Flash | 148 | 0.9995273 |
| Kimi-K3 | 152 | 0.9999962 |
| MiniMax-M3 | 148 | 0.9999896 |

All four layouts agree with independent replay. This is a selected-row CPU reproduction using published seeds; we did not reproduce blind seed recovery or rerun these models on physical NVIDIA GPUs. The separate upstream replay also reproduced its fifth, truncated-normal sample; FileVeil's normal adapter does not claim support for that distinct mechanism.

The 32-case matrix contains four public positives, four BF16→F32 conversions, four simulated int8 round trips, and 20 negative controls: wrong seeds, NumPy PCG64, NumPy MT19937, PyTorch 2.9.1 CPU normal initialization and simulated weight updates with noise four times the observed standard deviation. There were 0/20 false positives in these controls. Conversion and this simulated quantization retained the four positive matches. Perturbation controls did not meet the matching threshold. This does not establish survival after arbitrary training or actual quantized-model conversion.

Measured wall time was 0.369–0.670 seconds per case, including the confined CLI worker. Child peak RSS was 16,465,920 bytes (15.70 MiB). Each analysis sampled 32–56 KiB for BF16 or 64–112 KiB for F32. No complete model was downloaded or loaded; temporary sparse containers were removed. Local raw reports are under `work/v07/checkpoint-research/rust-reproduction-final/`; the harness records the tested CLI SHA-256 and both research revisions.

## Use

```sh
fileveil compute model.safetensors --tensor model.embed_tokens.weight \
  --rows 129083,129105,129127 --seeds 953049583 \
  --sm-counts 108,132,148,152 --json
```

`--philox-offset` is in original generator units and must be divisible by four. `--rows-per-shard` and `--seed-per-rank` describe explicit tensor-parallel seed offsets. Seeds are supplied, never brute-forced. GUI Lab → Compute fingerprint exposes normal single-tensor analysis; advanced sharding arguments are available through CLI.

Only [safetensors](https://github.com/safetensors/safetensors) and its basename-only local shard indexes are read. Selected tensors may be BF16, F16 or F32. Pickle, arbitrary model code and network access are never used. Integer quantized tensors and truncated-normal initialization return unsupported-input errors rather than a hardware attribution.

The header/index limit is 1 MiB; the container may have at most 10,000 tensors and must have consistent, nonoverlapping offsets. At most 65,536 values and 32 million candidate draws are accepted, with a 60-second replay deadline and isolated desktop-worker cancellation. The header and selected rows are re-read from the same descriptor. `sample_sha256` binds sampled bytes; it is not the whole-file SHA-256. Unsampled content and complete model integrity remain unassessed. MCP does not grant this desktop-only experiment additional shard access.

Reproduce with reviewed local research checkouts and an existing NumPy/SciPy installation:

```sh
python3 tools/compute-fingerprint-benchmark.py --fileveil target/debug/fileveil \
  --upstream /path/to/checkpoint-forensics \
  --independent /path/to/checkpoint-forensics-repro \
  --torch-cpu-control --output work/compute-reproduction
```

PyTorch is optional and only needed for its extra CPU negative control. The harness never downloads weights or dependencies. Upstream MIT attribution is retained under `assets/licenses/external-checkpoint-forensics/`; the original programs and model weights are not bundled into the core or release.
