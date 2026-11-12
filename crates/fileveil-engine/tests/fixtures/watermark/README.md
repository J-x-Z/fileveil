# Independent image-watermark controls

`astronaut.png` is the 512 × 512 photograph of astronaut Eileen Collins from
NASA, distributed by scikit-image v0.25.2. Scikit-image identifies this image as
public domain with no known copyright restrictions. The photograph retains its
original bytes and metadata as a negative control.

- [NASA photograph](https://flic.kr/p/r9qvLn)
- [Scikit-image source and public-domain statement](https://github.com/scikit-image/scikit-image/blob/v0.25.2/skimage/data/_fetchers.py#L355-L373)
- [Exact input asset](https://github.com/scikit-image/scikit-image/blob/v0.25.2/skimage/data/astronaut.png)

`astronaut-sd1.png` and `astronaut-sdxl.png` were generated from that photograph
by the unmodified `EmbedMaxDct` encoder in ShieldMnt/invisible-watermark commit
`68d0376d94a4701ed240af0841ec12e00676e325`. The same independent upstream
decoder verifies 136/136 and 48/48 payload bits respectively.

The SD1 payload is the 17-byte public string `StableDiffusionV1`. The SDXL
payload is the public 48-bit sequence `0xB3EC907BB19E`. These tests establish
compatibility with deployed public signal mechanisms. The natural photograph
was captured by a camera, and this deliberate embedding carries no model,
author or device authentication.

- [Official SD1 integration](https://github.com/CompVis/stable-diffusion/blob/main/scripts/txt2img.py)
- [Official SDXL detector](https://github.com/Stability-AI/generative-models/blob/e8cd657656fa5d61688191730d0e03242bf4ed44/scripts/demo/detect.py)
- [Independent encoder and decoder](https://github.com/ShieldMnt/invisible-watermark/blob/68d0376d94a4701ed240af0841ec12e00676e325/imwatermark/maxDct.py)

`astronaut-other.png` contains a different public payload as an unknown-payload
negative control. The two JPEG files are ordinary quality-95 lossy re-encodings
of the positive PNGs. The independent upstream decoder loses those marks, so
they exercise the difference between a successful encoding operation and a
detectable payload. `upstream-evidence.json` records hashes and actual scores.

Run `tests/support/generate_watermark_fixtures.py` with the developer-only
Python dependencies and an explicit oracle directory to reproduce the files.
The `*-444.jpg` positive JPEGs use quality 95 and 4:4:4 sampling. They retain
136/136 and 48/48 bits through the independent upstream decoder. The tests also
verify that ordinary 4:2:0 recompression can make the same payload undetectable.

Cargo tests run offline using these fixtures. The adapted decoder retains its
upstream MIT license in
`assets/licenses/external-invisible-watermark/LICENSE-MIT`.
