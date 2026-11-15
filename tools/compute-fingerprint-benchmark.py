#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Reproduce public pinned embedding samples with FileVeil's independent Rust replay.

Requires numpy, the reviewed upstream checkout and an explicit FileVeil binary.
No weights are downloaded and temporary sparse tensors are removed after each run.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
try:
    import resource
except ImportError:
    resource = None
import struct
import subprocess
import sys
import tempfile
import time


def tensor(path, model, row_bits, dtype='BF16'):
    width = model['shape'][1]
    stride=2 if dtype=='BF16' else 4
    raw_header = json.dumps({model['tensor']: {'dtype': dtype, 'shape': model['shape'],
                 'data_offsets': [0, math.prod(model['shape']) * stride]}}, separators=(',', ':')).encode()
    with path.open('xb') as stream:
        stream.write(struct.pack('<Q', len(raw_header)))
        stream.write(raw_header)
        stream.truncate(8 + len(raw_header) + math.prod(model['shape']) * stride)
        for row, bits in zip(model['rows'], row_bits):
            stream.seek(8 + len(raw_header) + row * width * stride)
            stream.write(bits.astype('<u2' if dtype=='BF16' else '<f4').tobytes())


def run(exe, path, model, seed, out, name):
    argv = [str(exe), '--json', '--timeout-seconds', '120', 'compute', str(path),
            '--tensor', model['tensor'], '--rows', ','.join(map(str, model['rows'])),
            '--seeds', str(seed), '--sm-counts', ','.join(map(str, range(16,257))),
            '--philox-offset', str(model.get('cpu_offset', 0))]
    if model.get('tp'):
        argv += ['--rows-per-shard', str(-(-model['shape'][0] // model['tp'])),
                 '--seed-per-rank', str(model.get('seed_per_rank', 0))]
    start=time.perf_counter()
    p=subprocess.run(argv, capture_output=True, text=True, timeout=125)
    try: report=json.loads(p.stdout)
    except ValueError as exc: raise RuntimeError(f'{name}: {p.returncode}: {p.stderr[:1000]}') from exc
    (out/(name+'.json')).write_text(json.dumps(report, indent=2)+'\n')
    if p.returncode not in (0,4) or 'compute_fingerprint' not in report.get('advanced',{}):
        raise RuntimeError(f'{name}: {p.returncode}: {report.get("warnings")} {p.stderr[:500]}')
    result=report['advanced']['compute_fingerprint']
    return {'case':name,'status':result['status'],'sm_count':result['candidates'][0]['sm_count'],
            'median_r':result['candidates'][0]['median_correlation'],
            'sampled_bytes':result['sampled_bytes'],'elapsed_seconds':time.perf_counter()-start,
            'wrong_seed_median_r':result['wrong_seed_control']['median_correlation']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fileveil',type=Path,required=True)
    parser.add_argument('--upstream',type=Path,required=True)
    parser.add_argument('--independent',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--torch-cpu-control',action='store_true',help='Use an already installed PyTorch for an additional CPU control')
    args=parser.parse_args()
    import numpy as np
    args.output.mkdir(parents=True,exist_ok=False)
    exe=args.fileveil.resolve(); upstream=args.upstream.resolve()
    models=json.loads((upstream/'models.json').read_text())
    summary={'schema':'fileveil.compute-reproduction.v1','upstream_commit':subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD'],text=True).strip(),
             'fileveil_sha256':hashlib.file_digest(exe.open('rb'),'sha256').hexdigest(),'cases':[],
             'scope':'Supplied seeds and published selected rows; no GPU rerun, physical identity or training-location claim',
             'not_assessed':['GPU-native replay','blind seed search','truncated-normal adapter']}
    independent=None
    if args.independent:
        sys.path.insert(0,str(args.independent.resolve()))
        from forensics.philox import normal_at
        independent=normal_at
        summary['independent_commit']=subprocess.check_output(['git','-C',str(args.independent),'rev-parse','HEAD'],text=True).strip()
    rng=np.random.default_rng(424242)
    torch=None
    if args.torch_cpu_control:
        import torch
        torch.manual_seed(424242)
        summary['torch_cpu_version']=torch.__version__
    for original in models:
        if original['dist']!='normal':continue
        all_bits=np.load(upstream/'rows'/(original['name']+'.npy'),allow_pickle=False)
        assert hashlib.sha256(all_bits.astype('<u2').tobytes()).hexdigest()==original['sha256']
        chosen=list(range(max(0,len(original['rows'])-4),len(original['rows'])))
        model=dict(original,rows=[original['rows'][i] for i in chosen])
        bits=all_bits[chosen].copy()
        cases=[('published',bits,original['seed']),('wrong-seed',bits,original['seed']+1)]
        values=(bits.astype(np.uint32)<<16).view(np.float32)
        sigma=float(np.std(values))
        # Quantization is simulated and labeled; these are not real trained releases.
        q=np.clip(np.rint(values/(max(sigma,1e-12)/16)),-127,127)*(max(sigma,1e-12)/16)
        updated=values+rng.normal(0,sigma*4,values.shape).astype(np.float32)
        cpu=rng.normal(0,max(sigma,1e-12),values.shape).astype(np.float32)
        mt=np.random.Generator(np.random.MT19937(424242)).normal(0,max(sigma,1e-12),values.shape).astype(np.float32)
        for name,control in [('simulated-int8-roundtrip',q),('simulated-training-noise',updated),('cpu-pcg64',cpu),('cpu-mt19937',mt)]:
            cases.append((name,(control.astype(np.float32).view(np.uint32)>>16).astype(np.uint16),original['seed']))
        if torch is not None:
            control=torch.empty(values.shape,device='cpu',dtype=torch.float32).normal_(0,max(sigma,1e-12)).numpy()
            cases.append(('pytorch-cpu',(control.view(np.uint32)>>16).astype(np.uint16),original['seed']))
        cases.append(('bf16-to-f32',values,original['seed']))
        if independent:
            shard=-(-model['shape'][0]//model.get('tp',1))
            correlations=[]
            for row,y in zip(model['rows'],values):
                seed=model['seed']+row//shard*model.get('seed_per_rank',0)
                positions=(row%shard*model['shape'][1])+np.arange(model['shape'][1],dtype=np.int64)
                ref=independent(seed,model['sms']*2048,positions,model.get('cpu_offset',0)//4)
                correlations.append(float(np.corrcoef(y,ref)[0,1]))
            summary.setdefault('independent_correlations',{})[model['name']]=correlations
            assert np.median(correlations)>.98
        for name,data,seed in cases:
            with tempfile.TemporaryDirectory(prefix='compute-',dir=args.output) as tmp:
                path=Path(tmp)/'sample.safetensors';tensor(path,model,data,'F32' if name=='bf16-to-f32' else 'BF16')
                result=run(exe,path,model,seed,args.output,model['name']+'-'+name)
            summary['cases'].append(result)
            if name in ('published','bf16-to-f32'):assert result['status']=='candidate_layout_match' and result['sm_count']==model['sms']
            if name in ('wrong-seed','cpu-pcg64','cpu-mt19937','pytorch-cpu','simulated-training-noise'):assert result['status']=='unable_to_determine'
    summary['published_positives']=sum(c['case'].endswith('-published') for c in summary['cases'])
    summary['negative_false_positives']=sum(c['status']=='candidate_layout_match' for c in summary['cases'] if any(c['case'].endswith('-'+x) for x in ['wrong-seed','cpu-pcg64','cpu-mt19937','pytorch-cpu','simulated-training-noise']))
    summary['child_peak_rss_native_units']=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss if resource else None
    summary['peak_rss_units']='bytes' if sys.platform=='darwin' else 'KiB'
    (args.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
