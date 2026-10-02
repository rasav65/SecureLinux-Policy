#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,hashlib,json,os,re,sys
from pathlib import Path

CANDIDATE_STATUS='NON_RELEASE_MEASUREMENT_CANDIDATE'
BUILD_CONTRACT_ID='step7b0-build-contract'
BUILD_CONTRACT_VERSION='0.9.3'
BUILD_CONTRACT_SHA256='aa1030729cfd96f804442143af354df8cf4ac97ebb4b02c551f9c071324a9729'
TARGET_ID='ubuntu-24.04-x86_64'
BUILDER_ID='securelinux-policy-builder-v1'
CANDIDATE_CANONICAL_PATH='step7b0/phase-b/securelinux-policy-builder-measurement-candidate-v4.py'
MEASUREMENT_LOCK_SENTINEL='0'*64
EXPECTED_INPUT_SHA256={
'controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv':'7be3247b957d575f5dee8abd851dc8a6138640fc0e25a58492f43e571887dc65',
'controls/fstec-core/linux-2022/fstec-linux-2022-2.4.1-dmesg-restrict.yaml':'51f99ed4b7c67eb30558176685885337c27a4d8c2047a8e667059dd2bbff07d9',
'controls/fstec-core/linux-2022/fstec-linux-2022-2.4.2-kptr-restrict.yaml':'ba25c49b237cf91b74afcda02e15fd872e81c08973abd9719a8f4c465513aa9a',
'controls/fstec-core/linux-2022/fstec-linux-2022-2.4.8-bpf-jit-harden.yaml':'cfe64060a4d9829351c2c6f19c6f41b0e0697bd8be5b503a90ffe27a5f4c52ee',
'controls/fstec-core/linux-2022/fstec-linux-2022-2.5.2-perf-event-paranoid.yaml':'b0eb7068712e20660c0d84871c271c6f3fdc542132cca1cf529910dcf7f85c0a',
'controls/fstec-core/linux-2022/fstec-linux-2022-2.5.4-kexec-load-disabled.yaml':'6006fdfb164b8a8860b8f4ae6d4e2758799f25ed32d53e185916da0ef0b7ed01',
'step7b0/BUILD-CONTRACT-v0.9.3.md':'aa1030729cfd96f804442143af354df8cf4ac97ebb4b02c551f9c071324a9729',
'step7b0/phase-a/STEP7B0-CONTROL-SET.lock':'92a1a0b9e97a105ebc1b7880f3453bf8f88d6eaa34754d1687751f7fba095930',
'step7b0/phase-a/adapter/sysctl-check-adapter-v1.json':'f66f6b094c551eb7340e3cb9d87b816c81214fbf8cccff24c085c9e3d3a33496',
'step7b0/phase-a/adapter/sysctl-check-adapter-v1.py':'7def3714012b3d8cde33d4c8a04ea743e8fee1e98d9160ed273d136148e96fee',
'step7b0/phase-a/contracts/build-environment-v1.json':'40fb1318f311c3dac6f8a5d7d45a5cc07e9f21b0f3486f903ff1afa9d0787a72',
'step7b0/phase-a/contracts/check-semantic-v1.json':'f708f6616e1b36db9960f00dc6eca062ced0b19341af4c419ed81889b4a1b963',
'step7b0/phase-a/contracts/cli-rc-v1.json':'698a7cb399ddbb1019928f0f7e73e6e5427d2dadd0d013d2b29077069705ff51',
'step7b0/phase-a/contracts/engineering-contracts-v1.json':'173dc5a7907e27b6fe6aaf41f21ff553219d4a65a37ca3e002f812cc41ea6db2',
'step7b0/phase-a/contracts/readonly-command-policy-v1.json':'026ecccfd9bba43dd639837ef89afa6f700553e5d9a65ffb4c0e230b2a843bcc',
'step7b0/phase-a/contracts/target-ubuntu-24.04-x86_64-v1.json':'3184a1d26f42048ee2579542ca77c4dae172101322fefa85da3d46d34263ba67',
'step7b0/phase-a/registries/BUILD-BINDINGS.tsv':'16e0d6c5180e89077eab0ab15d0bf79184108f81605d5375d1451ec72e16e37a',
'step7b0/phase-a/registries/EMISSION-EDGES.tsv':'d319ab1e1396caa948e1c5ab9e7cc0b454790dce5fa0447304bfadcd4fd32e27',
'step7b0/phase-a/registries/EMISSION-NODES.tsv':'da35e1b58e770e691c7d90417eb59dd61b48100260f4c055fbbf5e9c08d8abf2',
'step7b0/phase-a/registries/ENGINEERING-BINDINGS.tsv':'73ed88f6e8f1ab5e89c3c9834d180b804e525f86cc36ecccfdbe7cd8fd20a3a8',
'step7b0/phase-a/registries/RUNTIME-INVOCATIONS.tsv':'f01b3d388b4d875442c85d961e8c82795ee94fab4bbe1d0f5ae1a27ed1ab1a8d',
'step7b0/phase-a/serializer/securelinux-policy-check.sh.tmpl':'94531ddcd78b407362cec5ebd9b8176ef42d694300197ef65e4f2bac4b755cbc',
'step7b0/phase-a/serializer/serializer-contract-v1.json':'d5e36d36bb2663a4f2964371b948ffc54b02c78163592aece8aa334268942315',
}
ALLOWED_ENV={'LC_ALL':'C','LANG':'C','TZ':'UTC','PYTHONHASHSEED':'0','PYTHONNOUSERSITE':'1','HOME':'/nonexistent'}

sys.dont_write_bytecode=True

def sha_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def cjson(o)->bytes:return (json.dumps(o,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')
def shell_single(s:str)->str:return "'"+s.replace("'","'\\''")+"'"

def parse_tsv(b:bytes):
    txt=b.decode('utf-8')
    return list(csv.DictReader(txt.splitlines(),delimiter='\t'))

def parse_control(b:bytes)->dict:
    txt=b.decode('utf-8')
    out={};section=None
    for line in txt.splitlines():
        if not line or line.lstrip().startswith('#'):continue
        if not line.startswith(' '):
            m=re.match(r'^([A-Za-z0-9_]+):\s*(.*)$',line)
            if not m:continue
            k,v=m.groups();section=k
            if v!='':out[k]=v.strip().strip('"')
            continue
        m=re.match(r'^\s{2}([A-Za-z0-9_]+):\s*(.*)$',line)
        if m and section:
            k,v=m.groups();v=v.strip()
            if v=='null':val=None
            elif v=='true':val=True
            elif v=='false':val=False
            elif re.fullmatch(r'-?[0-9]+',v):val=int(v)
            else:val=v.strip('"')
            out[f'{section}.{k}']=val
    return {
      'id':out['id'],'layer':out['layer'],'index_id':out['source.index_id'],'doc_id':out['source.doc_id'],
      'source_locator':out['source.locator'],'quote_sha256':out['source.quote_sha256'],
      'parameter_kind':out['parameter.kind'],'parameter_locator':out['parameter.locator'],'key':out['parameter.key'],
      'expected_op':out['expected.op'],'expected_value':out['expected.value'],'expected_type':out['expected.type'],
      'apply_supported':out['apply.supported'],
    }

def read_exact_inputs(root:str)->dict[str,bytes]:
    data={}
    for rel in sorted(EXPECTED_INPUT_SHA256,key=lambda s:s.encode()):
        p=os.path.join(root,*rel.split('/'))
        with open(p,'rb') as f:b=f.read()
        got=sha_bytes(b)
        if got!=EXPECTED_INPUT_SHA256[rel]:raise RuntimeError(f'input SHA mismatch: {rel}: {got}')
        data[rel]=b
    return data

def load_adapter(source:bytes):
    ns={'__name__':'slp_adapter_embedded_load'}
    exec(compile(source,'<accepted-sysctl-check-adapter-v1>','exec'),ns,ns)
    return ns

def topo_order(nodes,edges):
    bynode={r['emission_node_id']:r['block_id'] for r in nodes}
    if len(bynode)!=len(nodes) or len(set(bynode.values()))!=len(nodes):raise RuntimeError('emission node uniqueness')
    out={n:set() for n in bynode};indeg={n:0 for n in bynode}
    seen=set()
    for e in edges:
        a,b=e['from_emission_node_id'],e['to_emission_node_id']
        if a not in bynode or b not in bynode:raise RuntimeError('emission edge endpoint')
        if e['edge_type']=='emit_before':x,y=a,b
        elif e['edge_type'] in ('emit_after','emit_requires'):x,y=b,a
        else:raise RuntimeError('unknown edge type')
        if x==y or (x,y) in seen:raise RuntimeError('invalid/duplicate normalized edge')
        seen.add((x,y));out[x].add(y);indeg[y]+=1
    order=[]
    while len(order)<len(bynode):
        ready=[n for n in bynode if indeg[n]==0 and n not in order]
        if not ready:raise RuntimeError('emission cycle')
        n=min(ready,key=lambda z:bynode[z].encode('utf-8'));order.append(n)
        for y in out[n]:indeg[y]-=1
    return [bynode[n] for n in order]

def block_bytes(block_id:str,body:str)->bytes:
    if not body.endswith('\n'):body+='\n'
    if re.search(r'^# (BEGIN|END) GENERATED BLOCK ',body,re.M):raise RuntimeError('reserved marker in body')
    return (f'# BEGIN GENERATED BLOCK {block_id}\n'+body+f'# END GENERATED BLOCK {block_id}\n').encode('utf-8')

def eng_body(role:str,ctx:dict)->str:
    if role=='build_info':
        return f'''slp_build_info() {{
  printf "%s\\t%s\\n" "SLP-BUILD-INFO-V1" "BUILD_CONTRACT_SHA256={ctx['contract_sha']}"
  printf "%s\\t%s\\n" "SLP-BUILD-INFO-V1" "BUILDER_SHA256={ctx['builder_sha']}"
  printf "%s\\t%s\\n" "SLP-BUILD-INFO-V1" "TARGET_ID={TARGET_ID}"
}}
'''
    if role=='cli_rc':
        return '''slp_help() {
  printf "%s\\n" "SecureLinux-Policy v3 read-only checker"
  printf "%s\\n" "usage: securelinux-policy-check.sh [--help|--build-info|--provenance [control_id]]"
}
slp_cli_rc() {
  _SLP_ACTION=policy
  _SLP_PROVENANCE_FILTER=
  if [[ $# -eq 0 ]]; then return 0; fi
  case "$1" in
    --help)
      if [[ $# -ne 1 ]]; then return 2; fi
      _SLP_ACTION=help
      return 0
      ;;
    --build-info)
      if [[ $# -ne 1 ]]; then return 2; fi
      _SLP_ACTION=build_info
      return 0
      ;;
    --provenance)
      if [[ $# -gt 2 ]]; then return 2; fi
      _SLP_ACTION=provenance
      if [[ $# -eq 2 ]]; then _SLP_PROVENANCE_FILTER=$2; fi
      return 0
      ;;
    *)
      return 2
      ;;
  esac
}
'''
    if role=='machine_output_format':
        return '''slp_emit_record() {
  printf "%s\\n" "$1"
}
'''
    if role=='provenance_query':
        records=''.join('# SLP-PROVENANCE-V1 '+json.dumps(r,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n' for r in ctx['provenance_records'])
        return '''slp_provenance_query() {
  local _slp_filter=${1-}
  local _slp_line _slp_json
  while IFS= read -r _slp_line; do
    case "$_slp_line" in
      "# SLP-PROVENANCE-V1 "*)
        _slp_json=${_slp_line#\\# SLP-PROVENANCE-V1 }
        if [[ -z $_slp_filter ]]; then
          printf "%s\\n" "$_slp_json"
        else
          case "$_slp_json" in
            *"\\\"control_id\\\":\\\"$_slp_filter\\\""*) printf "%s\\n" "$_slp_json" ;;
          esac
        fi
        ;;
    esac
  done < "$0"
}
'''+records
    if role=='result_aggregation':
        return '''slp_result_reset() {
  _SLP_TOTAL=0
  _SLP_PASS=0
  _SLP_FAIL=0
  _SLP_NOT_FOUND=0
  _SLP_ERROR=0
}
slp_result_record() {
  local _slp_line=$1
  local _slp_old_ifs=$IFS
  IFS='\t'
  set -- $_slp_line
  IFS=$_slp_old_ifs
  _SLP_TOTAL=$((_SLP_TOTAL + 1))
  case "$5" in
    PASS) _SLP_PASS=$((_SLP_PASS + 1)) ;;
    FAIL) _SLP_FAIL=$((_SLP_FAIL + 1)) ;;
    NOT_FOUND) _SLP_NOT_FOUND=$((_SLP_NOT_FOUND + 1)) ;;
    ERROR) _SLP_ERROR=$((_SLP_ERROR + 1)) ;;
    *) _SLP_ERROR=$((_SLP_ERROR + 1)) ;;
  esac
}
slp_result_aggregation() {
  local _slp_policy _slp_rc
  if [[ $_SLP_NOT_FOUND -gt 0 || $_SLP_ERROR -gt 0 ]]; then
    _slp_policy=UNEVALUATED
    _slp_rc=1
  elif [[ $_SLP_FAIL -gt 0 ]]; then
    _slp_policy=NONCOMPLIANT
    _slp_rc=0
  else
    _slp_policy=COMPLIANT
    _slp_rc=0
  fi
  printf "SLP-SUMMARY-V1\\tTOTAL=%s\\tPASS=%s\\tFAIL=%s\\tNOT_FOUND=%s\\tERROR=%s\\tPOLICY_STATUS=%s\\n" "$_SLP_TOTAL" "$_SLP_PASS" "$_SLP_FAIL" "$_SLP_NOT_FOUND" "$_SLP_ERROR" "$_slp_policy"
  return "$_slp_rc"
}
'''
    if role=='target_preflight':
        dq='\\"'
        return f'''slp_target_preflight() {{
  local _slp_id= _slp_version= _slp_arch= _slp_k _slp_v
  while IFS='=' read -r _slp_k _slp_v; do
    case "$_slp_k" in
      ID) _slp_id=${{_slp_v#{dq}}}; _slp_id=${{_slp_id%{dq}}} ;;
      VERSION_ID) _slp_version=${{_slp_v#{dq}}}; _slp_version=${{_slp_version%{dq}}} ;;
    esac
  done < /etc/os-release
  _slp_arch=$(/usr/bin/uname -m)
  if [[ $_slp_id == ubuntu && $_slp_version == 24.04 && $_slp_arch == x86_64 ]]; then
    return 0
  fi
  printf "%s\\n" "UNSUPPORTED_PLATFORM" >&2
  return 3
}}
'''
    if role=='main_dispatch':
        calls=[]
        for rr in ctx['runtime_rows']:
            if rr['runtime_phase']=='target_preflight':
                calls += ['  slp_target_preflight','  _slp_rc=$?','  if [[ $_slp_rc -ne 0 ]]; then return "$_slp_rc"; fi','  slp_result_reset']
            elif rr['runtime_phase']=='control':
                fn=ctx['control_fn_by_id'][rr['control_id']]
                calls += [f'  _slp_line=$({fn})','  slp_emit_record "$_slp_line"','  slp_result_record "$_slp_line"']
            elif rr['runtime_phase']=='aggregation':
                calls += ['  slp_result_aggregation','  return $?']
            else:raise RuntimeError('runtime phase')
        return '''slp_main_dispatch() {
  local _slp_rc _slp_line
  slp_cli_rc "$@"
  _slp_rc=$?
  if [[ $_slp_rc -ne 0 ]]; then return "$_slp_rc"; fi
  case "$_SLP_ACTION" in
    help) slp_help; return 0 ;;
    build_info) slp_build_info; return 0 ;;
    provenance) slp_provenance_query "$_SLP_PROVENANCE_FILTER"; return 0 ;;
    policy) : ;;
    *) return 1 ;;
  esac
'''+('\n'.join(calls))+'\n}\nslp_main_dispatch "$@"\nexit $?\n'
    raise RuntimeError('unknown engineering role '+role)

def build(root:str,staging:str,mode:str,build_inputs_lock_rel:str|None=None)->dict:
    if os.environ!={k:v for k,v in ALLOWED_ENV.items()}:
        raise RuntimeError('environment does not equal accepted sanitized map')
    root=os.path.normpath(os.path.abspath(root));staging=os.path.realpath(staging)
    if not os.path.isabs(root) or not os.path.isabs(staging):raise RuntimeError('absolute root/staging required')
    if os.path.commonpath([root,staging])==root:raise RuntimeError('staging inside project root')
    if not os.path.isdir(staging):raise RuntimeError('staging root missing')
    if os.listdir(staging):raise RuntimeError('staging root must be empty')
    data=read_exact_inputs(root)
    self_path=os.path.join(root,*CANDIDATE_CANONICAL_PATH.split('/'))
    with open(self_path,'rb') as f:self_bytes=f.read()
    builder_sha=sha_bytes(self_bytes)

    contract=data['step7b0/BUILD-CONTRACT-v0.9.3.md'].decode('utf-8')
    if 'build_contract_version = 0.9.3' not in contract or BUILD_CONTRACT_ID not in contract:raise RuntimeError('contract identity text mismatch')
    benv=json.loads(data['step7b0/phase-a/contracts/build-environment-v1.json'])
    if benv['contract_id']!='build-environment-v1' or benv['sanitized_environment']!=ALLOWED_ENV:raise RuntimeError('build environment mismatch')
    if benv['project_root']!='read-only' or benv['staging_root']!='explicit-external-empty':raise RuntimeError('build boundary mismatch')
    expected_invocation={'argv_prefix':['/usr/bin/python3','-I','-S','-B'],'builder_cli_args_binding':'exact-mode-specific-builder-cli-follows-script-operand','canonical_flags':['-I','-S','-B'],'executable_absolute_path':'/usr/bin/python3','path_selection_authority':'absolute-only-no-PATH','script_operand_binding':'exact-admitted-or-frozen-builder-source-as-next-argv-element'}
    if benv.get('interpreter_invocation')!=expected_invocation:raise RuntimeError('build interpreter invocation mismatch')
    sem=json.loads(data['step7b0/phase-a/contracts/check-semantic-v1.json'])
    cli=json.loads(data['step7b0/phase-a/contracts/cli-rc-v1.json'])
    target=json.loads(data['step7b0/phase-a/contracts/target-ubuntu-24.04-x86_64-v1.json'])
    ro=json.loads(data['step7b0/phase-a/contracts/readonly-command-policy-v1.json'])
    if sem['semantic_contract_id']!='check-semantic-v1' or target['target_id']!=TARGET_ID:raise RuntimeError('semantic/target mismatch')
    if not {'assignment','command-substitution'}.issubset(set(ro['allowed_shell_constructs'])):raise RuntimeError('readonly command policy missing required constructs')
    if '--apply' not in cli['forbidden'] or '--restore' not in cli['forbidden']:raise RuntimeError('mutating CLI not forbidden')

    lock_rows=parse_tsv(data['step7b0/phase-a/STEP7B0-CONTROL-SET.lock'])
    manifest_rows=parse_tsv(data['controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv'])
    bindings=parse_tsv(data['step7b0/phase-a/registries/BUILD-BINDINGS.tsv'])
    eng_bind=parse_tsv(data['step7b0/phase-a/registries/ENGINEERING-BINDINGS.tsv'])
    eng_contracts=json.loads(data['step7b0/phase-a/contracts/engineering-contracts-v1.json'])['engineering_contracts']
    nodes=parse_tsv(data['step7b0/phase-a/registries/EMISSION-NODES.tsv'])
    edges=parse_tsv(data['step7b0/phase-a/registries/EMISSION-EDGES.tsv'])
    runtime_rows=parse_tsv(data['step7b0/phase-a/registries/RUNTIME-INVOCATIONS.tsv'])
    if len(lock_rows)!=5 or len(bindings)!=5 or len(runtime_rows)!=7:raise RuntimeError('closed row counts mismatch')
    control_paths=[r['canonical_control_path'] for r in lock_rows]
    controls={p:parse_control(data[p]) for p in control_paths}
    byid={c['id']:c for c in controls.values()}
    if set(byid)!=set(r['control_id'] for r in lock_rows):raise RuntimeError('control set mismatch')
    man_by_id={r['control_id']:r for r in manifest_rows}
    for lr in lock_rows:
        c=byid[lr['control_id']];mr=man_by_id.get(c['id'])
        if c['index_id']!=lr['index_id'] or not mr:raise RuntimeError('control index/manifest mismatch')
        if mr['index_id']!=c['index_id'] or mr['key']!=c['key'] or int(mr['expected'])!=c['expected_value']:raise RuntimeError('manifest control projection mismatch')
        if mr['sha256']!=EXPECTED_INPUT_SHA256[lr['canonical_control_path']]:raise RuntimeError('manifest control hash mismatch')
        if c['layer']!='fstec-core' or c['parameter_kind']!='sysctl' or c['parameter_locator']!='sysctl' or c['expected_op']!='eq' or c['expected_type']!='integer' or c['apply_supported'] is not False:raise RuntimeError('control eligibility mismatch')

    adapter_contract=json.loads(data['step7b0/phase-a/adapter/sysctl-check-adapter-v1.json'])
    if adapter_contract['implementation_sha256']!=EXPECTED_INPUT_SHA256['step7b0/phase-a/adapter/sysctl-check-adapter-v1.py']:raise RuntimeError('adapter identity mismatch')
    adapter=load_adapter(data['step7b0/phase-a/adapter/sysctl-check-adapter-v1.py'])
    if adapter.get('ADAPTER_ID')!=adapter_contract['adapter_id'] or adapter.get('TARGET_ID')!=TARGET_ID:raise RuntimeError('adapter source constants mismatch')
    control_fn_by_id={};fstec_body={}
    for cid in sorted(byid,key=lambda s:s.encode()):
        c=byid[cid]
        src=adapter['shell_function'](cid,c['key'],c['expected_value'])
        first=src.splitlines()[0]
        m=re.fullmatch(r'([A-Za-z0-9_]+)\(\) \{',first)
        if not m:raise RuntimeError('adapter function framing')
        control_fn_by_id[cid]=m.group(1);fstec_body[cid]=src

    role_by_block={}
    eng_by_role={r['role']:r for r in eng_bind}
    contract_by_role={r['engineering_role']:r for r in eng_contracts}
    for role,r in eng_by_role.items():
        if r['emission_kind']=='runtime-block':
            bid=f"engineering-contract::{r['engineering_contract_id']}::{r['block_role']}::{TARGET_ID}"
            role_by_block[bid]=role
            cc=contract_by_role.get(role)
            if not cc or cc['engineering_contract_id']!=r['engineering_contract_id'] or str(cc['contract_version'])!=str(r['contract_version']):raise RuntimeError('engineering contract resolution')

    provenance=[]
    for cid in sorted(byid,key=lambda s:s.encode()):
        c=byid[cid]
        provenance.append({'control_id':cid,'layer':c['layer'],'index_id':c['index_id'],'doc_id':c['doc_id'],'source_locator':c['source_locator'],'quote_sha256':c['quote_sha256'],'execution_block_id':f'fstec-control::{cid}::check::{TARGET_ID}','adapter_id':adapter_contract['adapter_id'],'adapter_contract_version':adapter_contract['adapter_contract_version'],'target_id':TARGET_ID})

    emission_order=topo_order(nodes,edges)
    if set(emission_order)!={r['block_id'] for r in nodes} or len(emission_order)!=12:raise RuntimeError('emission closure')
    if role_by_block.get(emission_order[-1])!='main_dispatch':raise RuntimeError('main_dispatch not last')
    runtime_rows=sorted(runtime_rows,key=lambda r:int(r['runtime_sequence']))
    if [int(r['runtime_sequence']) for r in runtime_rows]!=list(range(1,8)):raise RuntimeError('runtime sequence')
    ctx={'contract_sha':BUILD_CONTRACT_SHA256,'builder_sha':builder_sha,'provenance_records':provenance,'runtime_rows':runtime_rows,'control_fn_by_id':control_fn_by_id}

    bodies={}
    for bid in emission_order:
        if bid.startswith('fstec-control::'):
            cid=bid.split('::')[1];bodies[bid]=fstec_body[cid]
        else:bodies[bid]=eng_body(role_by_block[bid],ctx)
    block_blob={bid:block_bytes(bid,bodies[bid]) for bid in emission_order}

    template=data['step7b0/phase-a/serializer/securelinux-policy-check.sh.tmpl'].decode('utf-8')
    if template.count('{{SLP_SLOT:MANIFEST_SHA256_HEADER}}')!=1 or template.count('{{SLP_SLOT:GENERATED_BLOCKS}}')!=1:raise RuntimeError('template placeholders')
    placeholder='# BUILD-MANIFEST-SHA256: '+'_'*64
    generated=b''.join(block_blob[bid] for bid in emission_order).decode('utf-8')
    scaffold_text='#!/bin/bash\n'+template.replace('{{SLP_SLOT:MANIFEST_SHA256_HEADER}}',placeholder).replace('{{SLP_SLOT:GENERATED_BLOCKS}}','')
    script_placeholder=('#!/bin/bash\n'+template.replace('{{SLP_SLOT:MANIFEST_SHA256_HEADER}}',placeholder).replace('{{SLP_SLOT:GENERATED_BLOCKS}}',generated)).encode('utf-8')
    if b'\r' in script_placeholder or not script_placeholder.endswith(b'\n'):raise RuntimeError('script LF')
    line_cursor=1
    line_ranges={}
    # launcher + template prefix before generated placeholder determine first block line
    prefix=('#!/bin/bash\n'+template.replace('{{SLP_SLOT:MANIFEST_SHA256_HEADER}}',placeholder).split('{{SLP_SLOT:GENERATED_BLOCKS}}')[0]).encode('utf-8')
    line_cursor=prefix.count(b'\n')+1
    for bid in emission_order:
        n=block_blob[bid].count(b'\n');line_ranges[bid]=(line_cursor,line_cursor+n-1);line_cursor+=n
    script_line_count=script_placeholder.count(b'\n')
    launcher_sha=sha_bytes(b'#!/bin/bash\n')
    scaffolding_sha=sha_bytes(scaffold_text.encode('utf-8'))

    blocks=[]
    for bid in emission_order:
        ls,le=line_ranges[bid]
        if bid.startswith('fstec-control::'):
            cid=bid.split('::')[1];c=byid[cid]
            rec={'origin_type':'fstec-control','origin_id':cid,'control_id':cid,'block_id':bid,'block_role':'control_check','target_id':TARGET_ID,'line_start':ls,'line_end':le,'block_sha256':sha_bytes(block_blob[bid]),'semantic_contract_id':'check-semantic-v1','adapter_id':adapter_contract['adapter_id'],'adapter_contract_version':adapter_contract['adapter_contract_version'],'layer':c['layer'],'index_id':c['index_id'],'doc_id':c['doc_id'],'source_locator':c['source_locator'],'quote_sha256':c['quote_sha256']}
        else:
            role=role_by_block[bid];er=eng_by_role[role]
            rec={'origin_type':'engineering-contract','origin_id':er['engineering_contract_id'],'engineering_contract_id':er['engineering_contract_id'],'engineering_contract_version':er['contract_version'],'engineering_role':role,'block_id':bid,'block_role':er['block_role'],'target_id':TARGET_ID,'line_start':ls,'line_end':le,'block_sha256':sha_bytes(block_blob[bid])}
        blocks.append(rec)

    if mode=='measurement':
        if build_inputs_lock_rel is not None:raise RuntimeError('measurement mode forbids BUILD-INPUTS.lock input')
        # NON-RELEASE measurement sentinel: this manifest is measurement output only and is not eligible for final admission.
        build_inputs_lock_sha=MEASUREMENT_LOCK_SENTINEL
    elif mode=='final':
        if not build_inputs_lock_rel:raise RuntimeError('final mode requires accepted BUILD-INPUTS.lock canonical path')
        parts=build_inputs_lock_rel.split('/')
        if build_inputs_lock_rel.startswith('/') or any(x in ('','.','..') for x in parts) or parts[-1]!='BUILD-INPUTS.lock':raise RuntimeError('invalid BUILD-INPUTS.lock canonical path')
        lockp=os.path.join(root,*parts)
        with open(lockp,'rb') as f:build_inputs_lock_sha=sha_bytes(f.read())
    else:raise RuntimeError('mode')

    manifest={'manifest_contract_version':'build-manifest-v1','build_contract_id':BUILD_CONTRACT_ID,'build_contract_version':BUILD_CONTRACT_VERSION,'build_contract_sha256':BUILD_CONTRACT_SHA256,'artifact_name':'securelinux-policy-check.sh','artifact_role':'read-only-check','target_id':TARGET_ID,'builder_id':BUILDER_ID,'builder_sha256':builder_sha,'build_inputs_lock_sha256':build_inputs_lock_sha,'build_environment_contract_id':benv['contract_id'],'build_environment_contract_version':str(benv['version']),'build_environment_contract_sha256':EXPECTED_INPUT_SHA256['step7b0/phase-a/contracts/build-environment-v1.json'],'control_set_lock_sha256':EXPECTED_INPUT_SHA256['step7b0/phase-a/STEP7B0-CONTROL-SET.lock'],'template_sha256':EXPECTED_INPUT_SHA256['step7b0/phase-a/serializer/securelinux-policy-check.sh.tmpl'],'launcher_contract_id':eng_by_role['launcher']['engineering_contract_id'],'launcher_contract_version':eng_by_role['launcher']['contract_version'],'launcher_line':1,'launcher_sha256':launcher_sha,'script_line_count':script_line_count,'scaffolding_sha256':scaffolding_sha,'emission_block_ids':emission_order,'runtime_invocation_block_ids':[r['block_id'] for r in runtime_rows],'blocks':blocks}
    manifest_bytes=cjson(manifest);manifest_sha=sha_bytes(manifest_bytes)
    final_header=('# BUILD-MANIFEST-SHA256: '+manifest_sha).encode('utf-8')
    placeholder_bytes=placeholder.encode('utf-8')
    if script_placeholder.count(placeholder_bytes)!=1:raise RuntimeError('manifest placeholder uniqueness')
    script_bytes=script_placeholder.replace(placeholder_bytes,final_header,1)
    if len(script_bytes)!=len(script_placeholder) or script_bytes.count(b'\n')!=script_line_count:raise RuntimeError('header replacement changed layout')
    script_sha=sha_bytes(script_bytes)
    sums=[]
    for name,dig in sorted([('BUILD-MANIFEST.json',manifest_sha),('securelinux-policy-check.sh',script_sha)],key=lambda x:x[0].encode()):sums.append(f'{dig}  {name}\n')
    sums_bytes=''.join(sums).encode('utf-8')

    outputs=[('BUILD-MANIFEST.json',manifest_bytes,0o644),('BUILD-SHA256',sums_bytes,0o644),('securelinux-policy-check.sh',script_bytes,0o755)]
    for name,b,modebits in outputs:
        p=os.path.join(staging,name)
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,modebits)
        try:
            with os.fdopen(fd,'wb') as f:f.write(b)
        except Exception:
            try:os.close(fd)
            except OSError:pass
            raise
        os.chmod(p,modebits)
    return {'status':CANDIDATE_STATUS,'mode':mode,'builder_sha256':builder_sha,'build_inputs_lock_sha256':build_inputs_lock_sha,'script_sha256':script_sha,'manifest_sha256':manifest_sha,'build_sha256_sha256':sha_bytes(sums_bytes),'measurement_project_input_count':len(EXPECTED_INPUT_SHA256)+1}

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--project-root',required=True)
    ap.add_argument('--staging-root',required=True)
    g=ap.add_mutually_exclusive_group(required=True);g.add_argument('--measurement',action='store_true');g.add_argument('--final',action='store_true')
    ap.add_argument('--build-inputs-lock')
    a=ap.parse_args();mode='measurement' if a.measurement else 'final'
    result=build(a.project_root,a.staging_root,mode,a.build_inputs_lock)
    for k in sorted(result,key=lambda s:s.encode()):print(f'{k.upper()}={result[k]}')
    return 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:
        print('PHASE_B_CANDIDATE_FAIL='+type(e).__name__+':'+str(e),file=sys.stderr);raise SystemExit(1)
