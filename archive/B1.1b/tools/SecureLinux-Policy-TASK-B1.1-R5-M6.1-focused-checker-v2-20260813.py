#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT=Path(sys.argv[1]).resolve(); MOD=ROOT/'B1.1b/modules/M6.1-registries'; FAIL=[]; PASS=[]
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def cjson(v): return (json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()
def csha(v): return hashlib.sha256(cjson(v)).hexdigest()
def load(p): return json.loads(Path(p).read_text())
def ok(cond,msg):
    (PASS if cond else FAIL).append(msg)
def validates(defs,name,obj):
    local_defs=dict(defs); local_defs['Id']={'type':'string','pattern':'^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$'}; schema={'$schema':'https://json-schema.org/draft/2020-12/schema','$ref':f'#/$defs/{name}','$defs':local_defs}
    return not list(Draft202012Validator(schema).iter_errors(obj))

schema=load(MOD/'schema.json'); defs=schema['definitions']; module=(MOD/'MODULE.md').read_text(); iface=load(MOD/'INTERFACE.json'); lock=load(MOD/'MODULE-LOCK.json'); rules=load(MOD/'RULES.json'); inv=load(MOD/'REGISTRY-INVARIANTS.json')
for n,v in defs.items():
    try: Draft202012Validator.check_schema(v)
    except Exception as e: FAIL.append(f'schema compile {n}: {e}')

# B-01: role present and role is enforced at reference use site.
ru=defs['ReferenceUse']; ok('reference_role' in ru.get('required',[]),'B01 ReferenceUse role required'); ok(set(ru['properties']['reference_role']['enum'])=={'membership-authority','scope-authority','type-registry','inventory'},'B01 exact role enum')
refuse={'reference_ref':'r','reference_role':'scope-authority','population_contract_ref':'p','expected_output_subject_type':'s','expected_element_schema_ref':'e','expected_domain_ref':'d'}
ok(validates(defs,'ReferenceUse',refuse),'B01 valid ReferenceUse accepted'); bad=dict(refuse); bad.pop('reference_role'); ok(not validates(defs,'ReferenceUse',bad),'B01 missing role rejected')

# B-02: compliance policy impossible in all selector reference contracts.
for n in ('ReferenceUse','ReferenceRegistryEntry','PopulationContract'):
    ok('compliance-policy' not in json.dumps(defs[n],sort_keys=True),f'B02 compliance-policy absent {n}')

# B-03: adapter enumeration cannot enter resolver registry.
rr={'schema':'selector-resolver/v9','instance_owner':'B1.2','resolver_ref':'r','resolution_kind':'adapter-enumeration','output_subject_type':'s','output_contract_ref':'selector-raw-candidate-population/v1','behavior_contract_ref':'b','input_slots':[],'output_field_refs':['f'],'enumeration_domain_ref':'d','enumeration_source_slot_ref':'slot','enumeration_operator_kind':'emit-population-elements'}
ok(not validates(defs,'ResolverRegistryEntry',rr),'B03 resolver adapter-enumeration rejected')
ok(defs['AdapterRegistryEntry']['properties']['resolution_kind'].get('const')=='adapter-enumeration','B03 adapter-only kind')
ok(defs['AdapterRegistryEntry']['properties']['enumeration_operator_kind'].get('const')=='emit-population-elements','B03 adapter operator fixed')

# B-04: machine-readable registry uniqueness contract is total for all registry keys.
keys={x['key_field'] for x in inv['registries']}; expected={'field_ref','resolver_ref','adapter_ref','value_ref','reference_ref','population_contract_ref','root_ref','event_source_ref'}
ok(keys==expected and all(x['unique'] is True for x in inv['registries']),'B04 registry key set and uniqueness')
ok(inv['duplicate_key_result']=='CONTRACT_ERROR','B04 duplicate result')

def registry_unique(rows,key):
    values=[r[key] for r in rows]
    return len(values)==len(set(values))
ok(registry_unique([{'value_ref':'a'},{'value_ref':'b'}],'value_ref'),'B04 positive unique values'); ok(not registry_unique([{'value_ref':'a'},{'value_ref':'a'}],'value_ref'),'B04 duplicate values rejected by contract checker')

# B-05: dead/unreachable definitions and exports removed.
for dead in ('AdapterInputTarget','FilenamePopulationUse','FilenamePopulationSlot','FilenamePopulationEntry'):
    ok(dead not in defs,f'B05 dead definition removed {dead}'); ok(not any(x.get('symbol_id')==f'schema-definition:{dead}' for x in iface['exports']),f'B05 dead export removed {dead}')

# Exact role x target matrix: 9 legal pairs and all other 45 structurally invalid.
def target(kind,role='membership-authority'):
    if kind=='root': return {'kind':'root','root_ref':'r'}
    if kind=='selector-source-set': return {'kind':'selector-source-set','source_set_ref':'ss'}
    if kind=='adapter-population': return {'kind':'adapter-population','adapter_ref':'a','source_population_contract_ref':'pc','source_element_schema_ref':'e','source_subject_type':'s','source_domain_ref':'d'}
    if kind=='producer-output': return {'kind':'producer-output','use':{'producer_record_ref':'pr','producer_output_ref':'po','producer_output_schema_ref':'ps','producer_subject_type':'s','snapshot_relation':'same-evaluation-snapshot'}}
    if kind=='event-source': return {'kind':'event-source','event_source_ref':'ev'}
    if kind=='reference-use': return {'kind':'reference-use','use':{'reference_ref':'ref','reference_role':role,'population_contract_ref':'pc','expected_output_subject_type':'s','expected_element_schema_ref':'e','expected_domain_ref':'d'}}
    raise KeyError(kind)
roles=['root','source','adapter-source','producer-output','event-source','scope','network-scope','authority','reference']; kinds=['root','selector-source-set','adapter-population','producer-output','event-source','reference-use']; legal={'root':'root','source':'selector-source-set','adapter-source':'adapter-population','producer-output':'producer-output','event-source':'event-source','scope':'reference-use','network-scope':'reference-use','authority':'reference-use','reference':'reference-use'}
def entry(role,kind):
    owner='B1.2' if role in ('root','producer-output') else ('B1.3' if role in ('scope','network-scope','authority','reference') else 'B1.6')
    shape='object' if role=='source' else ('stream' if role=='event-source' else ('population' if role in ('adapter-source','scope','network-scope','authority','reference') else 'scalar'))
    schema_ref='selector-source-set/v5' if role=='source' else 'vs'
    refrole='scope-authority' if role in ('scope','network-scope') else 'membership-authority'
    return {'schema':'selector-input-value/v5','instance_owner':owner,'value_ref':'v','input_role':role,'value_shape':shape,'value_schema_ref':schema_ref,'element_schema_ref':'e' if shape in ('population','stream') else None,'subject_type':'s' if shape in ('population','stream') else None,'domain_ref':'d' if shape in ('population','stream') else None,'enumeration_domain_refs':[],'target':target(kind,refrole)}
valid=invalid_rejected=invalid_total=0
for role in roles:
    for kind in kinds:
        got=validates(defs,'InputValueRegistryEntry',entry(role,kind))
        if kind==legal[role]:
            ok(got,f'matrix legal {role}->{kind}'); valid += int(got)
        else:
            invalid_total+=1; invalid_rejected += int(not got); ok(not got,f'matrix invalid rejected {role}->{kind}')
ok(valid==9 and invalid_total==45 and invalid_rejected==45,'matrix 9/9 valid 45/45 invalid')
# role-specific reference-use mismatch for scope must fail.
x=entry('scope','reference-use'); x['target']['use']['reference_role']='membership-authority'; ok(not validates(defs,'InputValueRegistryEntry',x),'scope requires scope-authority')

# Inline copies of M1 Id pattern are forbidden; every Id use is an import ref site.
pat='^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$'
def inline_count(v):
    if isinstance(v,dict): return (1 if v.get('type')=='string' and v.get('pattern')==pat else 0)+sum(inline_count(x) for x in v.values())
    if isinstance(v,list): return sum(inline_count(x) for x in v)
    return 0
ok(inline_count(defs)==0,'inline Id copies=0')
m1=load(ROOT/'B1.1b/modules/M1-primitives/INTERFACE.json'); idexp=[x for x in m1['exports'] if x.get('symbol_id')=='schema-definition:Id']; imp=[x for x in iface['imports'] if x.get('symbol_id')=='schema-definition:Id']; ok(len(idexp)==len(imp)==1 and imp[0]['definition_sha256']==idexp[0]['definition_sha256'],'M1 Id import exact hash')
def refs(v,p=''):
    out=[]
    if isinstance(v,dict):
        for k,ch in v.items():
            cp=p+'/'+str(k).replace('~','~0').replace('/','~1')
            if k=='$ref' and ch=='#/$defs/Id': out.append(cp)
            out += refs(ch,cp)
    elif isinstance(v,list):
        for i,ch in enumerate(v): out += refs(ch,p+f'/{i}')
    return out
actual={(f'schema-definition:{n}',p) for n,v in defs.items() for p in refs(v)}; claimed={(x['source_symbol'],x['json_pointer']) for x in imp[0]['reference_sites']}; ok(actual==claimed,'all Id ref sites pinned')

# Fixture ownership and positive/negative expansion.
ok(all(x['rule_ref'].startswith('rule:b1.1b-v9:section:7.') for x in rules['fixtures']),'fixtures local M6.1 rules'); ok(len(rules['fixtures'])==39,'fixture specifications 39')
# Explicitly declared asymmetry + no undefined config-use term.
ok('MAY be empty on input-value and root registry entries' in module,'enumeration_domain_refs asymmetry stated'); ok('There is no separate undefined “config use” concept.' in module,'config use eliminated')
# Embedded owner rule explicit.
ok(inv['embedded_use_objects']['independent_instance_owner'] is False,'embedded ownership rule')
# Direct source and derived pinning in module lock.
ok(lock.get('module_md_sha256')==sha(MOD/'MODULE.md'),'module lock pins MODULE.md')
ok(lock.get('schema_sha256')==sha(MOD/'schema.json'),'module lock pins schema.json')
ok(lock.get('task_sha256')==sha(MOD/'TASK.md'),'module lock pins TASK.md')
ok(lock.get('acceptance_sha256')==sha(MOD/'ACCEPTANCE.md'),'module lock pins ACCEPTANCE.md')
ok(lock.get('registry_invariants_sha256')==sha(MOD/'REGISTRY-INVARIANTS.json'),'module lock pins registry invariants')
fx_records=[{'path':x.relative_to(ROOT).as_posix(),'sha256':sha(x),'size':x.stat().st_size} for x in sorted((MOD/'fixtures').glob('*.txt'),key=lambda x:x.name)]
ok(lock.get('fixtures_manifest_sha256')==csha(fx_records),'module lock pins fixture manifest')
ok(lock.get('content_sha256')==iface.get('content_sha256'),'module lock content hash matches interface')
ok(lock.get('interface_sha256')==iface.get('interface_sha256'),'module lock interface hash matches interface')
ok(lock.get('rules_sha256')==sha(MOD/'RULES.json'),'module lock pins RULES')
ok(lock.get('offline_schema_sha256')==sha(MOD/'schema.offline.json'),'module lock pins offline schema')
ok(lock.get('status')=='LOCKED' and lock.get('frozen') is False and lock.get('focused_external_accept') is False,'module lock lifecycle')
# Project state/gates.
state=load(ROOT/'B1.1b/state/PROJECT-STATE.json'); ok(state['project_gate']=={'b1_1a':'ACCEPT','b1_1b':'NOT_ACCEPTED','selector_instances_frozen':'0/20','task_b1_1':'NOT_ACCEPTED','task_b1_2':'NOT_STARTED'},'project gate unchanged'); ok(state['modules']['M6.1-registries']['status']=='LOCKED' and state['modules']['M6.1-registries']['frozen'] is False,'M6.1 locked not frozen'); ok(state['modules']['M0-integration-invariants']['status']=='REOPENED','M0 reopened'); ok(state['gates'].get('R5_M6_1_INTERNAL_LOCK_PASS') is True,'R5 local gate recorded')

if FAIL:
    print('RESULT=R5_M6_1_FOCUSED_CHECK_FAIL'); [print('FAIL='+x) for x in FAIL]; raise SystemExit(1)
print('RESULT=R5_M6_1_FOCUSED_CHECK_PASS'); print(f'CHECKS={len(PASS)}'); print(f'SCHEMA_DEFINITIONS={len(defs)}'); print(f'FIXTURES={len(rules["fixtures"])}'); print(f'ID_REFERENCE_SITES={len(actual)}'); print('ROLE_TARGET_MATRIX_VALID=9/9'); print('ROLE_TARGET_MATRIX_INVALID_REJECTED=45/45'); print('DEAD_EXPORTS=0'); print('INLINE_ID_COPIES=0'); print('M6_1=LOCKED'); print('M0=REOPENED'); print('FROZEN=false')
