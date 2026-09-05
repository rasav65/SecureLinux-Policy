#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, re, tempfile
from pathlib import Path

REGISTRY_REL = "product/APPLY-KIND-REGISTRY.tsv"
ARCH_REL = "product/contracts/src0001-apply/architecture-v1.json"
EXPECTED_REGISTRY_FIELDS = (
    "apply_kind", "target_class", "architecture_id", "architecture_path", "architecture_sha256",
)
EXPECTED_IMPLEMENTATION_REGISTRY_FIELDS = (
    "apply_kind", "composition_contract_id", "adapter_id", "binding_path",
    "binding_sha256", "implementation_path", "implementation_sha256",
)
EXPECTED_IDENTITY = {
    "architecture_id": "src0001-local-account-password-state-apply-modular-v1",
    "source_row": "SRC-0001",
    "control_id": "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE",
    "apply_kind": "local-account-password-lock",
    "target_class": "shadow-password-field",
    "definition_reuse_scope": "SRC0001_SOURCE_LOCAL_UNTIL_SECOND_PROVEN_USE_CASE",
}
EXPECTED_BINDINGS = {
    "parent_schema": (
        "urn:securelinux-policy-v3:apply-semantic-contract:v1",
        "product/contracts/apply-semantic-contract-v1.schema.json",
    ),
    "flat_candidate": (
        "local-account-password-state-apply-semantic-v1",
        "product/contracts/local-account-password-state-apply-semantic-v1.json",
    ),
    "check_population_authority": (
        "local-account-password-state-check-semantic-v2",
        "product/contracts/local-account-password-state-check-semantic-v2.json",
    ),
    "composition_schema": (
        "urn:securelinux-policy-v3:src0001-apply-composition:v1",
        "product/contracts/src0001-apply/composition-v1.schema.json",
    ),
}
EXPECTED_ROLE_BINDINGS = (
    ("predicate", "src0001-empty-second-shadow-field-predicate-v1", "product/contracts/src0001-apply/predicate-empty-second-shadow-field-v1.json"),
    ("transform", "src0001-empty-second-shadow-field-to-bang-transform-v1", "product/contracts/src0001-apply/transform-empty-second-shadow-field-to-bang-v1.json"),
    ("snapshot_precondition", "src0001-external-snapshot-precondition-v1", "product/contracts/src0001-apply/snapshot-precondition-v1.json"),
    ("lock_reread", "src0001-account-db-lock-reread-v1", "product/contracts/src0001-apply/lock-reread-v1.json"),
    ("object_identity", "src0001-shadow-object-identity-v1", "product/contracts/src0001-apply/object-identity-v1.json"),
    ("metadata_preservation", "src0001-shadow-metadata-preservation-v1", "product/contracts/src0001-apply/metadata-preservation-v1.json"),
    ("atomic_transaction", "src0001-shadow-atomic-transaction-v1", "product/contracts/src0001-apply/atomic-transaction-v1.json"),
    ("dry_run_report", "src0001-dry-run-report-v1", "product/contracts/src0001-apply/dry-run-report-v1.json"),
)
EXPECTED_CLOSED_ROLES = tuple(role for role, _definition_id, _path in EXPECTED_ROLE_BINDINGS)
EXPECTED_PENDING_ROLES = ()
EXPECTED_DEFINITION_SHA256 = {
    "predicate": "9e531762d11504f4832a5ea8bb736ea63d5720b92ec2f15f3055018eddaf81ec",
    "transform": "606d5c68824bcfd09a209966e2c2e60210df83f105ad36592211e2a1ddd5b9bc",
    "snapshot_precondition": "4ce1dd93c27dcdf112c7de9b8b6b4bfbd5456f0085d4c86ddb9130233cd2991a",
    "lock_reread": "d37a252ccdc60444369a9949e5b34d35203949efa9d214c77559ee60a8b8c328",
    "object_identity": "ae4c372d296871d43d513b09f9dd5d6ac30c8387adc032a877ab163cea59185a",
    "metadata_preservation": "b380cb242f8b4141301cc196b5f2abf4e09373b90886ac94a7dcd8d899fb990c",
    "atomic_transaction": "a171356ea7521e52be5883cff8f785ac12a95857b5e950094aa615e0472e5ee4",
    "dry_run_report": "aa9e57dc2533fa95b4e2de87f8ba9aeec098b7bf5b439fbb96c6645b44a7eaaf",
}


def sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def load_json_regular(root: Path, rel: str) -> dict:
    path=root/rel
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"missing/non-regular JSON: {rel}")
    return json.loads(path.read_text(encoding='utf-8'))


def load_architecture(root: Path) -> dict:
    item=load_json_regular(root, ARCH_REL)
    for key,value in EXPECTED_IDENTITY.items():
        if item.get(key) != value:
            raise RuntimeError(f"architecture identity mismatch {key}: {item.get(key)!r}")
    bindings=item.get('bindings')
    if not isinstance(bindings,dict) or set(bindings) != set(EXPECTED_BINDINGS):
        raise RuntimeError('architecture binding population mismatch')
    for name,(expected_id,rel) in EXPECTED_BINDINGS.items():
        rec=bindings[name]
        if rec.get('id') != expected_id or rec.get('path') != rel:
            raise RuntimeError(f"architecture binding identity mismatch: {name}")
        target=root/rel
        if not target.is_file() or target.is_symlink():
            raise RuntimeError(f"bound file missing/non-regular: {rel}")
        actual=sha256_file(target)
        if rec.get('sha256') != actual:
            raise RuntimeError(f"stale architecture binding: {name}")
    flat=bindings['flat_candidate']
    if flat.get('status') != 'REVISE_INPUT_NOT_FINAL_AUTHORITY':
        raise RuntimeError('flat candidate status must remain REVISE input')

    roles=item.get('definition_roles')
    if not isinstance(roles,list) or len(roles) != len(EXPECTED_ROLE_BINDINGS):
        raise RuntimeError('definition role population mismatch')
    actual_roles=[]
    for rec,(role,definition_id,rel) in zip(roles,EXPECTED_ROLE_BINDINGS):
        if rec.get('role') != role or rec.get('definition_id') != definition_id or rec.get('path') != rel:
            raise RuntimeError(f'definition role identity mismatch: {role}')
        state=rec.get('state')
        target=root/rel
        if role not in EXPECTED_CLOSED_ROLES or state != 'CLOSED':
            raise RuntimeError(f'closed definition role state mismatch: {role}')
        digest=rec.get('sha256')
        if digest != EXPECTED_DEFINITION_SHA256[role]:
            raise RuntimeError(f'closed definition expected SHA mismatch: {role}')
        if not target.is_file() or target.is_symlink():
            raise RuntimeError(f'closed definition missing/non-regular: {rel}')
        if sha256_file(target) != digest:
            raise RuntimeError(f'stale definition binding: {role}')
        actual_roles.append(role)
    if tuple(actual_roles) != tuple(role for role, _definition_id, _path in EXPECTED_ROLE_BINDINGS):
        raise RuntimeError('definition role order mismatch')
    progress=item.get('definition_progress')
    if progress != {'closed_roles':list(EXPECTED_CLOSED_ROLES),'pending_roles':list(EXPECTED_PENDING_ROLES)}:
        raise RuntimeError('definition progress mismatch')

    predicate=load_json_regular(root, EXPECTED_ROLE_BINDINGS[0][2])
    transform=load_json_regular(root, EXPECTED_ROLE_BINDINGS[1][2])
    pred_binding=transform.get('predicate_binding')
    expected_pred_binding={
        'definition_id': EXPECTED_ROLE_BINDINGS[0][1],
        'path': EXPECTED_ROLE_BINDINGS[0][2],
        'sha256': sha256_file(root/EXPECTED_ROLE_BINDINGS[0][2]),
    }
    if pred_binding != expected_pred_binding:
        raise RuntimeError('transform predicate binding stale/mismatched')
    if predicate.get('definition_id') != EXPECTED_ROLE_BINDINGS[0][1]:
        raise RuntimeError('predicate definition identity mismatch')
    if transform.get('definition_id') != EXPECTED_ROLE_BINDINGS[1][1]:
        raise RuntimeError('transform definition identity mismatch')

    snapshot=load_json_regular(root, EXPECTED_ROLE_BINDINGS[2][2])
    expected_snapshot={
        'control_id':'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE',
        'definition_class':'APPLY_SNAPSHOT_PRECONDITION',
        'definition_id':'src0001-external-snapshot-precondition-v1',
        'definition_version':1,
        'evidence':{
            'carrier':'CALLER_SUPPLIED_READ_ONLY_JSON_FILE',
            'claim_strength':'EXTERNAL_OPERATOR_ATTESTATION_NOT_PROVIDER_CRYPTOGRAPHIC_PROOF',
            'constraints':{
                'attestation_version':1,
                'control_id':'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE',
                'host_identity_format':'LOWERCASE_HEX_32',
                'host_identity_source':'/etc/machine-id',
                'prestate_sha256_format':'LOWERCASE_HEX_64',
                'provider':'NONEMPTY_UTF8_NO_C0_OR_DEL',
                'rollback_capable':True,
                'snapshot_id':'NONEMPTY_UTF8_NO_C0_OR_DEL',
                'snapshot_scope':'FULL_TARGET_HOST_OR_VM',
                'source_row':'SRC-0001',
                'state':'READY',
                'target_path':'/etc/shadow',
            },
            'format':'SLP-EXTERNAL-SNAPSHOT-ATTESTATION-V1',
            'parsing':{'duplicate_json_keys':'REJECT','top_level':'OBJECT_ONLY','unknown_fields':'REJECT','utf8':'REQUIRED'},
            'required_negative_fixtures':[{'case': 'MISSING_HOST_IDENTITY', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'MISSING_PRESTATE_SHA256', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'UNKNOWN_TOP_LEVEL_FIELD', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'DUPLICATE_TOP_LEVEL_KEY', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'HOST_IDENTITY_WRONG_JSON_TYPE', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'HOST_IDENTITY_BAD_FORMAT', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'HOST_IDENTITY_MISMATCH', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'PRESTATE_SHA256_WRONG_JSON_TYPE', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'PRESTATE_SHA256_BAD_FORMAT', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'PRESTATE_SHA256_MISMATCH', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'STATE_NOT_READY', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'ROLLBACK_CAPABLE_FALSE', 'expected': 'ABORT_NO_MUTATION'}, {'case': 'INVALID_PROVIDER_OR_SNAPSHOT_ID', 'expected': 'ABORT_NO_MUTATION'}],
            'wire_contract':{'additional_properties': False, 'properties': {'attestation_version': {'const': 1, 'type': 'integer'}, 'control_id': {'const': 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE', 'type': 'string'}, 'host_identity': {'binding': 'EXACT_TRIMMED_MACHINE_ID_BYTES', 'pattern': '^[0-9a-f]{32}$', 'type': 'string'}, 'prestate_sha256': {'binding': 'SHA256_EXACT_FILE_BYTES:/etc/shadow', 'pattern': '^[0-9a-f]{64}$', 'type': 'string'}, 'provider': {'constraint': 'NONEMPTY_UTF8_NO_C0_OR_DEL', 'type': 'string'}, 'rollback_capable': {'const': True, 'type': 'boolean'}, 'snapshot_id': {'constraint': 'NONEMPTY_UTF8_NO_C0_OR_DEL', 'type': 'string'}, 'snapshot_scope': {'const': 'FULL_TARGET_HOST_OR_VM', 'type': 'string'}, 'source_row': {'const': 'SRC-0001', 'type': 'string'}, 'state': {'const': 'READY', 'type': 'string'}, 'target_path': {'const': '/etc/shadow', 'type': 'string'}}, 'required': ['attestation_version', 'control_id', 'host_identity', 'prestate_sha256', 'provider', 'rollback_capable', 'snapshot_id', 'snapshot_scope', 'source_row', 'state', 'target_path'], 'type': 'object'},
        },
        'failure':{
            'error_value_contract':'domain:reason',
            'invalid_evidence':'ABORT_NO_MUTATION',
            'literal_dash_for_error':False,
            'mismatched_evidence':'ABORT_NO_MUTATION',
            'missing_evidence':'ABORT_NO_MUTATION',
            'provider_state_not_ready':'ABORT_NO_MUTATION',
        },
        'precondition':{
            'comparison_time':'BEFORE_ANY_HOST_MUTATION',
            'host_identity_binding':'EXACT_TRIMMED_MACHINE_ID_BYTES',
            'required_before_host_mutation':True,
            'target_prestate_binding':'SHA256_EXACT_FILE_BYTES',
        },
        'recovery_model':{
            'failed_uncommitted_apply':'TRANSACTION_LOCAL_COMPENSATION_ONLY',
            'product_creates_snapshot':False,
            'product_restores_snapshot':False,
            'successful_apply_recovery':'EXTERNAL_SNAPSHOT_ROLLBACK_ONLY',
            'user_invokable_restore':False,
        },
        'source_row':'SRC-0001',
        'target':{'path':'/etc/shadow','prestate_digest':'SHA256_EXACT_FILE_BYTES'},
        'target_class':'shadow-password-field',
    }
    if snapshot != expected_snapshot:
        raise RuntimeError('snapshot precondition semantic mismatch')

    lock_reread=load_json_regular(root, EXPECTED_ROLE_BINDINGS[3][2])
    expected_lock_reread={'control_id': 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE', 'definition_class': 'APPLY_LOCK_REREAD', 'definition_id': 'src0001-account-db-lock-reread-v1', 'definition_version': 1, 'failure': {'error_value_contract': 'domain:reason', 'literal_dash_for_error': False, 'lock_acquisition_failure': 'ABORT_NO_MUTATION', 'lock_interrupted_or_timeout': 'ABORT_NO_MUTATION', 'reread_failure': 'ABORT_NO_MUTATION', 'stale_prestate': 'ABORT_NO_MUTATION'}, 'lock': {'authority': 'LIBC_LCKPWDF_PASSWORD_DATABASE_LOCK', 'api': 'lckpwdf(3)', 'release_api': 'ulckpwdf(3)', 'documented_lock_file': '/etc/.pwd.lock', 'success_return': 0, 'failure_return': -1, 'acquisition_timeout': 'LIBC_DEFINED_15_SECONDS', 'mode': 'EXCLUSIVE', 'scope': ['/etc/passwd', '/etc/shadow'], 'interoperability': 'SERIALIZES_WITH_PASSWORD_DATABASE_WRITERS_THAT_HONOR_LCKPWDF', 'noncooperating_direct_writers': 'NOT_SERIALIZED_BY_LCKPWDF', 'acquire_before': 'UNDER_LOCK_REREAD_AND_ANY_HOST_MUTATION', 'hold_until': 'APPLY_TRANSACTION_TERMINAL_STATE', 'product_owned_additional_account_db_lock': 'FORBIDDEN'}, 'predicate_binding': {'definition_id': 'src0001-empty-second-shadow-field-predicate-v1', 'path': 'product/contracts/src0001-apply/predicate-empty-second-shadow-field-v1.json', 'sha256': '9e531762d11504f4832a5ea8bb736ea63d5720b92ec2f15f3055018eddaf81ec'}, 'reread': {'input_paths': ['/etc/passwd', '/etc/shadow'], 'under_lock': True, 'bytes': 'EXACT_FILE_BYTES', 'recompute_check_population': 'EXACT_CURRENT_CHECK_SEMANTIC_V2', 'recompute_target_set': 'BOUND_PREDICATE_OVER_BOUND_CHECK_POPULATION', 'prelock_reference': {'input_file_sha256': [{'path': '/etc/passwd', 'digest': 'SHA256_EXACT_FILE_BYTES'}, {'path': '/etc/shadow', 'digest': 'SHA256_EXACT_FILE_BYTES'}], 'selected_record_keys': 'EXACT_ORDERED_USERNAME_BYTE_SEQUENCE'}, 'comparator': {'all_input_file_sha256': 'EXACT_EQUAL_BY_PATH', 'selected_record_keys': 'EXACT_EQUAL', 'object_identity_role': 'src0001-shadow-object-identity-v1'}, 'final_precommit_revalidation': {'required': True, 'input_file_sha256': 'EXACT_EQUAL_BY_PATH', 'selected_record_keys': 'EXACT_EQUAL', 'target_object_identity': 'EXACT_EQUAL', 'failure': 'ABORT_NO_MUTATION'}}, 'snapshot_precondition_binding': {'definition_id': 'src0001-external-snapshot-precondition-v1', 'path': 'product/contracts/src0001-apply/snapshot-precondition-v1.json', 'sha256': '4ce1dd93c27dcdf112c7de9b8b6b4bfbd5456f0085d4c86ddb9130233cd2991a'}, 'source_row': 'SRC-0001', 'stale_state': {'any_comparator_mismatch': 'ABORT_NO_MUTATION', 'mutation_before_comparator_pass': False, 'retry_policy': 'NEW_APPLY_ATTEMPT_REQUIRES_FRESH_CHECK_AND_SNAPSHOT_ATTESTATION'}, 'target_class': 'shadow-password-field'}
    if lock_reread != expected_lock_reread:
        raise RuntimeError('lock/reread semantic mismatch')
    object_identity=load_json_regular(root, EXPECTED_ROLE_BINDINGS[4][2])
    expected_object_identity={'control_id': 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE', 'definition_class': 'APPLY_OBJECT_IDENTITY', 'definition_id': 'src0001-shadow-object-identity-v1', 'definition_version': 1, 'failure': {'error_value_contract': 'domain:reason', 'literal_dash_for_error': False, 'hardlink_ambiguity': 'ABORT_NO_MUTATION', 'identity_drift': 'ABORT_NO_MUTATION', 'nonregular_target': 'ABORT_NO_MUTATION', 'symlink_or_path_resolution_ambiguity': 'ABORT_NO_MUTATION'}, 'identity': {'capture_points': ['PRELOCK', 'UNDER_LOCK_PREMUTATION'], 'parent': {'path': '/etc', 'lstat_type': 'DIRECTORY', 'symlink': 'FORBIDDEN', 'identity_tuple': ['st_dev', 'st_ino'], 'open_binding': 'DIRECTORY_FD_NOFOLLOW_EQUIVALENT'}, 'target': {'path': '/etc/shadow', 'lstat_type': 'REGULAR_FILE', 'symlink': 'FORBIDDEN', 'st_nlink': 1, 'identity_tuple': ['st_dev', 'st_ino', 'st_nlink'], 'open_binding': 'NOFOLLOW_FD_WITH_FSTAT_IDENTITY_MATCH'}, 'comparator': {'parent_identity': 'EXACT_EQUAL', 'target_identity': 'EXACT_EQUAL'}}, 'path_replacement_boundary': {'before_own_commit': 'FORBIDDEN', 'external_replace_between_capture_points': 'STALE_ABORT_NO_MUTATION', 'own_atomic_replace': 'DEFINED_ONLY_BY_BOUND_ATOMIC_TRANSACTION_ROLE'}, 'source_row': 'SRC-0001', 'target_class': 'shadow-password-field', 'use_after_verification': {'precommit_source_reads': 'VERIFIED_UNDER_LOCK_TARGET_FD_ONLY', 'unverified_path_reopen_before_commit': 'FORBIDDEN'}}
    if object_identity != expected_object_identity:
        raise RuntimeError('object identity semantic mismatch')

    comp=item.get('composition_contract')
    if comp != {
        'id':'local-account-password-state-apply-composition-v1',
        'path':'product/contracts/src0001-apply/composition-v1.json',
        'state':'CLOSED',
    }:
        raise RuntimeError('composition closed-state mismatch')
    impl=item.get('implementation_binding')
    if not isinstance(impl,dict) or impl.get('model') != 'SEPARATE_REGISTRY':
        raise RuntimeError('implementation binding model mismatch')
    if impl.get('registry_path') != 'product/APPLY-IMPLEMENTATION-REGISTRY.tsv':
        raise RuntimeError('implementation registry path mismatch')
    if impl.get('registry_state') != 'PRESENT':
        raise RuntimeError('implementation registry state mismatch')
    if tuple(impl.get('required_fields') or ()) != EXPECTED_IMPLEMENTATION_REGISTRY_FIELDS:
        raise RuntimeError('implementation registry required fields mismatch')
    return item


def expected_composition(root: Path, architecture: dict) -> dict:
    bindings={}
    for rec in architecture['definition_roles']:
        bindings[rec['role']]={
            'definition_id':rec['definition_id'],
            'path':rec['path'],
            'sha256':rec['sha256'],
        }
    return {
        'composition_contract_id':'local-account-password-state-apply-composition-v1',
        'composition_contract_version':1,
        'contract_class':'APPLY_COMPOSITION',
        'source_row':'SRC-0001',
        'control_id':'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE',
        'apply_kind':'local-account-password-lock',
        'target_class':'shadow-password-field',
        'architecture_binding':{
            'architecture_id':architecture['architecture_id'],
            'path':ARCH_REL,
            'sha256':sha256_file(root/ARCH_REL),
        },
        'parent_contract_binding':{
            'semantic_contract_id':'local-account-password-state-apply-semantic-v1',
            'path':'product/contracts/local-account-password-state-apply-semantic-v1.json',
            'sha256':'48e008ac5cd7da8e17dac3f5cef556cb9def3ba36051e4623bc2255ca3c312be',
        },
        'check_population_authority_binding':{
            'semantic_contract_id':'local-account-password-state-check-semantic-v2',
            'path':'product/contracts/local-account-password-state-check-semantic-v2.json',
            'sha256':'8351b4431f8f6ddd403afb4315cf2f8b5ebcf3f8d9c38f91bb3778e5086593cc',
        },
        'definition_bindings':bindings,
        'compatibility_chain':architecture['compatibility_chain'],
        'postcondition':{
            'check_contract_id':'local-account-password-state-check-semantic-v2',
            'required_compliance':'PASS',
            'idempotent_reapply':'NO_MUTATION',
        },
    }


def canonical_json_text(item: dict) -> str:
    return json.dumps(item,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n'


def expected_registry(root: Path, architecture: dict) -> str:
    digest=sha256_file(root/ARCH_REL)
    row=(architecture['apply_kind'],architecture['target_class'],architecture['architecture_id'],ARCH_REL,digest)
    return '\t'.join(EXPECTED_REGISTRY_FIELDS)+'\n'+'\t'.join(row)+'\n'


def atomic_write(path: Path, text: str) -> None:
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.', dir=str(path.parent))
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as f:
            f.write(text); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(),0o644)
        os.replace(tmp,path)
        dfd=os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    except Exception:
        try: os.unlink(tmp)
        except FileNotFoundError: pass
        raise


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--project-root',required=True)
    mode=ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check',action='store_true')
    mode.add_argument('--write',action='store_true')
    args=ap.parse_args()
    root=Path(args.project_root).resolve()
    if not (root/'.git').is_dir() and not (root/REGISTRY_REL).parent.is_dir():
        raise RuntimeError('project root required')
    architecture=load_architecture(root)
    expected=expected_registry(root,architecture)
    expected_comp=canonical_json_text(expected_composition(root,architecture))
    registry=root/REGISTRY_REL
    composition=root/architecture['composition_contract']['path']
    if args.check:
        if not composition.is_file() or composition.is_symlink():
            raise RuntimeError('composition contract missing/non-regular')
        if composition.read_text(encoding='utf-8') != expected_comp:
            raise RuntimeError('composition contract binding is stale')
        if not registry.is_file() or registry.is_symlink():
            raise RuntimeError('APPLY registry missing/non-regular')
        if registry.read_text(encoding='utf-8') != expected:
            raise RuntimeError('APPLY registry binding is stale')
        print('APPLY_BINDING_ACTION=CHECK')
    else:
        atomic_write(composition,expected_comp)
        atomic_write(registry,expected)
        if composition.read_text(encoding='utf-8') != expected_comp:
            raise RuntimeError('composition contract write verification failed')
        if registry.read_text(encoding='utf-8') != expected:
            raise RuntimeError('APPLY registry write verification failed')
        print('APPLY_BINDING_ACTION=WRITE')
    print('APPLY_BINDING_ARCHITECTURES=1')
    print('APPLY_BINDING_CLOSED_DEFINITIONS=8')
    print('APPLY_BINDING_PENDING_DEFINITIONS=0')
    print('APPLY_BINDING_RESULT=PASS')
    return 0

if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'APPLY_BINDING_RESULT=FAIL: {exc}', file=__import__('sys').stderr)
        raise SystemExit(1)
