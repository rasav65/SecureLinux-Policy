#!/usr/bin/env python3
from __future__ import annotations
import argparse,glob,json,os,re,sys
from pathlib import Path
from collections import Counter
PARSER_IMPLEMENTATION_VERSION='3.2-r4-final-meta-failclosed'
WRITE_OPEN_FLAGS={'O_WRONLY','O_RDWR','O_CREAT','O_TRUNC','O_APPEND','O_TMPFILE'}
NETWORK={'socket','socketpair','connect','accept','accept4','bind','listen','sendto','sendmsg','sendmmsg','recvfrom','recvmsg','recvmmsg','shutdown','setsockopt','getsockopt'}
WRITE={'write','writev','pwrite64','pwritev','pwritev2'}
OPEN={'open','openat','openat2','creat'}
DIRECT_PATH_RO={'stat','lstat','access','readlink','statfs','getxattr','lgetxattr','listxattr','llistxattr'}
DIRFD_PATH_RO={'newfstatat','statx','faccessat','faccessat2','readlinkat'}
FD_PATH_RO={'fstat','fstatfs','fgetxattr','flistxattr'}
XATTR_READ={'getxattr','lgetxattr','fgetxattr','listxattr','llistxattr','flistxattr'}
MUTATE_DIRECT={'rename','renameat','renameat2','unlink','unlinkat','link','linkat','symlink','symlinkat','mkdir','mkdirat','rmdir','mknod','mknodat','chown','fchown','fchownat','lchown','truncate','ftruncate','mount','umount2','setxattr','lsetxattr','fsetxattr','removexattr','lremovexattr','fremovexattr','sethostname','setdomainname','settimeofday','clock_settime'}
SIMPLE_BOOTSTRAP={'read','pread64','readv','close','lseek','getcwd','brk','mprotect','munmap','rt_sigaction','rt_sigprocmask','rt_sigreturn','sigaltstack','arch_prctl','set_tid_address','set_robust_list','rseq','prlimit64','getrlimit','getuid','geteuid','getgid','getegid','getpid','getppid','gettid','uname','getrandom','futex','sched_getaffinity','getcpu','clock_gettime','clock_getres','clock_nanosleep','nanosleep','dup','dup2','dup3','pipe','pipe2','poll','ppoll','select','pselect6','epoll_create1','epoll_ctl','epoll_wait','eventfd2','wait4','waitid','restart_syscall','sysinfo','close_range'}
PROCESS_CREATE={'clone','clone3','fork','vfork'}
PROCESS_EXIT={'exit','exit_group'}
VMA={'mmap','mremap','madvise','membarrier'}
IOCTL_QUERY={'TCGETS','TIOCGWINSZ'}
IOCTL_LOCAL_BOOTSTRAP={'FIOCLEX'}
FCNTL_QUERY={'F_GETFD'}
MADVISE_FORBID={'MADV_REMOVE','MADV_HWPOISON','MADV_SOFT_OFFLINE'}

SECURITY_PROPERTIES=[
 'project_root_immutable','writes_only_declared_staging_or_capture_sinks','network_dependency_absent',
 'undeclared_exec_absent','project_dependency_set_exact','process_tree_complete','external_dependencies_inventoried'
]
EFFECT_SCOPES={
 'process_memory_local','thread_synchronization_local','process_signal_state_local',
 'process_fd_metadata_query_local','process_identity_query','process_resource_query'
}
HARD_FAIL_EXACT_MIN={
 'add_key','bpf','capset','chroot','delete_module','finit_module','fsconfig','fsmount','fsopen','init_module','kcmp',
 'kexec_file_load','kexec_load','keyctl','memfd_create','mount','mount_setattr','move_mount','name_to_handle_at',
 'open_by_handle_at','open_tree','perf_event_open','personality','pivot_root','process_vm_readv','process_vm_writev',
 'ptrace','quotactl','reboot','request_key','seccomp','setfsgid','setfsuid','setgid','setgroups','setns','setregid',
 'setresgid','setresuid','setreuid','setuid','syslog','umount2','unshare','userfaultfd'
}
HARD_FAIL_PREFIX_MIN={'io_uring_','landlock_','pidfd_'}
LOCAL_INVARIANT_EVENTS={
 'arch_prctl','brk','close','fcntl','getrandom','gettid','ioctl','lseek','mmap','mprotect','munmap',
 'prlimit64','rseq','rt_sigaction','set_robust_list','set_tid_address'
}
INVARIANT_EVENT_NAMES=(OPEN|WRITE|DIRECT_PATH_RO|DIRFD_PATH_RO|FD_PATH_RO|NETWORK|MUTATE_DIRECT|PROCESS_CREATE|PROCESS_EXIT|
 {'getdents64','execve','execveat','chdir','fchdir','chmod','fchmod','fchmodat','mmap'}|LOCAL_INVARIANT_EVENTS)


class ParseFailure(ValueError): pass

def fail(kind): raise ParseFailure(kind)

def strip_prefix(line):
    s=line.rstrip('\n')
    s=re.sub(r'^\[pid\s+\d+\]\s+','',s.strip())
    return s

def split_call(line):
    s=strip_prefix(line)
    if not s: return ('blank',None,None,None)
    low=s.lower()
    if 'trace truncated' in low or '<unfinished ...>' in s or re.search(r'<\.\.\.\s+\w+ resumed>',s): fail('trace_loss_or_truncation')
    m=re.fullmatch(r'\+\+\+ exited with (\d+) \+\+\+',s)
    if m: return ('meta-exit',None,None,m.group(1))
    m=re.fullmatch(r'\+\+\+ killed by (SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+',s)
    if m: return ('meta-killed',None,None,m.group(1))
    if s.startswith('--- SIG') and s.endswith(' ---'): return ('meta-signal',None,None,s)
    if s.startswith('strace: Process '): fail('observer_meta_uncertainty')
    m=re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\(',s)
    if not m: fail('parser_uncertainty')
    name=m.group(1); start=m.end(); depth=1; quote=False; esc=False; angle=0; i=start
    while i < len(s):
        c=s[i]
        if quote:
            if esc: esc=False
            elif c=='\\': esc=True
            elif c=='"': quote=False
        else:
            if c=='"': quote=True
            elif c=='<': angle+=1
            elif c=='>' and angle: angle-=1
            elif not angle:
                if c=='(': depth+=1
                elif c==')':
                    depth-=1
                    if depth==0: break
        i+=1
    if i>=len(s) or depth!=0 or quote or angle: fail('parser_uncertainty')
    args=s[start:i]
    tail=s[i+1:].strip()
    if not tail.startswith('='): fail('parser_uncertainty')
    ret=tail[1:].strip()
    if not ret: fail('parser_uncertainty')
    return ('syscall',name,args,ret)

def split_args(args):
    out=[]; start=0; quote=False;esc=False; angle=0; stack=[]
    pairs={')':'(',']':'[','}':'{'}
    for i,c in enumerate(args):
        if quote:
            if esc: esc=False
            elif c=='\\': esc=True
            elif c=='"': quote=False
            continue
        if c=='"': quote=True; continue
        if c=='<': angle+=1; continue
        if c=='>' and angle: angle-=1; continue
        if angle: continue
        if c in '([{': stack.append(c); continue
        if c in ')]}':
            if not stack or stack[-1]!=pairs[c]: fail('parser_uncertainty')
            stack.pop(); continue
        if c==',' and not stack:
            out.append(args[start:i].strip()); start=i+1
    if quote or angle or stack: fail('parser_uncertainty')
    out.append(args[start:].strip())
    return out

_ESC={'\\':92,'"':34,'n':10,'t':9,'r':13,'f':12,'v':11,'b':8,'a':7}
def decode_fragment(raw):
    b=bytearray();i=0
    while i<len(raw):
        c=raw[i]
        if c!='\\':
            b.extend(c.encode('utf-8'));i+=1;continue
        i+=1
        if i>=len(raw): fail('undecodable_args')
        c=raw[i]
        if c in _ESC: b.append(_ESC[c]);i+=1;continue
        if c in '01234567':
            j=i
            while j<len(raw) and j<i+3 and raw[j] in '01234567': j+=1
            val=int(raw[i:j],8)
            if val>255: fail('undecodable_args')
            b.append(val);i=j;continue
        fail('undecodable_args')
    return bytes(b)

def decode_path_token(tok):
    s=tok.strip()
    if not s.startswith('"'): fail('undecodable_args')
    i=1; raw=[]; esc=False
    while i<len(s):
        c=s[i]
        if esc:
            raw.append('\\'+c);esc=False;i+=1;continue
        if c=='\\': esc=True;i+=1;continue
        if c=='"': break
        raw.append(c);i+=1
    if i>=len(s) or s[i]!='"' or esc: fail('undecodable_args')
    tail=s[i+1:].strip()
    if tail.startswith('...'): fail('undecodable_args')
    if tail: fail('parser_uncertainty')
    data=decode_fragment(''.join(raw))
    if b'\x00' in data: fail('undecodable_args')
    try: text=data.decode('utf-8','strict')
    except UnicodeDecodeError: fail('undecodable_args')
    return text

def decode_annotation(raw):
    data=decode_fragment(raw)
    if b'\x00' in data: fail('undecodable_args')
    try: text=data.decode('utf-8','strict')
    except UnicodeDecodeError: fail('undecodable_args')
    deleted=False
    if text.endswith(' (deleted)'):
        text=text[:-10];deleted=True
    if text.startswith('/'):
        # strace -yy may append nested device metadata inside the outer FD annotation,
        # e.g. 0</dev/null<char 1:3>>. Strip only the closed char/block suffix form.
        m=re.fullmatch(r'(.+)<(char|block) ([0-9]+):([0-9]+)>',text)
        device=None
        if m:
            text=m.group(1)
            if not text.startswith('/'): fail('uncertain_attribution')
            device={'kind':m.group(2),'major':int(m.group(3)),'minor':int(m.group(4))}
        return {'kind':'path','path':text,'deleted':deleted,'device':device}
    for prefix in ('pipe:[','socket:[','anon_inode:[','memfd:','net:['):
        if text.startswith(prefix): return {'kind':'nonpath','label':text}
    return {'kind':'nonpath','label':text}

def parse_fd_token(tok):
    s=tok.strip()
    m=re.fullmatch(r'(AT_FDCWD|-?\d+)(?:<(.*)>)?',s)
    if not m: return None
    fd=m.group(1); ann=decode_annotation(m.group(2)) if m.group(2) is not None else None
    return {'fd':fd,'annotation':ann}

def ret_fd(ret):
    # accept leading integer with optional -yy annotation, followed by any errno/flags text
    m=re.match(r'^(-?\d+)(?:<(.*)>)?(?:\s|$)',ret)
    if not m: return None
    ann=decode_annotation(m.group(2)) if m.group(2) is not None else None
    return {'fd':int(m.group(1)),'annotation':ann}

def canon(path,base=None):
    if '\x00' in path: fail('undecodable_args')
    if not os.path.isabs(path):
        if not base or not os.path.isabs(base): fail('uncertain_attribution')
        path=os.path.join(base,path)
    return os.path.realpath(os.path.normpath(path))

def under(path,root):
    try:return os.path.commonpath([path,root])==root
    except Exception:return False

def path_from_direct(tok,cwd): return canon(decode_path_token(tok),cwd)
def path_from_dirfd(fd_tok,path_tok,cwd):
    text=decode_path_token(path_tok)
    if os.path.isabs(text): return canon(text)
    fd=parse_fd_token(fd_tok)
    if not fd: fail('uncertain_attribution')
    if fd['fd']=='AT_FDCWD':
        ann=fd['annotation']
        base=canon(ann['path']) if ann and ann.get('kind')=='path' else cwd
    else:
        ann=fd['annotation']
        if not ann or ann.get('kind')!='path': fail('uncertain_attribution')
        base=canon(ann['path'])
    return canon(text,base)

def fd_path(tok):
    fd=parse_fd_token(tok)
    if not fd or not fd['annotation'] or fd['annotation'].get('kind')!='path': return None
    return canon(fd['annotation']['path'])

def all_fd_paths(tokens):
    out=[]
    for tok in tokens:
        f=parse_fd_token(tok)
        if f and f['annotation'] and f['annotation'].get('kind')=='path':
            p=canon(f['annotation']['path'])
            if p not in out: out.append(p)
    return out

def flags_present(text):
    return {f for f in WRITE_OPEN_FLAGS if re.search(r'(?<![A-Za-z0-9_])'+re.escape(f)+r'(?![A-Za-z0-9_])',text)}

def decode_string_token(tok):
    return decode_path_token(tok)

def parse_string_array(tok):
    z=tok.strip()
    if not (z.startswith('[') and z.endswith(']')): fail('undecodable_args')
    inner=z[1:-1].strip()
    if inner=='': return []
    vals=split_args(inner)
    return [decode_string_token(v) for v in vals]

def classify_syscall(name,args,ret,ctx):
    toks=split_args(args)
    pr=ctx['project_root']; sr=ctx['staging_root']; cwd=ctx['cwd']
    paths=[]
    def add(p):
        if p and p not in paths: paths.append(p)
    if name in NETWORK: return {'event':name,'class':'forbidden-network','paths':paths}
    if name in OPEN:
        if name=='open' or name=='creat':
            if len(toks)<1: fail('undecodable_args')
            inp=path_from_direct(toks[0],cwd)
        else:
            if len(toks)<2: fail('undecodable_args')
            inp=path_from_dirfd(toks[0],toks[1],cwd)
        add(inp)
        write_open=(name=='creat') or bool(flags_present(args))
        rf=ret_fd(ret)
        success=rf is not None and rf['fd']>=0
        resolved=None
        if success and rf['annotation'] and rf['annotation'].get('kind')=='path': resolved=canon(rf['annotation']['path'])
        if resolved: add(resolved)
        if write_open:
            target=resolved if success else inp
            if success and resolved is None: fail('uncertain_attribution')
            if target and sr and under(target,sr): return {'event':name,'class':'allowed-staging-write-open','paths':paths}
            return {'event':name,'class':'forbidden-write-open','paths':paths}
        return {'event':name,'class':'readonly','family':'filesystem-read','paths':paths}
    if name in WRITE:
        if not toks: fail('uncertain_attribution')
        f=parse_fd_token(toks[0])
        if not f or f['fd']=='AT_FDCWD': fail('uncertain_attribution')
        fd=int(f['fd'])
        if fd in (1,2):
            ann=f.get('annotation')
            expected=(ctx.get('stdout_sink_label') if fd==1 else ctx.get('stderr_sink_label'))
            if not expected or not ann or ann.get('kind')!='nonpath' or ann.get('label')!=expected: fail('uncertain_stdio_sink')
            return {'event':name,'class':'allowed-stdio-write','family':'declared-sink-write','paths':paths}
        p=canon(f['annotation']['path']) if f['annotation'] and f['annotation'].get('kind')=='path' else None
        add(p)
        if p and sr and under(p,sr): return {'event':name,'class':'allowed-staging-write','paths':paths}
        if p is not None: return {'event':name,'class':'forbidden-write','paths':paths}
        if f['annotation'] and f['annotation'].get('kind')=='nonpath': return {'event':name,'class':'forbidden-write-sink','paths':paths}
        fail('uncertain_attribution')
    if name in {'chmod','fchmodat'}:
        if name=='chmod':
            if not toks: fail('undecodable_args')
            p=path_from_direct(toks[0],cwd)
        else:
            if len(toks)<2: fail('undecodable_args')
            p=path_from_dirfd(toks[0],toks[1],cwd)
        add(p)
        if sr and under(p,sr): return {'event':name,'class':'allowed-staging-mode','paths':paths}
        return {'event':name,'class':'forbidden-mutation','paths':paths}
    if name=='fchmod':
        if not toks: fail('uncertain_attribution')
        p=fd_path(toks[0]); add(p)
        if p and sr and under(p,sr): return {'event':name,'class':'allowed-staging-mode','paths':paths}
        if p is None: fail('uncertain_attribution')
        return {'event':name,'class':'forbidden-mutation','paths':paths}
    if name in MUTATE_DIRECT:
        # Explicitly forbidden in Step 7B.0 current candidate slice; path attribution still collected where possible.
        return {'event':name,'class':'forbidden-mutation','paths':paths}
    if name in DIRECT_PATH_RO:
        if not toks: fail('undecodable_args')
        p=path_from_direct(toks[0],cwd);add(p)
        return {'event':name,'class':'readonly','family':'filesystem-read','paths':paths}
    if name in DIRFD_PATH_RO:
        if len(toks)<2: fail('undecodable_args')
        p=path_from_dirfd(toks[0],toks[1],cwd);add(p)
        return {'event':name,'class':'readonly','family':'filesystem-read','paths':paths}
    if name in FD_PATH_RO:
        if not toks: fail('undecodable_args')
        f=parse_fd_token(toks[0])
        if not f or f['fd']=='AT_FDCWD' or not f.get('annotation'): fail('uncertain_attribution')
        ann=f['annotation']
        if ann.get('kind')=='path':
            p=canon(ann['path']);add(p)
            return {'event':name,'class':'readonly','family':'filesystem-read','paths':paths}
        if ann.get('kind')=='nonpath':
            fd=int(f['fd'])
            if fd in (1,2):
                expected=(ctx.get('stdout_sink_label') if fd==1 else ctx.get('stderr_sink_label'))
                if not expected or ann.get('label')!=expected: fail('uncertain_stdio_sink')
                return {'event':name,'class':'readonly','family':'declared-sink-metadata-query','paths':paths}
            return {'event':name,'class':'unclassified','family':'fd-metadata-query-nonpath','paths':paths}
        fail('uncertain_attribution')
    if name=='getdents64':
        if not toks: fail('uncertain_attribution')
        p=fd_path(toks[0])
        if p is None: fail('uncertain_attribution')
        add(p)
        if pr and under(p,pr): fail('project_directory_enumeration')
        return {'event':name,'class':'readonly','family':'directory-enumeration','paths':paths}
    if name in PROCESS_CREATE:
        rf=ret_fd(ret)
        if rf and rf['fd']>0: ctx['child_pids'].add(rf['fd'])
        return {'event':name,'class':'unresolved-invariant','family':'process-create','paths':paths}
    if name in {'execve','execveat'}:
        if name=='execve':
            if len(toks)<2: fail('undecodable_args')
            p=path_from_direct(toks[0],cwd); argv=parse_string_array(toks[1])
        else:
            if len(toks)<3: fail('undecodable_args')
            p=path_from_dirfd(toks[0],toks[1],cwd); argv=parse_string_array(toks[2])
        add(p)
        expected=list(ctx.get('allowed_initial_argv_prefix') or ['/usr/bin/python3','-I','-S','-B'])
        if not ctx['initial_exec_seen'] and ctx.get('is_root_trace') and p==ctx.get('allowed_initial_exec'):
            if argv[:len(expected)]!=expected: fail('initial_interpreter_argv_mismatch')
            ctx['initial_exec_seen']=True
            return {'event':name,'class':'readonly','family':'initial-exec','paths':paths}
        return {'event':name,'class':'forbidden-exec','paths':paths}
    if name in PROCESS_EXIT:
        if not toks: fail('undecodable_args')
        m=re.match(r'^(-?\d+)$',toks[0])
        if not m: fail('undecodable_args')
        code=int(m.group(1))
        if code!=0: fail('nonzero_process_exit')
        return {'event':name,'class':'readonly','family':'process-exit','paths':paths}
    if name=='mmap':
        if len(toks)!=6: fail('undecodable_args')
        prot=toks[2].strip(); flags=toks[3].strip(); fd=parse_fd_token(toks[4])
        if not prot or not flags or not fd or fd['fd']=='AT_FDCWD': fail('undecodable_args')
        shared='MAP_SHARED' in flags or 'MAP_SHARED_VALIDATE' in flags
        writable='PROT_WRITE' in prot
        anonymous='MAP_ANONYMOUS' in flags
        fdnum=int(fd['fd'])
        p=None
        if not anonymous and fdnum >= 0:
            ann=fd.get('annotation')
            if not ann or ann.get('kind')!='path': fail('uncertain_attribution')
            p=canon(ann['path']); add(p)
        elif anonymous:
            if fdnum != -1: fail('uncertain_attribution')
        if shared and writable:
            if p and sr and under(p,sr):
                return {'event':name,'class':'allowed-staging-shared-mmap-write','family':'process-vma','paths':paths}
            if p is None: fail('uncertain_attribution')
            return {'event':name,'class':'forbidden-shared-mmap-write','paths':paths}
        return {'event':name,'class':'readonly','family':'process-vma','paths':paths}
    if name=='mremap':
        if len(toks)<4: fail('undecodable_args')
        flagtext=toks[3]
        toksf=[x.strip() for x in flagtext.split('|')]
        allowed={'0','MREMAP_MAYMOVE','MREMAP_FIXED','MREMAP_DONTUNMAP'}
        if any(x not in allowed for x in toksf): fail('undecodable_args')
        if 'MREMAP_FIXED' in toksf and len(toks)<5: fail('undecodable_args')
        return {'event':name,'class':'readonly','family':'process-vma','paths':paths}
    if name=='madvise':
        if len(toks)<3: fail('undecodable_args')
        advice=toks[2].strip()
        if advice in MADVISE_FORBID:return {'event':name,'class':'forbidden-vma-file-mutation','paths':paths}
        allowed={'MADV_NORMAL','MADV_RANDOM','MADV_SEQUENTIAL','MADV_WILLNEED','MADV_DONTNEED','MADV_FREE','MADV_COLD','MADV_PAGEOUT','MADV_HUGEPAGE','MADV_NOHUGEPAGE','MADV_MERGEABLE','MADV_UNMERGEABLE','MADV_WIPEONFORK','MADV_KEEPONFORK','MADV_POPULATE_READ','MADV_POPULATE_WRITE'}
        if advice not in allowed: fail('undecodable_args')
        return {'event':name,'class':'readonly','family':'process-vma','paths':paths}
    if name=='membarrier':
        if not toks: fail('undecodable_args')
        cmd=toks[0].strip()
        allowed={'MEMBARRIER_CMD_QUERY','MEMBARRIER_CMD_GLOBAL','MEMBARRIER_CMD_GLOBAL_EXPEDITED','MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED','MEMBARRIER_CMD_PRIVATE_EXPEDITED','MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED','MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE','MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE','MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ','MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ'}
        if cmd not in allowed: fail('undecodable_args')
        return {'event':name,'class':'readonly','family':'process-memory-barrier','paths':paths}
    if name=='ioctl':
        if len(toks)<2: fail('undecodable_args')
        f=parse_fd_token(toks[0])
        if not f or f['fd']=='AT_FDCWD' or not f.get('annotation'): fail('uncertain_attribution')
        fd=int(f['fd']); ann=f['annotation']; op=toks[1].strip()
        if ann.get('kind')=='path':
            p=canon(ann['path']); add(p)
            if fd==0 and ctx.get('declared_stdin_path') and p!=canon(ctx['declared_stdin_path']): fail('undeclared_stdin_source')
        elif ann.get('kind')=='nonpath':
            if fd in (1,2):
                expected=(ctx.get('stdout_sink_label') if fd==1 else ctx.get('stderr_sink_label'))
                if not expected or ann.get('label')!=expected: fail('uncertain_stdio_sink')
            elif fd!=0:
                fail('uncertain_attribution')
        else: fail('uncertain_attribution')
        if op in IOCTL_QUERY:
            # Current build envelope requires non-TTY stdin and captured stdout/stderr.
            # A successful TCGETS would expose undeclared terminal host state.
            if op=='TCGETS' and not ret.startswith('-1 ENOTTY'):
                return {'event':name,'class':'unresolved-invariant','family':'terminal-host-state','paths':paths}
            return {'event':name,'class':'readonly','family':'fd-metadata-query','paths':paths}
        if op in IOCTL_LOCAL_BOOTSTRAP:
            return {'event':name,'class':'readonly','family':'fd-local-control','paths':paths}
        return {'event':name,'class':'forbidden-ioctl','paths':paths}
    if name=='fcntl':
        if len(toks)<2: fail('undecodable_args')
        f=parse_fd_token(toks[0])
        if not f or f['fd']=='AT_FDCWD' or not f.get('annotation'): fail('uncertain_attribution')
        fd=int(f['fd']); ann=f['annotation']; op=toks[1].strip()
        if ann.get('kind')=='path':
            p=canon(ann['path']); add(p)
            if fd==0 and ctx.get('declared_stdin_path') and p!=canon(ctx['declared_stdin_path']): fail('undeclared_stdin_source')
        elif ann.get('kind')=='nonpath':
            if fd in (1,2):
                expected=(ctx.get('stdout_sink_label') if fd==1 else ctx.get('stderr_sink_label'))
                if not expected or ann.get('label')!=expected: fail('uncertain_stdio_sink')
            elif fd!=0:
                fail('uncertain_attribution')
        else: fail('uncertain_attribution')
        if op in FCNTL_QUERY:
            return {'event':name,'class':'readonly','family':'fd-metadata-query','paths':paths}
        return {'event':name,'class':'forbidden-fcntl','paths':paths}
    if name=='chdir':
        if not toks: fail('undecodable_args')
        p=path_from_direct(toks[0],cwd);add(p)
        if not ret.startswith('-1'):ctx['cwd']=p
        return {'event':name,'class':'readonly','family':'cwd-control','paths':paths}
    if name=='fchdir':
        if not toks: fail('undecodable_args')
        p=fd_path(toks[0]);add(p)
        if p is None: fail('uncertain_attribution')
        if not ret.startswith('-1'):ctx['cwd']=p
        return {'event':name,'class':'readonly','family':'cwd-control','paths':paths}
    if name in SIMPLE_BOOTSTRAP:
        if name in {'read','pread64','readv'}:
            if not toks: fail('uncertain_attribution')
            f=parse_fd_token(toks[0])
            if not f or f['fd']=='AT_FDCWD' or not f.get('annotation'): fail('uncertain_attribution')
            if f['annotation'].get('kind')=='path':
                p=canon(f['annotation']['path']); add(p)
                if int(f['fd'])==0 and ctx.get('declared_stdin_path') and p!=canon(ctx['declared_stdin_path']): fail('undeclared_stdin_source')
                return {'event':name,'class':'readonly','family':'filesystem-read','paths':paths}
            return {'event':name,'class':'unclassified','family':'fd-read-nonpath','paths':paths}
        if name in {'close','lseek'}:
            if not toks: fail('uncertain_attribution')
            f=parse_fd_token(toks[0])
            if not f or f['fd']=='AT_FDCWD' or not f.get('annotation'):
                fail('uncertain_attribution')
            fd=int(f['fd']); ann=f['annotation']
            if ann.get('kind')=='path':
                p=canon(ann['path']); add(p)
                if fd==0 and ctx.get('declared_stdin_path') and p!=canon(ctx['declared_stdin_path']): fail('undeclared_stdin_source')
            elif ann.get('kind')=='nonpath':
                if fd in (1,2):
                    expected=(ctx.get('stdout_sink_label') if fd==1 else ctx.get('stderr_sink_label'))
                    if not expected or ann.get('label')!=expected: fail('uncertain_stdio_sink')
                elif fd!=0:
                    fail('uncertain_attribution')
            else: fail('uncertain_attribution')
            return {'event':name,'class':'readonly','family':'fd-local-control','paths':paths}
        if name=='arch_prctl':
            if len(toks)!=2: fail('undecodable_args')
            if toks[0].strip()!='ARCH_SET_FS':
                return {'event':name,'class':'unclassified','family':'thread-arch-control','paths':paths}
            return {'event':name,'class':'readonly','family':'thread-local-state','paths':paths}
        if name=='brk':
            if len(toks)!=1: fail('undecodable_args')
            return {'event':name,'class':'readonly','family':'process-memory-local','paths':paths}
        if name=='mprotect':
            if len(toks)!=3: fail('undecodable_args')
            return {'event':name,'class':'readonly','family':'process-memory-local','paths':paths}
        if name=='munmap':
            if len(toks)!=2: fail('undecodable_args')
            return {'event':name,'class':'readonly','family':'process-memory-local','paths':paths}
        if name=='rt_sigaction':
            if len(toks)!=4: fail('undecodable_args')
            return {'event':name,'class':'readonly','family':'process-signal-state-local','paths':paths}
        if name=='set_tid_address':
            if len(toks)!=1: fail('undecodable_args')
            return {'event':name,'class':'readonly','family':'thread-local-state','paths':paths}
        if name=='set_robust_list':
            if len(toks)!=2: fail('undecodable_args')
            return {'event':name,'class':'readonly','family':'thread-local-state','paths':paths}
        if name=='rseq':
            if len(toks)!=4: fail('undecodable_args')
            return {'event':name,'class':'readonly','family':'thread-local-state','paths':paths}
        if name=='gettid':
            if toks!=['']: fail('undecodable_args')
            return {'event':name,'class':'readonly','family':'host-state-process-identity','paths':paths}
        if name=='prlimit64':
            if len(toks)!=4: fail('undecodable_args')
            if toks[0].strip()!='0' or toks[2].strip()!='NULL':
                return {'event':name,'class':'forbidden-resource-limit-mutation','paths':paths}
            return {'event':name,'class':'readonly','family':'host-state-resource-limits','paths':paths}
        if name=='getrandom':
            if len(toks)!=3: fail('undecodable_args')
            flags=toks[2].strip()
            if flags!='GRND_NONBLOCK':
                return {'event':name,'class':'unresolved-invariant','family':'randomness-flags-unreviewed','paths':paths}
            return {'event':name,'class':'readonly','family':'host-state-randomness','paths':paths}
        return {'event':name,'class':'unclassified','family':'bootstrap','paths':paths}
    return {'event':name,'class':'unclassified','family':'unknown','paths':paths}

def operation_key(name,args,policy):
    toks=split_args(args)
    by={r['event_name']:r for r in policy.get('operation_sensitive_events',[])}
    if name not in by: return (name,None)
    idx=by[name]['operation_argument_index']
    if idx<0 or idx>=len(toks): fail('undecodable_args')
    op=toks[idx].strip(' \t')
    if not op: fail('undecodable_args')
    return (name,op)

def policy_key_sort(entry):
    op=entry['operation']
    return (entry['event_name'].encode('utf-8'), b'\x00' if op is None else b'\x01'+op.encode('utf-8'))

def fixture_reproduces_key(path,key):
    obj=json.loads(Path(path).read_text(encoding='utf-8'))
    for case in obj.get('cases',{}).values():
        for line in case.get('lines',[]):
            try:
                kind,name,args,ret=split_call(line)
                if kind!='syscall': continue
                # Operation-sensitive map is carried in the fixture for evidence-only replay.
                ops=obj.get('operation_sensitive_events',[])
                pol={'operation_sensitive_events':ops}
                if operation_key(name,args,pol)==key:return True
            except ParseFailure:
                continue
    return False

def validate_policy(policy,repo_root=None):
    keys={'classification_policy_contract_version','policy_id','security_properties','review_key_mode','operation_sensitive_events','hard_fail_exact_syscalls','hard_fail_syscall_prefixes','reviewed_safe_events','unknown_event_disposition'}
    if set(policy)!=keys: fail('policy_schema')
    if policy['classification_policy_contract_version']!='build-dependency-observer-classification-policy-v2':fail('policy_schema')
    if not isinstance(policy['policy_id'],str) or not policy['policy_id']:fail('policy_schema')
    if policy['security_properties']!=SECURITY_PROPERTIES:fail('policy_security_properties')
    if policy['review_key_mode']!='event_name_plus_operation_or_null' or policy['unknown_event_disposition']!='REVIEW_REQUIRED':fail('policy_schema')
    ops=policy['operation_sensitive_events']
    if not isinstance(ops,list) or any(set(x)!={'event_name','operation_argument_index'} for x in ops):fail('policy_operation_schema')
    if [x['event_name'] for x in ops]!=sorted([x['event_name'] for x in ops],key=lambda x:x.encode('utf-8')):fail('policy_operation_order')
    if len({x['event_name'] for x in ops})!=len(ops) or any(not isinstance(x['operation_argument_index'],int) or x['operation_argument_index']<0 for x in ops):fail('policy_operation_schema')
    hd=policy['hard_fail_exact_syscalls'];hp=policy['hard_fail_syscall_prefixes']
    if hd!=sorted(set(hd),key=lambda x:x.encode('utf-8')) or not HARD_FAIL_EXACT_MIN.issubset(hd):fail('policy_hard_deny')
    if hp!=sorted(set(hp),key=lambda x:x.encode('utf-8')) or not HARD_FAIL_PREFIX_MIN.issubset(hp):fail('policy_hard_deny')
    rows=policy['reviewed_safe_events']
    if not isinstance(rows,list) or rows!=sorted(rows,key=policy_key_sort):fail('policy_review_order')
    seen=set(); opnames={x['event_name'] for x in ops}
    for r in rows:
        if set(r)!={'event_name','operation','effect_scope','review_evidence_fixture_path','review_evidence_fixture_sha256'}:fail('policy_review_schema')
        k=(r['event_name'],r['operation'])
        if k in seen:fail('policy_review_duplicate')
        seen.add(k)
        if r['effect_scope'] not in EFFECT_SCOPES:fail('invalid_effect_scope')
        if r['event_name'] in PROCESS_CREATE: fail('unsafe_policy_admission')
        if r['event_name'] in INVARIANT_EVENT_NAMES or r['event_name'] in hd or any(r['event_name'].startswith(x) for x in hp):fail('policy_override_attempt')
        if (r['event_name'] in opnames)!=(r['operation'] is not None):fail('policy_review_key')
        if not re.fullmatch(r'[0-9a-f]{64}',r['review_evidence_fixture_sha256']):fail('review_evidence_binding')
        if repo_root is not None:
            root=canon(repo_root); fp=canon(r['review_evidence_fixture_path'],root)
            if not under(fp,root) or not Path(fp).is_file():fail('review_evidence_binding')
            if hashlib_sha256_file(fp)!=r['review_evidence_fixture_sha256']:fail('review_evidence_binding')
            if not fixture_reproduces_key(fp,k):fail('review_evidence_binding')
    return True

def hashlib_sha256_file(path):
    import hashlib
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''):h.update(c)
    return h.hexdigest()

def evaluate_syscall(name,args,ret,ctx,policy):
    key=operation_key(name,args,policy)
    hd=set(policy['hard_fail_exact_syscalls']);hp=policy['hard_fail_syscall_prefixes']
    if name in hd or any(name.startswith(x) for x in hp):
        return {'event':name,'operation':key[1],'class':'forbidden-hard-deny','disposition':'FORBIDDEN','admission_source':None,'invariant_coverage':'COMPLETE','paths':[]}
    raw=classify_syscall(name,args,ret,ctx)
    cls=raw['class'];fam=raw.get('family')
    if cls.startswith('forbidden-'):
        raw.update({'operation':key[1],'disposition':'FORBIDDEN','admission_source':None,'invariant_coverage':'COMPLETE'});return raw
    invariant_families={
        'filesystem-read','directory-enumeration','initial-exec','process-exit','cwd-control',
        'declared-sink-write','declared-sink-metadata-query',
        'process-vma','process-memory-local','process-signal-state-local','thread-local-state',
        'fd-metadata-query','fd-local-control',
        'host-state-process-identity','host-state-resource-limits','host-state-randomness'
    }
    if cls.startswith('allowed-staging-') or fam in invariant_families:
        raw.update({'operation':key[1],'disposition':'ADMITTED','admission_source':'INVARIANT_ADMITTED','invariant_coverage':'COMPLETE'});return raw
    if fam=='process-create' or cls=='unresolved-invariant':
        raw.update({'operation':key[1],'disposition':'REVIEW_REQUIRED','admission_source':None,'invariant_coverage':'INCOMPLETE'});return raw
    reviewed={(r['event_name'],r['operation']):r for r in policy['reviewed_safe_events']}
    if key in reviewed:
        raw.update({'operation':key[1],'disposition':'ADMITTED','admission_source':'POLICY_ADMITTED','effect_scope':reviewed[key]['effect_scope'],'invariant_coverage':None});return raw
    raw.update({'operation':key[1],'disposition':'REVIEW_REQUIRED','admission_source':None,'invariant_coverage':None});return raw

def final_outcome(rows):
    if any(r.get('disposition')=='FORBIDDEN' for r in rows):return 'FAIL'
    if any(r.get('disposition')=='REVIEW_REQUIRED' for r in rows):return 'REVIEW_REQUIRED'
    return 'PASS'

def trace_files(prefix):
    p=Path(prefix)
    if p.is_file(): return [p]
    rows=[]
    for s in glob.glob(prefix+'.*'):
        q=Path(s)
        if q.is_file() and re.fullmatch(re.escape(prefix)+r'\.\d+',str(q)): rows.append(q)
    return sorted(rows,key=lambda q:q.name.encode())

def pid_from_trace(path,prefix):
    s=str(path)
    m=re.fullmatch(re.escape(prefix)+r'\.(\d+)',s)
    return int(m.group(1)) if m else None

def parse_trace_set(prefix,project_root,staging_root,policy,allowed_initial_exec='/usr/bin/python3',initial_cwd=None,allowed_initial_argv_prefix=None,stdout_sink_label=None,stderr_sink_label=None,declared_stdin_path='/dev/null'):
    tfs=trace_files(prefix)
    if not tfs: fail('trace_missing')
    pr=canon(project_root);sr=canon(staging_root);cwd=canon(initial_cwd or os.getcwd())
    pids={pid_from_trace(p,prefix) for p in tfs};pids.discard(None)
    # Root is the only trace pid not reported as a child; if no pid suffix, sole file is root.
    preliminary_children=set()
    all_lines={p:p.read_text(encoding='utf-8',errors='strict').splitlines() for p in tfs}
    for p,lines in all_lines.items():
        for line in lines:
            kind,name,args,ret=split_call(line)
            if kind=='syscall' and name in PROCESS_CREATE:
                rf=ret_fd(ret)
                if rf and rf['fd']>0: preliminary_children.add(rf['fd'])
    if pids:
        roots=pids-preliminary_children
        if len(roots)!=1: fail('trace_process_tree_uncertain')
        root_pid=next(iter(roots))
    else:
        if len(tfs)!=1: fail('trace_process_tree_uncertain')
        root_pid=None
    results=[]; child_pids=set(); initial_seen=False
    if root_pid is not None:
        tfs=sorted(tfs,key=lambda p:(0 if pid_from_trace(p,prefix)==root_pid else 1,p.name.encode()))
    for p in tfs:
        pid=pid_from_trace(p,prefix)
        ctx={'project_root':pr,'staging_root':sr,'cwd':cwd,'allowed_initial_exec':canon(allowed_initial_exec),'allowed_initial_argv_prefix':allowed_initial_argv_prefix or ['/usr/bin/python3','-I','-S','-B'],'stdout_sink_label':stdout_sink_label,'stderr_sink_label':stderr_sink_label,'declared_stdin_path':declared_stdin_path,'is_root_trace':(pid==root_pid if root_pid is not None else p==tfs[0]),'initial_exec_seen':initial_seen,'child_pids':child_pids}
        terminal_seen=False
        nonblank=[x for x in all_lines[p] if x.strip()]
        for pos,line in enumerate(nonblank):
            kind,name,args,ret=split_call(line)
            if terminal_seen: fail('trace_after_terminal')
            if kind=='meta-exit':
                terminal_seen=True
                if pos!=len(nonblank)-1: fail('trace_after_terminal')
                if int(ret)!=0: fail('nonzero_process_exit')
                results.append({'event':'meta-exit','class':'bootstrap','family':'process-exit-meta','disposition':'ADMITTED','admission_source':'INVARIANT_ADMITTED','invariant_coverage':'COMPLETE','paths':[]});continue
            if kind=='meta-killed': fail('fatal_signal:'+str(ret))
            if kind=='meta-signal': results.append({'event':'meta-signal','class':'bootstrap-signal-delivery','disposition':'REVIEW_REQUIRED','admission_source':None,'invariant_coverage':'INCOMPLETE','paths':[]});continue
            r=evaluate_syscall(name,args,ret,ctx,policy);results.append(r)
            initial_seen=initial_seen or ctx['initial_exec_seen']
        if not terminal_seen: fail('trace_terminal_missing')
    if not initial_seen:
        fail('initial_exec_missing')
    if pids:
        missing=child_pids-pids
        if missing: fail('trace_loss_child_missing:'+','.join(map(str,sorted(missing))))
        extra=pids-({root_pid}|child_pids)
        if extra: fail('trace_process_tree_extra:'+','.join(map(str,sorted(extra))))
    return results,tfs

def fixture_mode(obj,case_name,policy,repo_root=None):
    case=obj['cases'][case_name]
    try:
        ctx={'project_root':canon(case.get('project_root','/project')),'staging_root':canon(case.get('staging_root','/staging')),'cwd':canon(case.get('cwd','/')),'allowed_initial_exec':canon(case.get('allowed_initial_exec','/usr/bin/python3')),'allowed_initial_argv_prefix':case.get('allowed_initial_argv_prefix',['/usr/bin/python3','-I','-S','-B']),'stdout_sink_label':case.get('stdout_sink_label'),'stderr_sink_label':case.get('stderr_sink_label'),'declared_stdin_path':case.get('declared_stdin_path','/dev/null'),'is_root_trace':True,'initial_exec_seen':False,'child_pids':set()}
        parsed=[]
        for line in case['lines']:
            kind,name,args,ret=split_call(line)
            if kind=='syscall': parsed.append(evaluate_syscall(name,args,ret,ctx,policy))
            elif kind=='meta-exit':
                if int(ret)!=0:fail('nonzero_process_exit')
                parsed.append({'event':'meta-exit','class':'bootstrap','disposition':'ADMITTED','admission_source':'INVARIANT_ADMITTED','invariant_coverage':'COMPLETE','paths':[]})
            elif kind=='meta-killed':fail('fatal_signal:'+str(ret))
            elif kind=='meta-signal':parsed.append({'event':'meta-signal','class':'bootstrap-signal-delivery','disposition':'REVIEW_REQUIRED','admission_source':None,'invariant_coverage':'INCOMPLETE','paths':[]})
        if case.get('expect_error'): print('UNEXPECTED_PASS');return 1
        actual=final_outcome(parsed)
        expected=case.get('expected_outcome','PASS')
        sentinel=case.get('sentinel_event')
        if sentinel and not any(x.get('event')==sentinel for x in parsed): print('SENTINEL_MISSING');return 1
        if actual!=expected: print(json.dumps({'expected_outcome':expected,'actual_outcome':actual,'rows':parsed},sort_keys=True));return 1
        print(actual);return 0
    except Exception as e:
        if not case.get('expect_error'): print(type(e).__name__+': '+str(e));return 1
        ok=case['expect_error'] in str(e);print('EXPECTED_FAIL' if ok else ('WRONG_FAIL:'+str(e)));return 0 if ok else 1

def measurement_mode(a):
    expected=json.loads(Path(a.expected_project_paths_json).read_text(encoding='utf-8'));expected_set=set(expected['paths'])
    policy=json.loads(Path(a.policy).read_text(encoding='utf-8'));validate_policy(policy,a.repo_root);rows,tfs=parse_trace_set(a.trace_prefix,a.project_root,a.staging_root,policy,a.allowed_initial_exec,a.initial_cwd,['/usr/bin/python3','-I','-S','-B'],a.stdout_sink_label,a.stderr_sink_label,a.declared_stdin_path)
    pr=canon(a.project_root);sr=canon(a.staging_root);observed=set();external=set();counts=Counter()
    for r in rows:
        counts[r['class']]+=1
        for p in r.get('paths',[]):
            if under(p,pr):
                rel=os.path.relpath(p,pr).replace(os.sep,'/')
                if rel!='.' and not rel.startswith('../'): observed.add(rel)
            elif not under(p,sr): external.add(p)
    missing=sorted(expected_set-observed,key=lambda x:x.encode());extra=sorted(observed-expected_set,key=lambda x:x.encode())
    outcome=final_outcome(rows)
    if missing or extra: outcome='FAIL'
    review=sorted({(r.get('event'),r.get('operation')) for r in rows if r.get('disposition')=='REVIEW_REQUIRED'},key=lambda x:((x[0] or '').encode(),b'' if x[1] is None else x[1].encode()))
    result={'parser_implementation_version':PARSER_IMPLEMENTATION_VERSION,'trace_files':len(tfs),'event_count':len(rows),'class_counts':dict(sorted(counts.items())),'observed_project_paths':sorted(observed,key=lambda x:x.encode()),'expected_project_paths':sorted(expected_set,key=lambda x:x.encode()),'missing_project_paths':missing,'extra_project_paths':extra,'external_absolute_paths':sorted(external,key=lambda x:x.encode()),'review_required_keys':[{'event_name':x[0],'operation':x[1]} for x in review],'project_path_set_equality':'PASS' if not missing and not extra else 'FAIL','result':outcome}
    Path(a.output).write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n',encoding='utf-8',newline='\n')
    print('OBSERVER_PARSE_RESULT='+result['result']);print('OBSERVER_EVENT_COUNT='+str(len(rows)));print('OBSERVED_PROJECT_PATHS='+str(len(observed)))
    if missing:print('MISSING_PROJECT_PATHS='+','.join(missing))
    if extra:print('EXTRA_PROJECT_PATHS='+','.join(extra))
    return 0 if result['result']=='PASS' else (5 if result['result']=='REVIEW_REQUIRED' else 4)

def inventory_mode(a):
    names=Counter();tfs=trace_files(a.trace_prefix)
    if not tfs:fail('trace_missing')
    for p in tfs:
        for line in p.read_text(encoding='utf-8',errors='strict').splitlines():
            kind,name,args,ret=split_call(line)
            if kind=='syscall':names[name]+=1
    obj={'syscall_name_count':len(names),'syscall_counts':{k:names[k] for k in sorted(names,key=lambda s:s.encode())}}
    print(json.dumps(obj,sort_keys=True,separators=(',',':')));return 0

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--fixture');ap.add_argument('--case');ap.add_argument('--trace-prefix');ap.add_argument('--project-root');ap.add_argument('--staging-root');ap.add_argument('--expected-project-paths-json');ap.add_argument('--output');ap.add_argument('--allowed-initial-exec',default='/usr/bin/python3');ap.add_argument('--initial-cwd');ap.add_argument('--syscall-inventory',action='store_true');ap.add_argument('--policy');ap.add_argument('--repo-root');ap.add_argument('--stdout-sink-label');ap.add_argument('--stderr-sink-label');ap.add_argument('--declared-stdin-path',default='/dev/null');a=ap.parse_args()
    if a.syscall_inventory and a.trace_prefix:return inventory_mode(a)
    if not a.policy:return 2
    policy=json.loads(Path(a.policy).read_text(encoding='utf-8'));validate_policy(policy,a.repo_root)
    if a.fixture and a.case:return fixture_mode(json.loads(Path(a.fixture).read_text(encoding='utf-8')),a.case,policy,a.repo_root)
    if all([a.trace_prefix,a.project_root,a.staging_root,a.expected_project_paths_json,a.output,a.repo_root]):return measurement_mode(a)
    return 2

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:print('OBSERVER_PARSE_FAIL='+type(e).__name__+':'+str(e),file=sys.stderr);raise SystemExit(1)
