# GateX

Polymorphic shellcode loader generator. Give it raw shellcode, it encrypts it and spits out a .c file with random variable names, encrypted strings, junk code, decoys etc. Every run = completely different output. x64 Windows only

## Techniques

19 injection techniques:

`local` `inject` `apc` `callback` `fiber` `hijack` `stomp` `hollow` `pool` `phantom` `earlybird` `mapview` `tls` `transact` `threadless` `overload` `callbackfonts` `callbackdesktop` `callbackwindows`

## Encryption

XOR, AES-256-CBC, RC4. Can stack them with `--compound` for double encryption or `--multistage` for layered decryption

## Evasion

Theres a lot so heres the list:

- Sandbox detection (15 checks - timing, process count, RAM, disk, screen res, cursor movement, VM registry keys, BIOS strings, sandbox DLLs, username blacklist, MAC address)
- Anti-debug (PEB flags, NtQueryInformationProcess, debug objects, HW breakpoint regs, QPC timing, ThreadHideFromDebugger)
- Anti-emulation (CPUID vendor check, hypervisor bit, CPUID 0x40000000 for VMware/Hyper-V/KVM/Xen, GetTickCount64 timing, RDTSC, memory size, FPU precision)
- Indirect syscalls w/ HalosGate SSN resolution + encrypted stubs
- ETW/AMSI patching (polymorphic patches or hardware breakpoints)
- Ntdll unhook (KnownDlls or fresh copy from disk)
- Sleep obfuscation (timer-queue based, XOR encrypts shellcode during sleep, randomized timer)
- Shellcode fluctuation (marks memory PAGE_NOACCESS between cycles)
- Return address spoofing
- Cmdline spoofing (PEB based)
- PPID spoofing
- CFG bypass
- PE header wipe
- Thread hiding
- Heap encryption
- HMAC-SHA256 integrity check
- Anti-disassembly (junk bytes for IDA/Ghidra)
- Control flow flattening
- Self-delete (NTFS ADS rename trick)
- Env-keying (SHA256 hostname, full 32 byte key derivation)
- Kill-date
- Domain guardrails

## Polymorphism

- XOR encoded stack strings (random key per string)
- 18 junk code patterns (fake API calls, heap allocs, structs, arrays, switches etc)
- 17 opaque predicates
- Decoy globals + dead functions
- All variable/function names randomized
- Unique hash seed every generation

## Usage

```
python gatex.py shellcode.bin
python gatex.py shellcode.bin -t inject --target notepad.exe
python gatex.py shellcode.bin -t apc -e aes -s --stealth
python gatex.py shellcode.bin -t hollow --stealth --env-keying WORKSTATION01 --anti-emulation
python gatex.py shellcode.bin -t stomp -s --hwbp --compound --cff
python gatex.py shellcode.bin -t local --stealth --fluctuate --retaddr-spoof --hmac
python gatex.py shellcode.bin --format dll -t overload -e rc4 --stealth
```

`--stealth` turns on: syscalls, sleep-obf, anti-debug, ETW patch, AMSI patch, unhook, thread-hide, PE wipe, heap-encrypt, anti-disasm, self-delete

## Compile

MSVC:
```
cl /O2 output/loader.c /link bcrypt.lib
```

MinGW:
```
x86_64-w64-mingw32-gcc -O2 output/loader.c -o loader.exe -lbcrypt
```

Add `-lbcrypt` / `bcrypt.lib` when using AES, HMAC, `--stealth` or `--env-keying`

## Requirements

- Python 3.6+
- pycryptodome (`pip install pycryptodome`)

## Disclaimer

For educational and authorized security research only. Not responsible for misuse
