# Solution

## Overview

Three binaries, one flag. Each binary yields one shard. The Go binary takes all three shards as input and reveals the full flag.

```
vm_chall     (Linux ELF)    → shard 1
pe_chall.exe (Windows PE)   → shard 2
go_chall.exe (Go binary)    → shard 3 + full flag
```

**Flag:** `HTB{c4r_k3ys_sc4tt3r3d_4LL_0v3r_tH3_pL4c3_6e11873b9d9d94a44058bef5747735ce}`

---

## Part 1 — c1 (Linux ELF)

**Step 1 — Load into Ghidra**

Import `vm_chall`, let auto-analysis finish, find `main()`.

**Step 2 — Identify the VM**

Inside `main()` identify:
- A `calloc()` for a large struct — this is the VM state
- Two setup calls before input — `load_expected()` and `load_bytecode()`
- A dispatch loop with a switch statement — the VM execution engine

**Step 3 — Map the instruction set**

Trace the switch cases and map 8 opcodes:
```
0x01 PUSH  <imm>   — push immediate onto stack
0x02 LOAD  <addr>  — push mem[addr] onto stack
0x03 STORE <addr>  — pop stack, store into mem[addr]
0x04 ADD           — pop a, b; push (a+b) & 0xFF
0x05 XOR           — pop a, b; push a^b
0x06 CMP           — pop a, b; FLAG = (a==b)
0x07 JNE  <addr>   — jump if FLAG == 0
0x08 HALT <result> — terminate
```

**Step 4 — Dump and disassemble the bytecode**

Bytecode lives at `mem[0x40]`. Set a breakpoint after `load_bytecode()` and dump from that offset. You will see a repeating pattern for each of the 8 input bytes:
```
LOAD  0x10+i    ; load input byte
PUSH  i+0x5A   ; push XOR mask
XOR             ; transform
LOAD  0x20+i   ; load expected value
CMP             ; compare
JNE   FAIL      ; bail if mismatch
```
Followed by a checksum accumulation block.

**Step 5 — Extract expected values**

Expected transformed values sit at `mem[0x20..0x27]`:
```
{0x39, 0x6F, 0x2E, 0x02, 0x35, 0x6C, 0x19, 0x12}
```

**Step 6 — Invert the transform**

```python
expected = [0x39, 0x6F, 0x2E, 0x02, 0x35, 0x6C, 0x19, 0x12]
print(''.join(chr(expected[i] ^ (i + 0x5A)) for i in range(8)))
# c4r_k3ys
```

**Shard 1: `HTB{c4r_k3ys`**

---

## Part 2 — c2.exe (Windows PE)

**Step 1 — Load into Ghidra**

Import `pe_chall.exe`, let analysis finish. The entry point is CRT boilerplate — the real `main()` is `FUN_00401350`.

**Step 2 — Map the functions**

```
FUN_00401000  →  rdtsc_check()
FUN_00401090  →  fnv32()              ← hashes shard1 to derive key
FUN_004010e0  →  rolling_hash()       ← validates shard2 using key
FUN_00401180  →  print_fake_shard()   ← prints decoy output
FUN_00401230  →  store_real_shard()   ← real shard decoded here
DAT_0041d9b8  →  g_poison
0xD3C5431D    →  EXPECTED_HASH
```

**Step 3 — Understand the two-input structure**

The binary takes two inputs — shard1 from the ELF and a candidate shard2. `fnv32(shard1)` derives a key which seeds `rolling_hash()`. This means the PE is unsolvable without first solving the ELF.

**Step 4 — Spot the fake shard**

Run with correct inputs:
```
Enter shard 1: HTB{c4r_k3ys
Enter shard 2: sc4tt3r3d
Correct! Shard 2: _5c4tt3r3d
```
Submitting `_5c4tt3r3d` to the Go binary gives `Wrong.` — the printed output is a decoy. Notice `print_fake_shard()` and `store_real_shard()` are two separate functions. The real shard is decoded into RAM inside `store_real_shard()` and never printed.

**Step 5 — Spot the RDTSC anti-debug**

Inside `rdtsc_check()` at `00041006` and `0004103E` find two `rdtsc` instructions. The branch at `0004105C` sets `g_poison` if timing is too large — silently corrupting bytes inside `rolling_hash()`. Running under a debugger without patching gives `Wrong.` even with correct input.

**Step 6 — Patch RDTSC in x32dbg**

Open `pe_chall.exe` in x32dbg. Patch the anti-debug branches:
- `Ctrl+G` → `41006` to confirm location
- Click `0004105C` → Space → type `nop` → Enter (repeat for `0004105D`)
- Click `00041065` → Space → type `nop` → Enter (repeat for `00041066`)

**Step 7 — Set breakpoints**

- `Ctrl+G` → `41230` → F2 (breakpoint on `store_real_shard`)
- Set a second breakpoint on the hold loop inside `store_real_shard` — the no-op loop right after the decode loop (`for local_10 = 0; local_10 < 1000`)

**Step 8 — Run and catch the real shard**

Press F9, feed inputs in the console window:
```
Enter shard 1: HTB{c4r_k3ys
Enter shard 2: sc4tt3r3d
```
When breakpoint hits at the hold loop:
- Right click `EAX` in registers → Follow in Dump
- Read the heap buffer in the dump panel before the wipe loop runs:
```
73 63 34 74 74 33 72 33 64   s c 4 t t 3 r 3 d
```

**Step 9 — Verify with Python**

```python
def fnv32(s):
    h = 2166136261
    for c in s.encode():
        h ^= c
        h = (h * 16777619) & 0xFFFFFFFF
    return h

def rolling_hash(s, key):
    state = key
    for b in s.encode():
        state = ((state << 5) | (state >> 27)) & 0xFFFFFFFF
        state ^= b
        state = (state + ((state >> 3) ^ 0xA5A5A5A5)) & 0xFFFFFFFF
    return state

key = fnv32('HTB{c4r_k3ys')
print(hex(rolling_hash('sc4tt3r3d', key)))  # 0xd3c5431d ✓
```

**Shard 2: `_sc4tt3r3d`**

---

## Part 3 — c3.exe (Go binary)

**Step 1 — Recover symbols with GoReSym**

```bash
GoReSym.exe -t -d go_chall.exe > syms.json
```
Load into Ghidra using the GoReSym script. Function names become readable:
```
main.main
main.transformWorker
main.checkWorker
main.junkWorker
main.deriveMagic
main.revealFlag
```

**Step 2 — Identify real vs junk goroutines**

Four goroutines spawn. Two call `main.junkWorker` with seeds `0x13` and `0x37` — their output is discarded. The real pipeline is `main.transformWorker → main.checkWorker`.

**Step 3 — Reverse main.deriveMagic()**

```go
a := uint32(0x6334) << 16   // = 0x63340000
b := uint32(0x7363)          // = 0x00007363
magic := a | b               // = 0x63347363
```

**Step 4 — Reverse main.transformWorker()**

Each shard3 byte is XOR'd with a rotating byte of `magic`:
```go
shift = (i % 4) * 8
mask  = byte(magic >> shift)
output = input ^ mask
```

**Step 5 — Extract expected[] from main.checkWorker()**

```
{0x57, 0x3F, 0x78, 0x3C, 0x53, 0x05, 0x07, 0x11}
```

**Step 6 — Invert to recover shard3**

```python
magic    = 0x63347363
expected = [0x57, 0x3F, 0x78, 0x3C, 0x53, 0x05, 0x07, 0x11]

result = []
for i in range(8):
    shift = (i % 4) * 8
    mask  = (magic >> shift) & 0xFF
    result.append(chr(expected[i] ^ mask))

print(''.join(result))
# 4LL_0v3r
```

**Step 7 — Feed all three shards**

```
Enter all 3 shards (space separated): HTB{c4r_k3ys _sc4tt3r3d 4LL_0v3r
Correct! Shard 3: _4LL_0v3r_tH3_pL4c3_6e11873b9d9d94a44058bef5747735ce}
```

**Shard 3: `4LL_0v3r`**

---

## Full Flag

```
HTB{c4r_k3ys_sc4tt3r3d_4LL_0v3r_tH3_pL4c3_6e11873b9d9d94a44058bef5747735ce}
```
