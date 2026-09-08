# Pitfalls: the subtle pwn bugs that burn hours

A running catalogue of non-obvious bugs that have cost us real solve time.
Each entry: **symptom**, **root cause**, **diagnosis**, **fix**, and
**detector** (the kraken helper or technique that would catch it next time).

When triaging a new challenge, grep this file for keywords that match the
observed behavior before burning hours on manual debug.

---

## 1. The scanf → FILE\* pushback → getchar trap

**Symptom.** After a working libc leak via stage-1 BOF, stage-2 fgets
ROP crashes at a non-canonical RIP that looks like your intended retaddr
shifted by exactly 1 byte.

**Root cause.** `scanf("%d*%c", &choice)` reads `"1"` and then fails to
match literal `'*'` against the `'\n'` left in stdin, glibc `ungetc`'s
the `'\n'` back to `FILE *stdin`'s pushback buffer. The next
`read(0, tmp_buf, N)` is a direct syscall and bypasses FILE\* pushback,
so stage 1 arrives clean in the read buffer. But later, when a wrapper
function calls `getchar()`, it **is** a FILE\* op, it consumes that
stale `\n` from pushback first, **not** the first byte of your stage-2
payload. Any byte you added as a "getchar prefix" in stage 2 actually
lands inside fgets's stack buffer, shifting the whole ROP chain by 1.

**Diagnosis (the fast version).** Feed the stage-2 payload
through a FIFO with `auto_fifo_gdb.py`, break at the vuln function's
`leave` instruction, and read the saved-rbp stack slot. If it contains
the LAST byte of your padding + first 7 bytes of what should be
`fake_rbp`, you have a 1-byte right-shift and the culprit is an
extraneous getchar byte.

**Fix.** Drop the getchar prefix. Stage 2 is exactly `read_size - 1`
bytes starting directly with the fgets payload. The getchar ate the
pushback `\n`, not your byte.

**Detector.** `auto_rop_offset_check.py` on a cyclic pattern would
reveal the exact byte offset mismatch. `auto_fifo_gdb.py` at the
vuln function's leave dumps saved_rbp/saved_retaddr for eyeball diff.

**Prior case.** VERE pwn2, burned ~hours before the payload was
correctly offset.

---

## 2. Canary-check NOPed out of the binary

**Symptom.** The challenge advertises "Stack Canary enabled" but stack
BOFs don't abort on canary mismatch, you can overwrite saved rbp/rip
freely.

**Root cause.** The compare-and-branch at the end of the vuln function
was patched post-build. In disasm:
```
je  <epilogue>          ; takes canary match → leave;ret
nop                     ; was `call __stack_chk_fail`
nop
nop
nop
nop
<epilogue>: leave; ret
```
On mismatch, execution falls through the nops and hits leave;ret
normally, the canary is effectively ignored.

**Diagnosis.** `objdump -d` the vuln function. Look for `je <leave>`
followed by `nop` instructions instead of a `call __stack_chk_fail`.

**Fix.** None needed, send whatever bytes you want in the canary
slot.

**Detector.** `classify_wrapper.py` could flag "canary slot reachable
but no `__stack_chk_fail` reference in the function body".

**Prior case.** VERE pwn2.

---

## 3. strlen-bypass via `memcpy(buf, tmp_buf, r)` (not `strlen`)

**Symptom.** A "too long" check exists (e.g., `strlen(tmp_buf) >= 256`)
but you can still overflow because the copy that follows uses the raw
read count `r`, not the strlen.

**Root cause.**
```c
int r = read(0, tmp_buf, sizeof(tmp_buf) - 1);
tmp_buf[r] = 0;
if (strlen(tmp_buf) >= BUFFER_SIZE) exit(1);
memcpy(buf, tmp_buf, r);   // <-- uses r, not strlen(tmp_buf)
```
Place a NUL early in `tmp_buf` (via `\0`) and strlen sees a short
string while `r` is still the full read length, memcpy happily
copies past `buf`.

**Fix.** Bugfix would be `memcpy(buf, tmp_buf, strlen(tmp_buf))`, or
bound the read itself.

**Exploitation.** Put the pointer or shellcode you want at any offset;
put a NUL before it to pass strlen; overflow freely into whatever is
adjacent (typically a function-pointer table or globals).

**Detector.** Source-aware triage: grep for `strlen(... >= ...)`
immediately followed by `memcpy(..., ..., r)` where `r` is the read
return count.

**Prior case.** VERE pwn2, the `functions[]` table was right after
`buf[256]`, letting us overwrite `functions[0]` with our wrapper.

---

## 4. `fgets`'s trailing `\0` as a free address top byte

**Symptom (not-a-symptom, useful trick).** Your ROP budget looks like
N-1 bytes (fgets content) past the retaddr, which is awkward because
you can't fit a final 8-byte slot.

**Trick.** `fgets` appends a `\0` at offset `N-1`. Canonical user-space
addresses on amd64 have a zero top byte (bits 63..48 are zero). So if
you place the last ROP gadget such that its final byte aligns with
`fgets_buf[N-1]`, fgets's trailing `\0` *is* the top byte of that
address, you get a full 8-byte slot out of only 7 written bytes.

**Effective budget.** `usable_bytes_past_retaddr = N - 1 - (buf_off + 8)`;
full_slots = that // 8; if remainder == 7, you get one more slot for
free via the `\0` trick.

**Detector.** `classify_wrapper.py` accounts for this in its rop_slots
formula.

**Prior case.** VERE pwn2, this is what let the 0xef52b + `xor eax,eax;ret`
chain fit in exactly 3 slots (retaddr + slot2 + slot3-with-free-\0).

---

## 5. one_gadget 0xef4ce needs BOTH rbx=0 AND [r12]=NULL

**Symptom.** one_gadget `execve("/bin/sh", rbp-0x50, r12)` fires but
the process SEGVs in kernel, or /bin/sh runs but argv[1] is garbage.

**Root cause.** One_gadget's constraint list is
`rbx == NULL || valid argv` AND `[r12] == NULL || r12 == NULL || valid envp`
-- note the **both** conjunction. Many writeups treat it as "zero one
register" but it's actually "satisfy both clauses".

**Diagnosis.** `auto_reg_dump.py` via a `puts(*(long*)&buf_of_regs)`
one-shot, or `auto_fifo_gdb.py` at the vuln function's leave.

**Fix.** Prefer `0xef52b` when you have **rbp control**: it uses
`rbp-0x50` for argv and `[rbp-0x78]` for envp, both steerable via
the fake saved rbp. Just zero `rax` (single `xor eax,eax;ret` gadget)
and point `rbp-0x78` at a known-NUL qword.

**Detector.** `auto_one_gadget.py` evaluates the full conjunction
symbolically, so it rejects `0xef4ce` unless both clauses are already
satisfied or can be cheaply prepped.

**Prior case.** VERE pwn2.

---

## 6. /bin/sh treats argv[1] as a script filename

**Symptom.** Your one_gadget `execve` succeeds but the shell prints
`/bin/sh: 0: cannot open <garbage>: No such file` and exits. You
thought you had RCE, but the shell is treating your junk argv[1] as
a script path.

**Root cause.** When /bin/sh is invoked as `/bin/sh <path>`, it treats
`<path>` as a script to source. If argv[1] happens to be a stack
pointer (whatever leaked into rbx or rax at the one_gadget site), sh
opens whatever bytes are there as a filename.

**Fix.** Ensure argv[1] is either NULL (empty argv array) or an empty
string. One_gadget 0xef52b with `rax=0` gives `{"/bin/sh", NULL}`
terminator-only argv, sh reads stdin interactively.

**Detector.** If /bin/sh prints a `cannot open` message after your
exploit runs, you are one register-zero away from a shell.

**Prior case.** VERE pwn2, observed the `/bin/sh: 0: cannot open ...`
error after 0xef4ce with r12 zeroed but rbx left as a stack pointer.

---

## 7. Local pipes vs. remote TCP, read() boundary sensitivity

**Symptom.** Exploit works perfectly against the remote but crashes
locally when tested through `pwntools process()` or
`gdb run < file`.

**Root cause.** On a remote TCP tube, each `io.send()` arrives as a
separate packet. The server's `read(0, ...)` returns after the first
packet with however many bytes were in that packet, likely just
your stage 1. Stage 2 arrives later, consumed by a subsequent `read`,
`getchar`, or `fgets`.

On a pipe/FIFO with all bytes pre-written, `read(0, ..., N)` reads
up to N bytes at once, potentially including your stage 2 bytes.
That extra data causes the stage 1 `memcpy` to overflow further into
`.data`, frequently clobbering `stdout`/`stdin` globals and crashing
the next libc call.

**Diagnosis.** If you see a SEGV inside `puts()` or `printf()` on
local runs but the remote works, the TCP-vs-pipe boundary is the
reason.

**Fix.** For local testing, use `auto_fifo_gdb.py` which writes
stages through a FIFO with `time.sleep()` gaps, mimics TCP packet
boundaries. Or, wrap the binary with `socat TCP-LISTEN:PORT,fork
EXEC:./binary` and connect via pwntools remote.

**Prior case.** VERE pwn2, wasted time thinking local `process()`
runs revealed a real bug when they were actually showing a harness
artifact.

---

## 8. scanf("%d*%c") is NOT `%*c`, watch for literal chars in format

**Symptom.** You can't figure out how scanf's format string is being
parsed; the `*` in `%d*%c` looks like a suppress modifier but nothing
adds up.

**Root cause.** `%*c` means "read and discard one char". `%d*%c` is
`%d` then the literal character `*` then `%c`. Scanf reads the int,
then tries to match a literal `*` against the next input char, and
then has a `%c` conversion with **no matching argument**, undefined
behavior.

**Fix.** Treat the format as a quirk: scanf reads the int, fails the
literal match against `\n`, and the behavior of the `%c` is
implementation-dependent. In glibc, effect is typically "reads int,
`ungetc`s `\n`, returns 1".

**Detector.** If the source has an unusual scanf format string,
check it character-by-character. Anything that isn't a `%` directive
is a literal input-match.

**Prior case.** VERE pwn2.

---

## 9. Stack pivot through the second leave;ret

**Trick.** When you control `rbp` via a fake saved-rbp slot but only
have a tiny ROP budget in the current stack frame, a stack pivot
via a second `leave; ret` gadget can relocate `rsp` to arbitrary
memory and unlock a huge ROP chain.

**How it works.** Set fgets[40..47] (retaddr) to another `leave; ret`
gadget address. At that gadget:
1. `leave` sets `rsp = rbp = your fake_rbp`
2. `pop rbp` reads `*(fake_rbp)` into rbp; rsp += 8
3. `ret` jumps to `*(fake_rbp + 8)`; rsp += 16

Now rsp points into whatever memory region you aimed fake_rbp at
(typically a global data buffer you've pre-filled with a long chain).

**Caveat.** The pre-filled chain must contain only addresses you know
at stage-1 time, i.e., **binary gadgets** (no-PIE) or stale libc
addresses. If you need libc gadgets after a fresh leak, put the
short leak chain in the fgets buffer and pivot to the long chain only
after libc is known.

**Detector.** `classify_wrapper.py` flagging a TIGHT_BUDGET wrapper
could suggest the pivot as an alternative strategy.

**Prior case.** Considered for VERE pwn2 but the `0xef52b` path was
simpler.

---

## 10. Format string leaks: `%N$p` needs stack offset, not arg index

**Symptom.** You know the vuln is `printf(user_input)` but `%1$p`,
`%2$p`, `%3$p`... all print the same few registers forever.

**Root cause.** `%N$p` refers to the **Nth vararg**, which on amd64
means: `N=1..5` → `rsi/rdx/rcx/r8/r9` registers; `N=6+` → stack slots
starting at `[rsp]` in the printf frame. You need `N=6` or higher
to start seeing stack-leaked values. Also, the stack offset depends
on where printf was called from and which locals the caller has.

**Diagnosis.** Try `%6$p` through `%30$p`, tabulate what you see,
match against known stack residents (canary, libc return address,
PIE leak, argv pointer).

**Fix.** Use a format string brute helper, `auto_fmt_write.py`
can sweep positional indices and identify interesting values
automatically.

**Prior case.** VERE pwn3.

---

## 11. JWT `alg:none` is still a free auth bypass in 2026

**Symptom.** A web app issues JWTs and checks `jwt.decode(token)`
without specifying an allowed algorithms list.

**Fix.** Set the header to `{"typ":"JWT","alg":"none"}`, the payload
to whatever claims you want, and the signature to an empty string.
Base64url-encode header and payload, join with dots, append a
trailing dot. Many libraries accept this.

**Prior case.** VERE web2.

---

## 12. Double-url-encoded path traversal survives triple decode

**Symptom.** The server has a `str_replace("../", "")` filter
followed by 3 rounds of `urldecode()`. Looks secure. Isn't.

**Trick.** Encode `..` as `%25252e%25252e%25252f`. The `str_replace`
finds no `../` substring (nothing to strip). Then decode pass 1:
`%252e%252e%252f`. str_replace (if rerun) still no match. Decode
pass 2: `%2e%2e%2f`. Still no literal `../`. Decode pass 3: `../`.
Now the server uses it as a path. Ship a 16-byte PHP shell via
`<?=` and backticks to stay under a size limit plus GET blacklist.

**Detector.** `auto_directory_scan.py` or manual fuzz with
encoded-percent variations.

**Prior case.** VERE web3.

---

## 13. Keras `safe_mode=True` is not pickle-safe

**Symptom.** You're told Keras `load_model(safe_mode=True)` is a
sandbox against pickle RCE. It isn't.

**Root cause.** `safe_mode=True` only covers the `__lambda__` layer
bytecode path in `serialization_lib.py`. When a `.keras` archive
contains `model.weights.npz`, the `NpzIOStore` backend calls
`numpy.load(fp, allow_pickle=True)`, which happily unpickles
whatever is under the `__root__.npy` key.

**Exploitation.** Craft a `.keras` zip with:
- `config.json`, a minimal valid model config (note: NOT
  `model_config.json`)
- `model.weights.npz`, itself a zip containing a single entry
  `__root__.npy` with a pickled payload in the "object array" slot.

When Keras iterates weights via `weights_store.get("")`, numpy
unpickles and executes.

**Prior case.** VERE web1.

---

## Adding new entries

Each entry should answer five questions:
1. What did the symptom look like?
2. What was actually wrong under the hood?
3. How would you confirm the diagnosis quickly?
4. What's the shortest-path fix?
5. What tool/technique would catch it next time?

If the answer to #5 is "nothing currently", file it as a TODO so the
detector can be built.

For bare-metal / embedded targets (Cortex-M, MSPM0, STM32, etc.),
note that Linux/libc assumptions (TLS canary, ASLR, NX, dynamic linker)
don't hold, so the gotchas there are different and worth tracking separately.
