# Exploratory profiles: 2026-10-27

These are flat profiles of single runs, taken after the timing matrix on the
same host. They locate where time goes. They are not measurements of the
change, and they are not repeated. The raw `perf.data` files are not kept.

## Method

Each profile records one `--time` run of a binary listed in `manifest.json`:

    perf record -F 999 -o <file> -- <binary> --time <workload>
    perf report -i <file> --stdio --no-children --sort symbol -n

`perf` is 6.1.187. Call stacks were not recorded, so the shares below belong
to the sampled function itself. Kernel samples have no resolved symbols.
In the glibc builds, the unresolved addresses near `0x163000` are inside
the shared C library.

## Top functions

| Binary | Workload | Samples | Top functions, share of samples |
|---|---|---:|---|
| main, glibc | `append-512x257` | 8,150 | `Renderer::render` 60.2%, `project_padded` 5.2%, `project_owned` 4.7% |
| main, musl | `append-512x257` | 27,370 | `memcmp` 71.0%, `Renderer::render` 19.0% |
| change, musl | `append-512x257` | 48,580 | `memcmp` 84.7%, `Renderer::render` 10.9% |
| main, glibc | `echo-200x50` | 455 | `Renderer::render` 23.5%, `TerminalCore::frame` 18.4%, `project_padded` 11.5%, `project_owned` 10.5% |
| change, glibc | `echo-200x50` | 358 | `Renderer::render` 27.4%, `TerminalCore::fill` 20.8%, `project_owned` 18.7% |
| main, musl | `echo-200x50` | 1,783 | `memcmp` 39.0%, `Renderer::render` 7.1% |
| change, musl | `echo-200x50` | 1,890 | `memcmp` 73.5%, `Renderer::render` 7.1%, `memmove` 7.0% |
| main, musl, harness of 2026-10-26 | `echo-200x50` | 2,548 | `memcmp` 56.8%, `Renderer::render` 6.5% |

The last row is the `main` musl binary of
[`../2026-10-26-frame-storage/`](../2026-10-26-frame-storage/).

## Comparison counts

To check whether the two builds compare different amounts of memory, the
glibc builds were run with a preloaded library that replaces `memcmp` and
`bcmp` and counts calls and bytes. Totals over one `--time` process,
preparation and warm-up included:

| Workload | Build | Calls | Bytes |
|---|---|---:|---:|
| `echo-200x50` | main | 25,908,267 | 1,658,126,201 |
| `echo-200x50` | change | 25,908,682 | 1,658,551,161 |
| `stream-200x50` | main | 8,317,457 | 532,314,312 |
| `stream-200x50` | change | 8,317,873 | 532,740,296 |

The library was built with `gcc -O2 -shared -fPIC` from:

```c
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned long long calls, asked, scanned;
static int cmp(const void *a, const void *b, size_t n) {
    const unsigned char *l = a, *r = b; size_t i = 0;
    calls++; asked += n;
    for (; i < n && l[i] == r[i]; i++);
    scanned += i < n ? i + 1 : n;
    return i < n ? l[i] - r[i] : 0;
}
int memcmp(const void *a, const void *b, size_t n) { return cmp(a, b, n); }
int bcmp(const void *a, const void *b, size_t n) { return cmp(a, b, n); }
__attribute__((destructor)) static void report(void) {
    fprintf(stderr, "cmp calls %llu asked %llu scanned %llu\n", calls, asked, scanned);
}
```

`Bytes` is the total length passed. Nearly every comparison found its
operands equal, so nearly all of it was read.

The builds compare the same memory to within 0.1%. About 64 bytes per call
matches the 16 combining-mark slots of a cell.

## `memcmp` placement in the musl builds

musl's `memcmp` is a loop over single bytes. Its address differs between
builds, because it is linked after code that differs:

| Binary | `memcmp` address | Offset modulo 64 |
|---|---:|---:|
| main, musl, harness of 2026-10-26 | `0xb2a9b` | 27 |
| change `09236be`, musl | `0xb4a1b` | 27 |
| main, musl (this run) | `0xb2c8b` | 11 |
| change `da9bd81`, musl | `0xb381b` | 27 |

At offset 27, the loop's first compare and branch, at bytes 2 to 6 of the
function, cross a 32-byte boundary. At offset 11 they do not. On this CPU
family, a jump that crosses or ends on a 32-byte boundary is slower under
the JCC erratum microcode update. That would explain why the binary at
offset 11 spends a smaller share in `memcmp` while comparing the same bytes.
This explanation is not established: the microcode state of the host was
not checked, and no binary was rebuilt to move `memcmp`.
