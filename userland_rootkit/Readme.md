# Generation 1 User-Space function Hooking Demo

## Overview
This project is a simple user-space function-hooking experiment for academic project.
It builds a shared object that is intended to be loaded through the dynamic linker preload mechanism.

## Important Notice
Use only in authorized, isolated test environments.
Do not run on production systems or systems you do not own and control.

## Constants Used By The Current Code
- `MAGIC_PORT`: `58231`
- `HIDDEN_PREFIX`: `7fd5bc27_735a_4172-9d66_d94c102fc43f`
- `EVIL_LIB`: `libsystemd-auth.so`
- `PRELOAD_FILE`: `/etc/ld.so.preload`

## Hooked Functions
The current implementation in `main.c` overrides these libc interfaces:

- `readdir`
- `read`
- `__xstat`
- `stat`
- `open`
- `accept`
- `accept4`
- `write`

## Current Behavior
1. Entry filtering in directory listings
`readdir` skips entries whose names contain any of:
- `HIDDEN_PREFIX`
- `EVIL_LIB`
- `ld.so.preload`

2. Read-buffer scrubbing
`read` clears returned buffers when matched content includes:
- `HIDDEN_PREFIX`
- `EVIL_LIB`

3. Metadata manipulation for selected paths
`stat` and `__xstat` set `st_size = 0` when the path is considered hidden.

4. Path redirection
`open` redirects hidden paths to `/dev/null`.

5. Socket-triggered shell path
`accept` and `accept4` check incoming IPv4 source port values.
When source port matches `MAGIC_PORT`, child-process logic attempts to exec `/bin/sh` with stdio redirected to the accepted socket.

6. Write output suppression
`write` returns success without writing when outgoing data matches:
- `HIDDEN_PREFIX`
- `EVIL_LIB`

## Build
Requirements:
- `gcc`
- `make`

Build the shared object:

```bash
make
```

Output artifact:
- `libsystemd-auth.so`

## Makefile Targets
- `make`: build `libsystemd-auth.so`
- `make clean`: remove object and shared library artifacts
- `make install`: copy library to `/usr/local/lib/` and append it to `/etc/ld.so.preload`