# Generation 1 User-Space Rootkit (LD_PRELOAD/ld.so.preload Hooking)

## Overview
This project is a user-space hooking experiment for academic research in a controlled lab.
It uses dynamic linker preloading to intercept selected libc calls.

## Important Notice
This code is for authorized, isolated testing only.
Do not run it on production systems or systems you do not own and control.

## What It Hooks
The shared library currently overrides:

- `readdir`
- `accept`
- `accept4`
- `write`
- `open`
- `openat`

## Observed Behavior

1. File and directory listing filtering
The `readdir` hook skips entries that match (will be improoved soon ):
- `config`
- `rootkit`
- `secret`

2. Socket accept inspection
The `accept` and `accept4` hooks pass accepted sockets to `inspect_and_shell`.
If the peer source port equals `61004` (`MAGIC_SOURCE_PORT`), the code forks and tries to execute `/bin/sh` with stdio redirected to that socket.

3. Output suppression
The `write` hook scans outgoing buffers and suppresses content containing:
- `config`
- `rootkit`
- `secret`

4. Access redirection for selected paths
The `open` and `openat` hooks redirect attempts to open paths containing:
- `ld.so.preload`
- `libsystemd-auth.so`
to `/dev/null`.

## Build
Requirements:
- `gcc`
- `make`

Build command:

```bash
make
```

Output artifact:
- `libsystemd-auth.so`

## Lab-Only Execution Example
1-Move the payload to a legitimate-looking system directory:

```bash
mv libsystemd-auth.so /lib/x86_64-linux-gnu/
```
2-Inject the payload into the dynamic linker's preload configuration:

```bash
echo "/lib/x86_64-linux-gnu/libsystemd-auth.so" >> /etc/ld.so.preload
```
## Clean
```bash
make clean
```