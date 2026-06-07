# abo-builder

> Experimental ELF64 → ABO converter for Annwyn applications.

═════════════════════════════════════════════════════════

## ◉ What is abo-builder?

`abo-builder` converts ELF64 executables into the ABO (Application Bundle Object) format used by Annwyn.

The tool is responsible for:

✓ Parsing ELF64 binaries

✓ Extracting loadable segments

✓ Building ABO containers

✓ Embedding application metadata

✓ Generating deterministic UUIDs

✓ Validating ABO files

✓ Inspecting existing bundles

The produced bundles are intended to be loaded by the Annwyn runtime.

═════════════════════════════════════════════════════════

## ◉ Format

⟦ ***ABO v0*** ⟧

The current format contains:

• Header

• Manifest

• Segment table

• Segment data

```text
+-------------------+
| Header            |
+-------------------+
| Manifest          |
+-------------------+
| Segment Table     |
+-------------------+
| Segment Data      |
+-------------------+
```

ABO v0 is still experimental and may change significantly.

═════════════════════════════════════════════════════════

## ◉ Project Status

⟦ ***Early Development*** ⟧

Current features include:

• ELF64 parsing

• PT_LOAD extraction

• Segment conversion

• Manifest embedding

• Deterministic UUID generation

• Bundle validation

• Bundle inspection

This repository is currently an experimentation platform rather than a stable packaging tool.

═════════════════════════════════════════════════════════

## ◉ Current Progress

### Implemented

* [x] ELF64 parser
* [x] ET_EXEC support
* [x] ET_DYN support
* [x] Segment extraction
* [x] Manifest support
* [x] Deterministic UUID generation
* [x] ABO validation
* [x] ABO dumping

### In Progress

* [ ] Improved validation
* [ ] Better diagnostics
* [ ] Rich metadata

### Planned

* [ ] WASM payload support
* [ ] Compression
* [ ] Signature support
* [ ] Dependency metadata
* [ ] ABI versioning

═════════════════════════════════════════════════════════

## ◉ Building

### Build

```bash
cargo build --release
```

═════════════════════════════════════════════════════════

## ◉ Usage

### Convert ELF to ABO

```bash
abo-builder init.elf init.abo
```

### With a manifest

```bash
abo-builder init.elf init.abo --manifest manifest.txt
```

### Override metadata

```bash
abo-builder init.elf init.abo \
    --name init \
    --version 0.1.0 \
    --cap-req IpcEndpoint:SEND \
    --cap-exp service://init \
    --sandbox no_network
```

═════════════════════════════════════════════════════════

## ◉ Validation

Validate an existing bundle:

```bash
abo-builder --check init.abo
```

Inspect its contents:

```bash
abo-builder --dump init.abo
```

═════════════════════════════════════════════════════════

## ◉ Manifest Format

⟦ ***KEY=VALUE*** ⟧

Example:

```text
NAME=init
VERSION=0.1.0

CAP_REQ=IpcEndpoint:SEND
CAP_REQ=Memory:MAP

CAP_EXP=service://init

SANDBOX=no_network
SANDBOX=no_filesystem
```

Supported directives:

| Directive | Description         |
| --------- | ------------------- |
| `NAME`    | Component name      |
| `VERSION` | Component version   |
| `CAP_REQ` | Required capability |
| `CAP_EXP` | Exposed service     |
| `SANDBOX` | Sandbox restriction |

═════════════════════════════════════════════════════════

## ◉ ELF Requirements

Input binaries should:

• Be ELF64

• Target x86_64

• Contain PT_LOAD segments

• Be compiled as ET_EXEC or ET_DYN

Typical build command:

```bash
cargo build --target x86_64-unknown-none
```

For PIE executables, the runtime currently assumes a load base of:

```text
0x00400000
```

which must remain synchronized with the kernel.

═════════════════════════════════════════════════════════

## ◉ Contributing

Contributions, discussions, ideas, criticism, and questions are welcome.

Please keep in mind that:

• Format compatibility is more important than features.

• Simplicity is preferred over complexity.

• Changes must remain synchronized with the kernel loader.

• Backward compatibility should be considered whenever possible.

═════════════════════════════════════════════════════════

## ◉ Related Repositories

• annwyn-kernel

• annwyn-runtime

• annwyn-sdk

• annwyn-docs

═════════════════════════════════════════════════════════

## ◉ License

Licensed under either of:

* MIT License

* Apache License 2.0

at your option.
