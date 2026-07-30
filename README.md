<div align="center">
  <h1 align="center">XaBlob</h1>
  <p align="center">
    Python tool to unpack/repackage Xamarin assembly store.
  </p>
</div>

> Fork of [Kirlif/XaBlob](https://github.com/Kirlif/XaBlob) with a fix for
> unpacking/repackaging assemblies that ship `.config` files.

### What's fixed in this fork (v1.2)
- `.config` files now survive an unpack → modify → repack cycle. The reader writes
  them under the name the writer expects, so `xablob -p` no longer fails with
  `FileNotFoundError`.
- Repacking no longer corrupts the blob when a config is missing or substituted:
  the writer resolves config bytes before computing offsets and falls back to a
  minimal valid XML stub, so the Mono/Xamarin runtime no longer crashes on launch
  with `System.TypeLoadException`.

### Support
Xamarin assembly store format version 2 and version 3

### Requirements
1. Python 3
2. `lz4` python package.
   ```bash
   pip3 install -U --user 'lz4'
   ```
   > On externally-managed systems (e.g. Arch Linux, PEP 668), prefer `pipx` or a
   > virtual environment over `pip --user`.

### Installation
Download the wheel here: https://github.com/fanuverse/XaBlob/releases/latest

Recommended (isolated, no system-Python changes):
```bash
pipx install https://github.com/fanuverse/XaBlob/releases/latest/download/xablob-1.2-py3-none-any.whl
```

or directly with pip:
```bash
pip install --user https://github.com/fanuverse/XaBlob/releases/latest/download/xablob-1.2-py3-none-any.whl
```

### Usage
#### from CLI<br>
xablob [-h] [-v] [-l LIB_PATH | -u LIB_PATH | -p [LIB_DIR] | -c [LIB_DIR]]

#### options<br>
<strong>-l</strong>:
show assembly store content<br>
required argument: path to the elf

<strong>-u</strong>:
unpack dlls in « assemblies » folder next to the elf<br>
required argument: path to the elf

<strong>-p:</strong>
package dlls<br>
optional argument: path to the parent directory of the elf<br>
current directory by default

<strong>-c:</strong>
remove « assemblies » folder<br>
optional argument: path to the parent directory of the elf<br>
current directory by default

#### from Python<br>
\>\>\> import xablob<br>
\>\>\> xablob.list(LIB_PATH)<br>
\>\>\> xablob.unpack(LIB_PATH)<br>
\>\>\> xablob.pack(LIB_DIR)<br>
\>\>\> xablob.clean(LIB_DIR)<br>

### ToDo
- regular assemblies and satellite assemblies
- ~~runtime config blob~~ — handled in v1.2
