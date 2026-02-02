<div align="center">
  <h1 align="center">XaBlob</h1>
  <p align="center">
    Python tool to unpack/repackage Xamarin assembly store.
  </p>
</div>

### Support
Xamarin assembly store format version 2 and version 3

### Requierements
1. Python3
2. lz4 python package.
   ```bash
   pip3 install -U --user 'lz4'
   ```
### Installation
Download the wheel here: https://github.com/Kirlif/XaBlob/releases/latest
   ```bash
pip install --user xablob-1.1-py3-none-any.whl
   ```
or direcly
   ```bash
pip install --user https://github.com/Kirlif/XaBlob/releases/download/1.1/xablob-1.1-py3-none-any.whl
   ```

### Usage
#### from CLI<br>
xablob [-h] [-v] [-l LIB_PATH | -u LIB_PATH | -p [LIB_DIR] | -c [LIB_DIR]]


#### options<br>
<strong>-l</strong>:
show assembly store content<br>
requiered argument: path to the elf

<strong>-u</strong>:
unpack dlls in « assemblies » folder next to the elf<br>
requiered argument: path to the elf

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

- runtime config blob?
