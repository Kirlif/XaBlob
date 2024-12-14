<div align="center">
  <h1 align="center">XaBlob</h1>
  <p align="center">
    Python tool to unpack/repackage Xamarin assembly store.
  </p>
</div>

### Requierements
1. Python3
2. lz4 python package.
   ```bash
   pip3 install -U --user 'lz4'
   ```

### Usage
python3 xablob.py [-h] [-u LIB_PATH | -p [LIB_DIR] | -c [LIB_DIR]]


#### options<br>
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


### ToDo
- regular assemblies and satellite assemblies

- runtime config blob?
