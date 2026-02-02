from lz4.block import compress
from io import BytesIO
from os import path, rename
from pickle import load
from struct import pack, pack_into
from sys import exit


class Writer:
    def __init__(self, working_dir):
        self.working_dir = working_dir
        self.assemblies_folder = path.join(working_dir, "assemblies")
        self.new_blob_bin = BytesIO()
        data = self.get_data()
        self.header = data["header"]
        self.elf = data["elf"]
        self.is64bit = self.elf["is64bit"]
        self.ml = data["ml"]
        self.ms = data["ms"]
        self.assemblies = sorted(
            data["assemblies"], key=lambda assembly: assembly.mapping_index
        )
        self.assembly_data = {}

    def walk(self):
        self.prepare_blob()
        self.write_blob()
        self.write_libassemblies()
        print(" Done.")

    def get_data(self):
        data_path = path.join(self.assemblies_folder, "libassemblies.data")
        if path.isfile(data_path):
            with open(data_path, "rb") as f:
                return load(f)
        exit("Error: « assemblies » folder not found.")

    def prepare_blob(self):
        offset = self.assemblies[0].data_offset
        print(" Creating blob")
        rti = "RTId" if self.assemblies[0].index_rt_desc_array else ""
        print(
            "{:{ml}}{:<6}{:<8}{:<{ms}}{}".format(
                "Name", "MId", rti, "Size", "Δ", ml=self.ml, ms=self.ms
            )
        )
        for assembly in self.assemblies:
            if not assembly.ignore:
                with open(path.join(self.assemblies_folder, assembly.name), "rb") as f:
                    if assembly.is_compressed:
                        data = (
                            b"XALZ"
                            + assembly.index_rt_desc_array
                            + compress(
                                f.read(), compression=12, mode="high_compression"
                            )
                        )
                    else:
                        data = f.read()
                    data_size = len(data)
                    diff_size = data_size - assembly.data_size
                    self.assembly_data[assembly] = BytesIO(data)
                    assembly.data_size = data_size
                    assembly.data_offset = offset
                    if assembly.debug_offset:
                        assembly.debug_offset = offset + data_size
                    if assembly.config_offset:
                        assembly.config_offset = (
                            offset + data_size + assembly.debug_size
                        )
                    offset += data_size + assembly.debug_size + assembly.config_size
                    print(
                        "{:{ml}}{:<6}{:<8}{:<{ms}}{}".format(
                            assembly.name,
                            assembly.mapping_index,
                            (
                                str(
                                    int.from_bytes(
                                        assembly.index_rt_desc_array, "little"
                                    )
                                )
                                if rti
                                else ""
                            ),
                            assembly.data_size,
                            diff_size,
                            ml=self.ml,
                            ms=self.ms,
                        )
                    )
            else:
                print("Ignored:", f" {assembly.mapping_index:<3}", assembly.name)

    def write_blob(self):
        self.new_blob_bin.write(
            pack(
                "<5I",
                self.header.magic,
                self.header.version,
                self.header.entry_count,
                self.header.index_entry_count,
                self.header.index_size,
            )
        )

        index_entries = []
        for assembly in self.assemblies:
            index_entries.append(
                (assembly.hashes[0], assembly.mapping_index, assembly.ignore)
            )
            index_entries.append(
                (assembly.hashes[1], assembly.mapping_index, assembly.ignore)
            )
        index_entries = sorted(index_entries, key=lambda index_entry: index_entry[0])
        for ie in index_entries:
            if self.header.version & 0xF > 2:
                self.new_blob_bin.write(
                    pack("<QI?" if self.is64bit else "<II?", ie[0], ie[1], ie[2])
                )
            else:
                self.new_blob_bin.write(
                    pack("<QI" if self.is64bit else "<II", ie[0], ie[1])
                )

        for assembly in self.assemblies:
            self.new_blob_bin.write(
                pack(
                    "<7I",
                    assembly.mapping_index,
                    assembly.data_offset,
                    assembly.data_size,
                    assembly.debug_offset,
                    assembly.debug_size,
                    assembly.config_offset,
                    assembly.config_size,
                )
            )

        for assembly in self.assemblies:
            name = assembly.name.encode()
            name_length = len(assembly.name)
            self.new_blob_bin.write(pack("<I", name_length))
            self.new_blob_bin.write(name)

        for assembly in self.assemblies:
            if not assembly.ignore:
                data = self.assembly_data[assembly].getvalue()
                self.new_blob_bin.write(data)
                if assembly.debug_size:
                    debug_file = path.join(
                        self.assemblies_folder, path.splitext(assembly.name)[0] + ".pdb"
                    )
                    with open(debug_file, "rb") as g:
                        self.new_blob_bin.write(g.read())
                if assembly.config_size:
                    config_file = path.join(
                        self.assemblies_folder,
                        path.splitext(assembly.name)[0] + ".config",
                    )
                    with open(config_file, "rb") as g:
                        self.new_blob_bin.write(g.read())

    def write_libassemblies(self):
        print(" Writing libassemblies")
        libassemblies = self.elf["libassemblies"]
        lib = bytearray(self.elf["lib"])
        sh_table = bytearray(self.elf["sh_table"])

        blob = self.new_blob_bin.getvalue()
        blob_size = len(blob)

        if self.header.version & 0xF > 2:
            mod = 16 if self.elf["e_machine"] == 0xB7 else 8
            n_extra_bytes = mod - len(blob) % mod
        else:
            n_extra_bytes = 0
        extra_bytes = n_extra_bytes * b"\x00"

        blob_size_offset = (0x20 if self.is64bit else 0x14) * (
            2 * self.elf["shblob_index"] + 1
        )
        pack_into("<Q" if self.is64bit else "<I", sh_table, blob_size_offset, blob_size)

        e_shoff_offset = 0x28 if self.is64bit else 0x20
        new_e_shoff = len(lib) + blob_size + n_extra_bytes
        pack_into("<Q" if self.is64bit else "<I", lib, e_shoff_offset, new_e_shoff)

        output = libassemblies + ".tmp"
        with open(output, "wb") as f:
            f.write(lib + blob + extra_bytes + sh_table)
        rename(libassemblies, libassemblies + ".ori")
        rename(output, libassemblies)
