from lz4.block import compress, decompress
from io import BytesIO
from os import mkdir, path
from pickle import dump
from struct import pack, unpack, unpack_from
from sys import exit
from .assembly_store import *


class Reader:
    MACHINES = {0x03: "X86", 0x28: "ARM32", 0x3E: "X86_64", 0xB7: "ARM64"}

    def __init__(self, libassemblies):
        self.libassemblies = libassemblies
        self.assemblies_folder = path.join(
            path.dirname(self.libassemblies), "assemblies"
        )
        self.store = None
        self.shblob_index = None
        self.blob_offset = None
        self.blob_size = None
        self.lib = None
        self.sh_table = None
        self.e_machine = None
        self.is64bit = None
        self.assemblies = None
        self.header = None

    def walk(self, extract=True):
        self.get_store()
        self.get_assemblies()
        print(f"  assembly store format version: {self.header.version & 0xf}\n")
        if extract:
            self.extract_assemblies()
            self.write_data()
            print(f"\n  dll files unpacked to {self.assemblies_folder}")
        else:
            self.print_assemblies()

    def get_store(self):
        with open(self.libassemblies, "rb") as elf:
            lib = elf.read()
            ei_class = lib[4]
            self.e_machine = unpack_from("<H", lib, 0x12)[0]
            try:
                self.is64bit = "64" in self.MACHINES[self.e_machine] and ei_class == 2
            except KeyError:
                exit(f"Error: {path.basename(self.libassemblies)} is not supported.")
            e_shoff = (
                unpack_from("<Q", lib, 0x28)[0]
                if self.is64bit
                else unpack_from("<I", lib, 0x20)[0]
            )
            e_shentsize = unpack_from("<H", lib, 0x3A if self.is64bit else 0x2E)[0]
            e_shnum = unpack_from("<H", lib, 0x3C if self.is64bit else 0x30)[0]
            e_shstrndx = unpack_from("<H", lib, 0x3E if self.is64bit else 0x32)[0]
            sh_table_size = e_shnum * e_shentsize
            elf.seek(e_shoff)
            self.sh_table = elf.read(sh_table_size)
            section_size = 0x40 if self.is64bit else 0x28
            section_headers = [
                self.sh_table[i * section_size : (i + 1) * section_size]
                for i in range(e_shnum)
            ]
            shstrtab_header = section_headers[e_shstrndx]
            shstrtab_offset = (
                unpack_from("<Q", shstrtab_header, 0x18)[0]
                if self.is64bit
                else unpack_from("<I", shstrtab_header, 0x10)[0]
            )
            shstrtab_size = (
                unpack_from("<Q", shstrtab_header, 0x20)[0]
                if self.is64bit
                else unpack_from("<I", shstrtab_header, 0x14)[0]
            )
            shstrtab = lib[shstrtab_offset : shstrtab_offset + shstrtab_size]
            try:
                shstrtab_blob_index = shstrtab.index(b"payload")
            except ValueError:
                exit("Error: store not found.")
            for i, sh in enumerate(section_headers):
                if unpack("<I", sh[:4])[0] == shstrtab_blob_index:
                    self.shblob_index = i
                    break
            shblob_header = section_headers[self.shblob_index]
            self.blob_offset = (
                unpack_from("<Q", shblob_header, 0x18)[0]
                if self.is64bit
                else unpack_from("<I", shblob_header, 0x10)[0]
            )
            assert self.blob_offset % 0x4000 == 0
            self.blob_size = (
                unpack_from("<Q", shblob_header, 0x20)[0]
                if self.is64bit
                else unpack_from("<I", shblob_header, 0x14)[0]
            )
            self.lib = lib[: self.blob_offset]
            elf.seek(self.blob_offset)
            self.store = BytesIO(elf.read(self.blob_size))

    def get_assemblies(self):
        magic, version, entry_count, index_entry_count, index_size = unpack(
            "<5I", self.store.read(20)
        )
        header = Header(magic, version, entry_count, index_entry_count, index_size)

        self.header = header
        assembly_count = header.entry_count
        index_entry_count = header.index_entry_count

        index = []
        ignore = False
        for _ in range(index_entry_count):
            if self.is64bit:
                if self.header.version & 0xF > 2:
                    name_hash, descriptor_index, ignore = unpack(
                        "<QI?", self.store.read(13)
                    )
                else:
                    name_hash, descriptor_index = unpack("<QI", self.store.read(12))
            else:
                if self.header.version & 0xF > 2:
                    name_hash, descriptor_index, ignore = unpack(
                        "<II?", self.store.read(9)
                    )
                else:
                    name_hash, descriptor_index = unpack("<II", self.store.read(8))
            index.append(IndexEntry(name_hash, descriptor_index, ignore))

        descriptors = []
        for _ in range(assembly_count):
            (
                mapping_index,
                data_offset,
                data_size,
                debug_data_offset,
                debug_data_size,
                config_data_offset,
                config_data_size,
            ) = unpack("<7I", self.store.read(28))
            desc = EntryDescriptor(
                mapping_index,
                data_offset,
                data_size,
                debug_data_offset,
                debug_data_size,
                config_data_offset,
                config_data_size,
            )
            descriptors.append(desc)

        names = []
        for _ in range(assembly_count):
            name_length = unpack("<I", self.store.read(4))[0]
            name_bytes = self.store.read(name_length).decode()
            names.append(name_bytes)

        temp_items = {}
        for ie in index:
            if ie.descriptor_index not in temp_items:
                temp_items[ie.descriptor_index] = TemporaryItem(
                    names[ie.descriptor_index],
                    descriptors[ie.descriptor_index],
                    ie.ignore,
                )
            temp_items[ie.descriptor_index].index_entries.append(ie)

        assert len(temp_items) == len(descriptors)

        store_items = []
        target_arch = 8 if self.is64bit else 4
        for ti in temp_items.values():
            item = StoreItemV2(
                target_arch,
                ti.name,
                self.is64bit,
                ti.index_entries,
                ti.descriptor,
                ti.ignored,
            )
            store_items.append(item)
        self.assemblies = store_items

    def print_assemblies(self):
        assemblies = sorted(self.assemblies, key=lambda ass: ass.mapping_index)
        self.ml = max(len(ass.name) for ass in assemblies) + 2
        self.ms = max(len(str(ass.data_size)) for ass in assemblies) + 2
        rti = "RTId" if assemblies[0].index_rt_desc_array else ""
        print("{:{ml}}{:<6}{:<8}{}".format("Name", "MId", rti, "Size", ml=self.ml))
        for ass in assemblies:
            print(
                "{:{ml}}{:<6}{:<8}{}".format(
                    ass.name,
                    ass.mapping_index,
                    (
                        str(int.from_bytes(ass.index_rt_desc_array, "little"))
                        if rti
                        else ""
                    ),
                    ass.data_size,
                    ml=self.ml,
                )
            )

    def extract_assemblies(self):
        def write(name, dat, compressed=False):
            sub_dir = path.join(self.assemblies_folder, path.dirname(name))
            if not path.isdir(sub_dir):
                mkdir(sub_dir)
            with open(path.join(self.assemblies_folder, name), "wb") as f:
                if compressed:
                    f.write(decompress(dat[8:]))
                else:
                    f.write(dat)

        if not path.isdir(self.assemblies_folder):
            mkdir(self.assemblies_folder)

        print(f"{self.header.entry_count} dll files\n")
        for assembly in sorted(self.assemblies, key=lambda ass: ass.mapping_index):
            if not assembly.ignore:
                self.store.seek(assembly.data_offset)
                data = self.store.read(assembly.data_size)
                compressed = data[:4] == b"XALZ"
                assembly.is_compressed = compressed
                if assembly.is_compressed:
                    assembly.index_rt_desc_array = data[4:8]
                write(assembly.name, data, compressed)
                if assembly.debug_size:
                    self.store.seek(assembly.debug_offset)
                    debug_data = self.store.read(assembly.debug_size)
                    write(path.splitext(assembly.name)[0] + ".pdb", debug_data)
                if assembly.config_size:
                    self.store.seek(assembly.config_offset)
                    config_data = self.store.read(assembly.config_size)
                    write(assembly.name + ".config", config_data)
        self.print_assemblies()

    def write_data(self):
        elf = {
            "lib": self.lib,
            "sh_table": self.sh_table,
            "shblob_index": self.shblob_index,
            "libassemblies": self.libassemblies,
            "e_machine": self.e_machine,
            "is64bit": self.is64bit,
        }
        data = {
            "elf": elf,
            "header": self.header,
            "assemblies": self.assemblies,
            "ml": self.ml,
            "ms": self.ms,
        }
        with open(path.join(self.assemblies_folder, "libassemblies.data"), "wb") as f:
            dump(data, f)
