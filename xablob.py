#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
xablob
by Kirlif'
December 2024
"""

from io import BytesIO
from os import getcwd, listdir, mkdir, path, remove, rename, rmdir
from pickle import dump, load
from struct import pack, pack_into, unpack, unpack_from
from sys import exit
import lz4.block

class Header:
    def __init__(self, magic, version, entry_count, index_entry_count, index_size):
        self.magic = magic
        self.version = version
        self.entry_count = entry_count
        self.index_entry_count = index_entry_count
        self.index_size = index_size


class IndexEntry:
    def __init__(self, name_hash, descriptor_index):
        self.name_hash = name_hash
        self.descriptor_index = descriptor_index


class EntryDescriptor:
    def __init__(self, mapping_index, data_offset, data_size, debug_data_offset,
                 debug_data_size, config_data_offset, config_data_size):
        self.mapping_index = mapping_index
        self.data_offset = data_offset
        self.data_size = data_size
        self.debug_data_offset = debug_data_offset
        self.debug_data_size = debug_data_size
        self.config_data_offset = config_data_offset
        self.config_data_size = config_data_size


class TemporaryItem:
    def __init__(self, name, descriptor):
        self.name = name
        self.descriptor = descriptor
        self.index_entries = []


class AssemblyStoreItem:
    def __init__(self, name, is64bit, hashes):
        self.name = name
        self.is64bit = is64bit
        self.hashes = hashes


class StoreItemV2(AssemblyStoreItem):
    def __init__(self, target_arch, name, is64bit, index_entries, descriptor):
        super().__init__(name, is64bit, self.index_to_hashes(index_entries))
        self.data_offset = descriptor.data_offset
        self.data_size = descriptor.data_size
        self.debug_offset = descriptor.debug_data_offset
        self.debug_size = descriptor.debug_data_size
        self.config_offset = descriptor.config_data_offset
        self.config_size = descriptor.config_data_size
        self.mapping_index = descriptor.mapping_index
        self.target_arch = target_arch
        self.is_compressed = None

    def index_to_hashes(self, index_entries):
        return [ie.name_hash for ie in index_entries]


class Reader:
    MACHINES = {
        0x03: "X86",
        0x28: "ARM32",
        0x3E: "X86_64",
        0xB7: "ARM64"
    }
    def __init__(self, libassemblies):
        self.libassemblies = libassemblies
        self.assemblies_folder = path.join(path.dirname(self.libassemblies), "assemblies")
        self.store = None
        self.shblob_index = None
        self.blob_offset = None
        self.blob_size = None
        self.lib = None
        self.pre_sh_table = None
        self.sh_table = None
        self.is64bit = None
        self.assemblies = None
        self.header = None

    def walk(self):
        self.get_store()
        self.get_assemblies()
        self.write_assemblies()
        self.write_data()
        print(f"  dll files unpacked to {self.assemblies_folder}")

    def get_store(self):
        with open(self.libassemblies, "rb") as elf:
            lib = elf.read()
            ei_class = lib[4]
            e_machine = unpack_from("<H", lib, 0x12)[0]
            try:
                self.is64bit = "64" in self.MACHINES[e_machine] and ei_class == 2
            except KeyError:
                exit(f"Error: {path.basename(self.libassemblies)} is not supported.")
            e_shoff = unpack_from("<Q", lib, 0x28)[0] if self.is64bit else unpack_from("<I", lib, 0x20)[0]
            e_shentsize = unpack_from("<H", lib, 0x3A if self.is64bit else 0x2E)[0]
            e_shnum = unpack_from("<H", lib, 0x3C if self.is64bit else 0x30)[0]
            e_shstrndx = unpack_from("<H", lib, 0x3E if self.is64bit else 0x32)[0]
            sh_table_size = e_shnum * e_shentsize
            elf.seek(e_shoff)
            self.sh_table = elf.read(sh_table_size)
            section_size = 0x40 if self.is64bit else 0x28
            section_headers = [self.sh_table[i * section_size: (i + 1) * section_size] for i in range(e_shnum)]
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
            shstrtab = lib[shstrtab_offset: shstrtab_offset + shstrtab_size]
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
                unpack_from("<Q", shblob_header, 0x18)[0] if self.is64bit else unpack_from("<I", shblob_header, 0x10)[0]
            )
            self.blob_size = (
                unpack_from("<Q", shblob_header, 0x20)[0] if self.is64bit else unpack_from("<I", shblob_header, 0x14)[0]
            )
            self.lib = lib[:self.blob_offset]
            self.pre_sh_table = lib[self.blob_offset + self.blob_size: e_shoff]
            elf.seek(self.blob_offset)
            self.store = BytesIO(elf.read(self.blob_size))

    def get_assemblies(self):
        magic, version, entry_count, index_entry_count, index_size = unpack("<5I", self.store.read(20))
        header = Header(magic, version, entry_count, index_entry_count, index_size)

        self.header = header
        assembly_count = header.entry_count
        index_entry_count = header.index_entry_count

        index = []
        for _ in range(index_entry_count):
            if self.is64bit:
                name_hash, descriptor_index = unpack("<QI", self.store.read(12))
            else:
                name_hash, descriptor_index = unpack("<II", self.store.read(8))
            index.append(IndexEntry(name_hash, descriptor_index))

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
                    names[ie.descriptor_index], descriptors[ie.descriptor_index]
                )
            temp_items[ie.descriptor_index].index_entries.append(ie)

        assert len(temp_items) == len(descriptors)

        store_items = []
        target_arch = 8 if self.is64bit else 4
        for ti in temp_items.values():
            item = StoreItemV2(target_arch, ti.name, self.is64bit, ti.index_entries, ti.descriptor)
            store_items.append(item)
        self.assemblies = store_items

    def write_assemblies(self):
        def write(name, dat, comp=False):
            with open(path.join(self.assemblies_folder, name), "wb") as f:
                if comp:
                    f.write(lz4.block.decompress(dat[8:]))
                else:
                    f.write(dat)

        if not path.isdir(self.assemblies_folder):
            mkdir(self.assemblies_folder)

        for assembly in self.assemblies:
            self.store.seek(assembly.data_offset)
            data = self.store.read(assembly.data_size)
            compressed = data[:4] == b"XALZ"
            assembly.is_compressed = compressed
            write(assembly.name, data, compressed)
            if assembly.debug_size:
                self.store.seek(assembly.debug_offset)
                debug_data = self.store.read(assembly.debug_size)
                write(path.splitext(assembly.name)[0] + ".pdb", debug_data)
            if assembly.config_size:
                self.store.seek(assembly.config_offset)
                config_data = self.store.read(assembly.config_size)
                write(assembly.name + ".config", config_data)

    def write_data(self):
        elf = {
            "lib": self.lib,
            "pre_sh_table": self.pre_sh_table,
            "sh_table": self.sh_table,
            "shblob_index": self.shblob_index,
            "libassemblies": self.libassemblies,
            "is64bit": self.is64bit,
        }
        data = {"elf": elf, "header": self.header, "assemblies": self.assemblies}
        with open(path.join(self.assemblies_folder, "libassemblies.data"), "wb") as f:
            dump(data, f)


class Writer:
    def __init__(self, working_dir):
        self.working_dir = working_dir
        self.assemblies_folder = path.join(working_dir, "assemblies")
        self.blob_bin = path.join(self.assemblies_folder, "blob.bin")
        data = self.get_data()
        self.header = data["header"]
        self.elf = data["elf"]
        self.is64bit = self.elf["is64bit"]
        self.assemblies = sorted(data["assemblies"], key=lambda assembly: assembly.mapping_index)
        self.assembly_data = {}

    def walk(self):
        self.prepare_blob()
        self.write_blob()
        self.write_libassemblies()
        print("  dll files repackaged")

    def get_data(self):
        data_path = path.join(self.assemblies_folder, "libassemblies.data")
        if path.isfile(data_path):
            with open(data_path, "rb") as f:
                return load(f)
        exit("Error: « assemblies » folder not found.")

    def prepare_blob(self):
        offset = self.assemblies[0].data_offset
        for assembly in self.assemblies:
            with open(path.join(self.assemblies_folder, assembly.name), "rb") as f:
                if assembly.is_compressed:
                    data = (
                        b"XALZ"
                        + pack("<I", assembly.mapping_index)
                        + lz4.block.compress(f.read(), compression=12, mode="high_compression")
                    )
                else:
                    data = f.read()
                data_size = len(data)
                diff_size = data_size - assembly.data_size
                if diff_size:
                    print("Modified:", assembly.mapping_index, assembly.name, diff_size)
                self.assembly_data[assembly] = BytesIO(data)
                assembly.data_size = data_size
                assembly.data_offset = offset
                if assembly.debug_offset:
                    assembly.debug_offset = offset + data_size
                if assembly.config_offset:
                    assembly.config_offset = offset + data_size + assembly.debug_size
                offset += data_size + assembly.debug_size + assembly.config_size

    def write_blob(self):
        with open(self.blob_bin, "wb") as f:

            f.write(
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
                index_entries.append((assembly.hashes[0], assembly.mapping_index))
                index_entries.append((assembly.hashes[1], assembly.mapping_index))
            index_entries = sorted(index_entries, key=lambda index_entry: index_entry[0])
            for ie in index_entries:
                f.write(pack("<QI" if self.is64bit else "<II", ie[0], ie[1]))

            for assembly in self.assemblies:
                f.write(
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
                f.write(pack("<I", name_length))
                f.write(name)

            for assembly in self.assemblies:
                data = self.assembly_data[assembly].getvalue()
                f.write(data)
                if assembly.debug_size:
                    debug_file = path.join(self.assemblies_folder, path.splitext(assembly.name)[0] + ".pdb")
                    with open(debug_file, "rb") as g:
                        f.write(g.read())
                if assembly.config_size:
                    config_file = path.join(self.assemblies_folder, path.splitext(assembly.name)[0] + ".config")
                    with open(config_file, "rb") as g:
                        f.write(g.read())

    def write_libassemblies(self):
        libassemblies = self.elf["libassemblies"]
        lib = bytearray(self.elf["lib"])
        pre_sh_table = self.elf["pre_sh_table"]
        sh_table = bytearray(self.elf["sh_table"])

        with open(self.blob_bin, "rb") as f:
            blob = f.read()

        blob_size_offset = (0x20 if self.is64bit else 0x14) * (2 * self.elf["shblob_index"] + 1)
        pack_into("<Q" if self.is64bit else "<I", sh_table, blob_size_offset, len(blob))

        e_shoff_offset = 0x28 if self.is64bit else 0x20
        new_e_shoff = len(lib) + len(blob) + len(pre_sh_table)
        pack_into("<Q" if self.is64bit else "<I", lib, e_shoff_offset, new_e_shoff)

        output = libassemblies + ".tmp"
        with open(output, "wb") as f:
            f.write(lib + blob + pre_sh_table + sh_table)
        rename(libassemblies, libassemblies + ".ori")
        rename(output, libassemblies)

def clean(working_dir):
    assemblies_folder = path.join(working_dir, "assemblies")
    if path.isdir(assemblies_folder):
        for file in listdir(assemblies_folder):
            remove(path.join(assemblies_folder, file))
        rmdir(assemblies_folder)
        print(f"{assemblies_folder} removed")
    else:
        print("assemblies folder not found")


def file_path(string):
    if path.isfile(string):
        return string
    raise()


def dir_path(string):
    if path.isdir(string):
        return string
    raise()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="xablob allows to unpack and repackage dll files\nfrom xamarin assembly store (elf)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument(
        "-u",
        metavar="LIB_PATH",
        help="unpack dlls in « assemblies » folder:\nrequired: path to the elf file",
        type=file_path,
    )
    command_group.add_argument(
        "-p",
        metavar="LIB_DIR",
        nargs="?",
        const=getcwd(),
        help="package dll files\noptional: path to the parent directory of the elf\n\t  current directory by default",
        type=dir_path,
    )
    command_group.add_argument(
        "-c",
        metavar="LIB_DIR",
        nargs="?",
        const=getcwd(),
        help="remove « assemblies » folder\noptional: path to the parent directory of the elf\n\t  current directory by default",
        type=dir_path,
    )
    args = parser.parse_args()
    (
        clean(args.c)
        if args.c
        else Writer(args.p).walk() if args.p
        else Reader(args.u).walk() if args.u
        else parser.print_help()
    )
