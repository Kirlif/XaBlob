import argparse
from os import getcwd, listdir, path, remove, rmdir
from .assembly_reader import Reader
from .assembly_writer import Writer

author = "Kirlif'"
repo = "https://github.com/Kirlif/xablob"
version = 1.1


def clean(working_dir=getcwd(), sub_folder=""):
    assemblies_folder = path.abspath(path.join(working_dir, "assemblies"))
    if path.isdir(assemblies_folder):
        folder = path.join(assemblies_folder, sub_folder)
        for file in listdir(folder):
            if path.isdir(path.join(assemblies_folder, file)):
                clean(working_dir, file)
            else:
                remove(path.join(folder, file))
        rmdir(folder)
        if folder == path.join(assemblies_folder, ""):
            print(f"{assemblies_folder} removed")
    else:
        print("assemblies folder not found")


def list(libass):
    Reader(libass).walk(False)


def pack(working_dir=getcwd()):
    Writer(working_dir).walk()


def unpack(libass):
    Reader(libass).walk()


def file_path(string):
    if path.isfile(string):
        return string
    raise ()


def dir_path(string):
    if path.isdir(string):
        return string
    raise ()


def main():
    parser = argparse.ArgumentParser(
        description="xablob allows to unpack and repackage dll files\nfrom xamarin assembly store (elf)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version="1.1")
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument(
        "-l",
        metavar="LIB_PATH",
        help="show assembly store content:\nrequired: path to the elf file",
        type=file_path,
    )
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
        else (
            pack(args.p)
            if args.p
            else (
                unpack(args.u)
                if args.u
                else list(args.l) if args.l else parser.print_help()
            )
        )
    )


if __name__ == "__main__":
    main()
