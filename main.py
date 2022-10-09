# @ waves
from capstone import *
import argparse
import pefile
import sys
import os


def asam_dump():
    file_loaded = pefile.PE(sys.argv[2])
    with open((f"{sys.argv[4]}"), 'x+') as file:
        _entry_point = file_loaded.OPTIONAL_HEADER.AddressOfEntryPoint
        data = file_loaded.get_memory_mapped_image()[_entry_point:]
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        rdbin = cs.disasm(data, 0x1000)
        for instruc in rdbin:
            file.write(f"0x{instruc.address}:\t{instruc.mnemonic}\t{instruc.op_str}\n")
        print(f"[+] Succesfully disassembled {sys.argv[2]}")

def show_format():
    pe = pefile.PE(sys.argv[2])
    with open(f'{sys.argv[4]}', 'x+') as file:
            file.write(f"{str(pe)}")
    print(f"[+] Succesfully brokedown file {sys.argv[2]}")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", 
                        help="Disassemble file and show assembly code")
    parser.add_argument("-p", 
                        help="Show PE file information")
    parser.add_argument("-s",
                        help="Enter file name to save output",
                        action='store')

    cli_args = parser.parse_args()

    if cli_args.p:
        show_format()
    elif cli_args.d:
        asam_dump()


if __name__ == "__main__":
    main()
