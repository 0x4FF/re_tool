import pefile
from capstone import *

def PE_FORMAT_DISPLAY():
    file = input(".exe file name: ")
    exe = pefile.PE(file)
    with open('pe_format_log.txt', 'w+') as file:
        file.write(str(exe))

def EXE_DISASSEMBLE():
    file = input(".exe file name: ")
    exe = pefile.PE(file)
    e_p = exe.OPTIONAL_HEADER.AddressOfEntryPoint
    data = exe.get_memory_mapped_image()[e_p:]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    rdbin = cs.disasm(data, 0x1000)
    with open('disam_code.txt', 'w+') as file:
        for i in rdbin:
            file.write("0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str))


def main():
    choice = input("[1] PE Breakdown   [2] Disassemble EXE: ")
    if choice == "1":
        PE_FORMAT_DISPLAY()
        main()
    elif choice == "2":
        EXE_DISASSEMBLE()
        main()


main()