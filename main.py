# @ waves
import pefile,sys,os;from capstone import *;


if os.name == 'nt': pip = "pip";clear = "cls"
elif os.name == 'posix': pip = "pip3";clear = "clear"


try:
    os.system(f"{pip} install capstone")
    os.system(f"{pip} install pefile")
except:
    pass


class EXE_DISASM:
    def __init__(self, file):
            self.file = file

    def asam_dump(self,file):
            file_loaded = pefile.PE(file)
            file_entry_point = file_loaded.OPTIONAL_HEADER.AddressOfEntryPoint
            data = file_loaded.get_memory_mapped_image()[file_entry_point:]
            cs = Cs(CS_ARCH_X86, CS_MODE_32)
            rdbin = cs.disasm(data, 0x1000)
            for i in rdbin:
                print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


class PE_FILE_FORMAT:
        def __init__(self, file):
            self.file = file

        def show_format(self, file):
            exe = pefile.PE(file)
            print(str(exe))


def main():
        os.system(clear)
        print(f"""Options: -p, -d
        \nUsage: ./{sys.argv[0]} <option> <file>""")

        choice = sys.argv[1]
        if choice == "-p":
                FILE__ = PE_FILE_FORMAT(sys.argv[2])
                FILE__.show_format(sys.argv[2])
        elif choice == "-d":
                FILE_ = EXE_DISASM(sys.argv[2])
                FILE_.asam_dump(sys.argv[2])


if __name__ == "__main__":
    main()
