import argparse
import lief
from abc import ABC, abstractmethod
from capstone import *
from syscalls import *
from AwdPwnPatcher import *
from info import *
from pwn import *

DEBUG = True
#amd64模板
Assembly = """      
mov rax,157
mov rdi,22
mov rsi,2
lea rdx,[{0}]
syscall
{1}
"""
class SandboxAttacher(ABC):      #父类
    def __init__(self,argv,arch) -> None:
        self.argv = argv        #参数列表
        if not (argv.to is None or argv.fr is None or argv.asm is None):
            self.fr = int(argv.fr,16)            #开始跳转进行patch的地址
            self.to = int(argv.to,16)           #最后跳转回的地址
            self.asm = argv.asm          #覆盖掉的指令
        else:
            self.fr = None
            self.to = None
            self.asm = ""
        
        self.rulesNum = len(self.argv.disable_syscalls)
        self.arch = arch
    
    @abstractmethod
    def showDisabled(self):
        success(f'disabled syscall:{", ".join(self.argv.disable_syscalls)}')
    
    @abstractmethod
    def initializeBinary(self):
        pass

    def automaticStart(self):   #无需用户指定开始patch by jmp的位置，自动识别
        pass

    @abstractmethod
    def disable(self):
        """禁用某些系统调用，主要逻辑所在"""
        pass

class Amd64Attacher(SandboxAttacher):
    def __init__(self,argv,arch) -> None:
        self.argv = argv        #参数列表
        if not (argv.to is None or argv.fr is None or argv.asm is None):
            self.fr = int(argv.fr,16)            #开始跳转进行patch的地址
            self.to = int(argv.to,16)           #最后跳转回的地址
            self.asm = argv.asm          #覆盖掉的指令
        else:
            self.fr = None
            self.to = None
            self.asm = ""
        self.filename = self.argv.file
        self.rulesNum = len(self.argv.disable_syscalls)
        self.arch = arch
        self.initializeBinary()
    
    #初始化二进制文件
    def initializeBinary(self):
        self.patcher = AwdPwnPatcher(self.filename)
        self.elf = ELF(self.filename)

    def showDisabled(self):
        success(f'disabled syscall:{", ".join(self.argv.disable_syscalls)}')

    def makeSectionExecutable(self):
        binary = lief.parse(self.filename+'_patch')
        # 查找 .eh_frame 段,改段表
        eh_frame = None
        
        for section in binary.sections:
            print(section.name)
            if section.name == ".eh_frame":
                eh_frame = section
                break
        if eh_frame:
            # 打印原始段标志
            show(f"Original section flags: {eh_frame.flags}")
            # 设置新标志：RWX（可读、可写、可执行）
            eh_frame.flags = (lief.ELF.Section.FLAGS.ALLOC |  # ALLOC
                  lief.ELF.Section.FLAGS.EXECINSTR |  # EXECINSTR (Executable instructions)
                  lief.ELF.Section.FLAGS.WRITE)   # WRITE
            # 打印修改后的段标志
            show(f"Modified section flags: {eh_frame.flags}")
            # 保存修改后的二进制文件
        else:
            error(".eh_frame section not found")
        # 查找包含 eh_frame 段的 Program Header
        for ph in binary.segments:
            if ph.virtual_address <= binary.get_section('.eh_frame').virtual_address < (ph.virtual_address + ph.virtual_size):
                # 给 Program Header 增加可执行权限
                ph.add(lief.ELF.Segment.FLAGS.X)  # X 代表可执行
                break
        else:
            error(".eh_frame section not found")
        binary.write(self.filename+'_patch')

    #无需用户指定开始patch by jmp的位置，自动识别
    def automaticStart(self):
        mainAddr = self.elf.symbols['main']
        self.fr = mainAddr
        show(f"Main addr: {hex(mainAddr)}")
        code = self.elf.read(mainAddr, 20)  #先读20字节机器码
        # 使用 Capstone 反汇编机器码
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        # 找出5字节空间用于跳转
        # 反汇编指令存储列表
        instructions = []
        byte_count = 0
        additional = 0  #处理额外的情况
        for i in md.disasm(code, mainAddr):
            if i.mnemonic == 'endbr64':     #不替换endbr64
                additional = i.size
                continue
            print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
            byte_count += i.size
            instructions.append(i.mnemonic + ' ' + i.op_str)
            # 只要找到的指令总长度达到或超过 5 字节就停止
            if byte_count >= 5:
                self.to = mainAddr + byte_count + additional
                break
        #将instruction中的内容拼接到asm中去
        self.asm = "\n".join(instructions)
        show("automatic replace: "+self.asm.replace('\n',';'))
    
    #禁用syscall
    def disable(self):
        #未提供相应参数，自动识别
        if self.to is None or self.fr is None or self.asm is None:
            self.automaticStart()
        
        filter_addr = self.setFilters()
        prog_addr = self.setProg(filter_addr)

        assembly = Assembly.format(prog_addr,self.asm)
        print(assembly)
        self.patcher.patch_by_jmp(jmp_from=self.fr,jmp_to=self.to,assembly=assembly)
        self.patcher.save()
        self.makeSectionExecutable()        #赋予ehframe段可执行权限
        
    def setProg(self,filter_addr):
        prog = p64(3+len(self.argv.disable_syscalls)) + p64(filter_addr)
        prog_addr = self.patcher.add_constant_in_ehframe(prog)
        return prog_addr
    
    def setFilters(self):
        filter = p64(0x20)
        for i,syscall in enumerate(self.argv.disable_syscalls):
            item = 0x15     #记录该条syscall的BPF_JUMP规则
            jt,jf = self.rulesNum-1-i, 1 if(i==self.rulesNum-1) else 0  #记录匹配到和未匹配到调用号所需跳转的长度,最后一条记录未匹配跳转到pass
            item += (jt << 16) + (jf << 24)
            item += getSysNum(syscall,self.arch) << 32
            print(hex(item))
            filter += p64(item)
        filter += p64(6) + p64(0x7fff000000000006)
        filter_addr = self.patcher.add_constant_in_ehframe(filter)
        return filter_addr


def findInvalid(args,arch):
    invalid = []
    if arch == 'amd64':
        for arg in args:
            if arg not in Amd64syscalls:
                invalid.append(arg)
    return invalid


if __name__ == '__main__':
    ARCH = 'amd64'      #默认架构
    parser = argparse.ArgumentParser(description="SandboxAttacher")
    #获取禁用禁用的syscall
    parser.add_argument('-d','--disable-syscalls', 
        nargs='+',  # 使用 '+' 表示至少一个，'*' 表示 0 个或多个
        help='需要禁用的系统调用列表',
        required=True  # 设置为必填参数
        )
    #获取要添加沙箱的二进制文件
    parser.add_argument('-f','--file', 
        help='需要禁用系统调用的文件',
        required=True  # 设置为必填参数
        )
    
    #patch起始地址
    parser.add_argument('--fr', 
        help='开始patch的起始地址',
        required=False
        )
    
    #patch跳转回地址
    parser.add_argument('--to', 
        help='跳转回地址',
        required=False
        )

    #补全跳过的命令
    parser.add_argument('--asm', 
        help='补全指令',
        required=False
        )
    
    #指定架构
    parser.add_argument('-a','--arch', 
        help='指定程序架构:[i386,amd64...]',
        required=False  # 默认为amd64
        )
    
    # 解析命令行参数
    args = parser.parse_args()

    if args.arch:
        ARCH = args.arch

    # 检查给出的系统调用的正确性
    invalid = findInvalid(args.disable_syscalls,ARCH)
    if len(invalid)!=0:
        print(f'Invalid syscall: {", ".join(invalid)}')
    else:
        attacher = Amd64Attacher(args,ARCH)
        attacher.showDisabled()
        attacher.disable()
        success('done!')
        