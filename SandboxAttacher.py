import argparse
import logging
from syscalls import *
from AwdPwnPatcher import *
from pwn import *

logging.basicConfig(level=logging.INFO)
DEBUG = True

class SandboxAttacher:
    def __init__(self,argv) -> None:
        self.argv = argv        #参数列表
        self.fr = int(argv.fr,16)            #开始跳转进行patch的地址
        self.to = int(argv.to,16)           #最后跳转回的地址
        self.asm = argv.asm          #覆盖掉的指令
        self.rulesNum = len(self.argv.disable_syscalls)
    
    def showDisabled(self):
        logging.info(f'[+] disabled syscall:{", ".join(self.argv.disable_syscalls)}')

    #禁用syscall
    def disable(self):
        binary = self.argv.file
        patcher = AwdPwnPatcher(binary)
        filter_addr = self.setFilters(patcher)
        prog_addr = self.setProg(patcher,filter_addr)

        assembly = f"""
            mov rax,157
            mov rdi,22
            mov rsi,2
            lea rdx,[{prog_addr}]
            syscall
            {self.asm}
            """
        print(assembly)
        patcher.patch_by_jmp(jmp_from=self.fr,jmp_to=self.to,assembly=assembly)
        patcher.save()
        
    def setProg(self,patcher,filter_addr):
        prog = p64(3+len(self.argv.disable_syscalls)) + p64(filter_addr)
        prog_addr = patcher.add_constant_in_ehframe(prog)
        return prog_addr
    
    def setFilters(self,patcher):
        filter = p64(0x20)
        for i,syscall in enumerate(self.argv.disable_syscalls):
            item = 0x15     #记录该条syscall的BPF_JUMP规则
            jt,jf = self.rulesNum-1-i,self.rulesNum-i       #记录匹配到和未匹配到调用号所需跳转的长度
            item += (jt << 16) + (jf << 24)
            item += getSysNum(syscall) << 32
            print(hex(item))
            filter += p64(item)
        filter += p64(6) + p64(0x7fff000000000006)
        filter_addr = patcher.add_constant_in_ehframe(filter)
        return filter_addr


def findInvalid(args):
    invalid = []
    for arg in args:
        if arg not in syscalls:
            invalid.append(arg)
    return invalid

def helpInfo():
    print('''-h --help :  shows instructions\n
          -f --file :   choose the target binary\n
          -d --disable-syscalls :   choose the syscall you want to ban\n
          -a --asm :    your skipped opcode\n
          --fr :    where your patch start\n
          --to :    where you back to main process\n
          ''')

if __name__ == '__main__':
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
        required=True  # 设置为必填参数
        )
    
    #patch跳转回地址
    parser.add_argument('--to', 
        help='跳转回地址',
        required=True  # 设置为必填参数
        )

    #补全跳过的命令
    parser.add_argument('-a','--asm', 
        help='补全指令',
        required=False  # 设置为必填参数
        )
    
    # 解析命令行参数
    args = parser.parse_args()

    # 检查给出的系统调用的正确性
    invalid = findInvalid(args.disable_syscalls)
    if len(invalid)!=0:
        print(f'Invalid syscall: {", ".join(invalid)}')
    else:
        attacher = SandboxAttacher(args)
        attacher.showDisabled()
        attacher.disable()
        print('[+] done!')