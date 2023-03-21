#!/usr/bin/env python3

import string
from pwn import *

context.log_level = 'error'

string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()*+\,-./:;<=>?@[\\]^_`{|}~"
flag = ""
correct_count = 1

elf = ELF("./random2")

while True:
    status_expected = correct_count * 'O'
    for c in string:
        p = process([elf.path, flag + c])
        status_got = p.recvall().decode().strip()
        
        # the program gives a status if a character in a particular position is correct
        # 'X' means WRONG, 'O' means CORRECT
        # for example, if 1st character is correct and 2nd charcter is wrong it'll output OX
        if status_got == status_expected:
            correct_count += 1
            flag = flag[:] + c
            print(flag)
            break
    
    # break if last character of the flag '}' is found
    if flag[len(flag) - 1] == '}':
        break
    
print(flag)
