Also a beginner level challenge where participants have to leak the **Stack Canary** using the `Format String Vulnerability` in `printf()` function. They have to figure out where in the stack the canary is stored. The CANARY is a 64-bit value as the binary is 64-bit. The **9th** value on the stack is the canary for this challenge which can be leaked by passing `%9$p` as the input. The input buffer is of only 7 bytes so that participants are forced to use the `$` specifier as an argument to printf.
After receiving the CANARY, they have to send it back. The program will compare the received value with original CANARY. If the check is passed, flag will be printed. Use of `pwntools` is needed as input has to be sent based on received response from target remote program.

The stack CANARY  for a function is stored at address [RBP-8] where RBP marks the base of function's stack frame. The original CANARY has been retrieved by using the value inside RBP register through inline assembly in C.

Compiled with `gcc -o chal chal.c`. Symbols have not been stripped to make analysis easier. Otherwise the difficulty would've been higher and more points had to be allocated.
