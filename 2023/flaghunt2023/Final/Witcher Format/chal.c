#include <stdio.h>
#include <stdlib.h>

void print_flag()
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
    fflush(stdout);
    exit(0);
}

void canary()
{
    unsigned long *RBP;

    asm ("movq %%rbp, %0"
    : "=r" (RBP)
    );
    // Canary is stored at address [RBP-8]
    // As RBP is a pointer, *(RBP-1) is equivalent to accessing [RBP-8]
    unsigned long CANARY = *(RBP-1);

    char buf[6]; // "%9$p" will print the canary, strict buffer size will force to use '$' format specifier
    printf("Give me the FORMAT: ");
    fflush(stdout);
    fgets(buf, sizeof(buf), stdin);
    printf(buf); // format string vulnerability

    unsigned long input;
    printf("Tell me the secret CANARY: ");
    fflush(stdout);
    scanf("%lu", &input);

    if (CANARY == input)
    {
        printf("So you made your way into the world of Wild Hunt and got the CANARY! You deserve the flag!\n");
        print_flag();
    }
    else
    {
        printf("You failed to bring the CANARY cz you don't know the Witcher Format. You don't belong here!\n");
        exit(1);
    }
    
}

int main()
{
    canary();
}