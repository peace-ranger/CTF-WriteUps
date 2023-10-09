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