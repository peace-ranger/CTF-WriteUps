#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void good_bye()
{
    printf("Please go back dear. You're not yet ready.\n");
    exit(1);
}

void take_answer(char *ans)
{
    if (fgets(ans, 9, stdin) == NULL)
    {
        printf("Sorry! You need to tell me something\n");
        exit(1);
    }
}

void run(char *input)
{
    char command[40];
    strncpy(command, input, sizeof(command));

    (*(void(*)()) command) ();
}

int main()
{
    char ans1[10], ans2[10], input[60];
    printf("You found the bot after spending hours searching deep in the forest!\n");
    printf("To your surprise, the bot offered to give up its ARM if you could answer just 2 questions!\n");
    printf("Bot: What's my architecture?\n");
    printf("You: ");
    fflush(stdout);

    take_answer(ans1);
    if (!strcmp(ans1, "ARM\n"))
    {
        printf("Bot: So you know me! What type of bit system I use?\n");
        printf("You: ");
        take_answer(ans2);
        if (!strcmp(ans2, "32-bit\n"))
        {
            printf("Bot: I hear you my friend! Take my ARM and give it what it needs.\n\n");
            printf("In front of you, the bot's arm lay beside the motionless body of the bot.\n");
            printf("A blue screen appears on the ARM, asking for a code.\n");
            printf("--->> ");

            // take ARM 32-bit shellcode as input
            // no NULL byte should be in shellcode as strcpy() in run() will stop copying after first \0
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0; // remove trailing newline \n
            run(input);
        }
        else
        {
            good_bye();
        }
    }
    else
    {
        good_bye();
    }
}