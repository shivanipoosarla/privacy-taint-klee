#include <stdio.h>
#include <klee/klee.h>

int main() {
    char input[4];
    klee_make_symbolic(input, sizeof(input), "input");
    input[3] = '\0';

    if (input[0] == 's' && input[1] == 'e' && input[2] == 'c') {
        printf("Sensitive input: %s\n", input); // Privacy violation
    }
    return 0;
}
