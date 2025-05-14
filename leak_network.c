#include <stdio.h>
#include <string.h>
#include <klee/klee.h>

void send_data(const char* buf) {
    printf("Sending: %s\n", buf); // Treated as network sink
}

int main() {
    char sensitive[4];
    klee_make_symbolic(sensitive, sizeof(sensitive), "sensitive");
    sensitive[3] = '\0';

    if (strcmp(sensitive, "abc") == 0) {
        send_data(sensitive); // Privacy violation
    }

    return 0;
}
