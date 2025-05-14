#include <stdio.h>
#include <klee/klee.h>

void log_data(const char* data) {
    FILE *log = fopen("logfile.txt", "a");
    fprintf(log, "LOG: %s\n", data); // Privacy violation
    fclose(log);
}

int main() {
    char secret[4];
    klee_make_symbolic(secret, sizeof(secret), "secret");
    secret[3] = '\0';

    if (secret[0] == 'k') {
        log_data(secret);
    }

    return 0;
}
