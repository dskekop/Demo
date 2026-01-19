#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fprintf(stdout, "[netforward-sidecar-stub] sidecar stub running (no IPC implemented)\n");
    return EXIT_SUCCESS;
}
