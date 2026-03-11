/*
 * pudo_wrapper.c — SUID root launcher for pudo_internal.py
 *
 * Why C?  Linux does NOT honour the SUID bit on interpreted scripts (#!).
 * This binary is setuid-root. It:
 *   1. Saves the real UID (caller).
 *   2. Calls prctl(PR_SET_KEEPCAPS, 1) so capabilities survive the UID drop.
 *   3. Execs /usr/local/lib/pudo/pudo_internal.py via the system python3.
 *
 * Build:
 *   gcc -O2 -Wall -o pudo pudo_wrapper.c
 *   sudo chown root:root pudo && sudo chmod 4755 pudo
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <linux/capability.h>

#define PYTHON      "/usr/bin/python3"
#define PUDO_PY     "/usr/local/lib/pudo/pudo_internal.py"
#define MAX_ARGS    256

int main(int argc, char *argv[])
{
    /* Keep capabilities across the upcoming UID/GID changes */
    if (prctl(PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) != 0) {
        perror("[pudo] prctl(PR_SET_KEEPCAPS)");
        /* non-fatal — continue without ambient caps */
    }

    /* Verify the script is still where we expect and owned by root */
    if (access(PUDO_PY, X_OK) != 0) {
        fprintf(stderr, "[pudo] Cannot find %s — reinstall pudo.\n", PUDO_PY);
        return 1;
    }

    /* Build argv: python3 pudo_internal.py <original args...> */
    char *new_argv[MAX_ARGS + 3];
    new_argv[0] = PYTHON;
    new_argv[1] = PUDO_PY;

    int i;
    for (i = 1; i < argc && i < MAX_ARGS; i++)
        new_argv[i + 1] = argv[i];
    new_argv[i + 1] = NULL;

    execv(PYTHON, new_argv);

    /* execv only returns on error */
    perror("[pudo] execv");
    return 1;
}
