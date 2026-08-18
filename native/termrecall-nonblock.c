/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int flags;

    (void)argv;
    if (argc != 1) {
        return 64;
    }
    flags = fcntl(STDIN_FILENO, F_GETFL);
    if (flags == -1) {
        return 1;
    }
    return fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == -1 ? 1 : 0;
}
