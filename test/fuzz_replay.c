/*
 * Replay driver for the libFuzzer harnesses, used for coverage measurement.
 *
 * libFuzzer normally supplies main() and drives LLVMFuzzerTestOneInput() with
 * mutated inputs. For a REPEATABLE coverage measurement we instead link this
 * plain main() against a fuzzer's sources (compiled with gcc --coverage and
 * -DFUZZ_REPLAY, no libFuzzer runtime) and replay a fixed corpus: every file
 * under each directory argument (and any file arguments) is read once and fed
 * to LLVMFuzzerTestOneInput(). This works unchanged for BOTH fuzz_console.c
 * and fuzz_backup.c, which each define LLVMFuzzerTestOneInput()/
 * LLVMFuzzerInitialize().
 */

#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Provided by the fuzzer .c linked alongside this main. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
/* Optional one-time setup; weak so a harness without it still links. */
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

static void replay_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "replay: cannot open %s\n", path);
        return;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return;
    }
    rewind(f);

    uint8_t *buf = malloc((size_t)sz + 1); /* +1 so a 0-byte file still mallocs */
    if (!buf) {
        fclose(f);
        return;
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    LLVMFuzzerTestOneInput(buf, n);
    free(buf);
}

static void replay_dir(const char *path) {
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "replay: cannot open dir %s\n", path);
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.')
            continue; /* skip ".", "..", dotfiles */
        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        struct stat st;
        if (stat(child, &st) == 0 && S_ISREG(st.st_mode))
            replay_file(child);
    }
    closedir(d);
}

int main(int argc, char **argv) {
    if (LLVMFuzzerInitialize)
        LLVMFuzzerInitialize(&argc, &argv);

    for (int i = 1; i < argc; i++) {
        struct stat st;
        if (stat(argv[i], &st) != 0) {
            fprintf(stderr, "replay: cannot stat %s\n", argv[i]);
            continue;
        }
        if (S_ISDIR(st.st_mode))
            replay_dir(argv[i]);
        else
            replay_file(argv[i]);
    }
    return 0;
}
