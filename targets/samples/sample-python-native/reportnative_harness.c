#include <stdio.h>
#include "reportnative_core.h"

/* Standalone AddressSanitizer driver for pack_cells: reads one job file whose
   body is "<rows> <width>" and packs that grid, so the native memory bug is
   observable under ASan without an instrumented Python interpreter (importing an
   ASan-built .so under a stock interpreter aborts on link order / SIP). The job
   format mirrors reportkit_cli.py's `native` op — an "op:" header line then a
   "<rows> <width>" body — so the same testcase drives both surfaces. */
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s job-file\n", argv[0]);
        return 2;
    }
    FILE *handle = fopen(argv[1], "r");
    if (handle == NULL) {
        fprintf(stderr, "could not read input\n");
        return 2;
    }
    char line[256];
    unsigned int rows = 0, width = 0;
    int have = 0;
    while (fgets(line, sizeof(line), handle)) {
        if (sscanf(line, "%u %u", &rows, &width) == 2) {
            have = 1;
            break;
        }
    }
    fclose(handle);
    if (!have) {
        fprintf(stderr, "job body must be \"<rows> <width>\"\n");
        return 2;
    }
    printf("native: checksum=%zu\n", pack_cells(rows, width, 0x41));
    return 0;
}
