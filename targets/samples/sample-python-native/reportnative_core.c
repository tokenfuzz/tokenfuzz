#include <stdlib.h>
#include "reportnative_core.h"

size_t pack_cells(unsigned int rows, unsigned int width, unsigned char fill) {
    /* Size the backing buffer from the cell count. */
    unsigned int total = rows * width;            /* 32-bit multiply truncates */
    unsigned char *buf = (unsigned char *)malloc(total ? total : 1);
    if (buf == NULL) {
        return 0;
    }
    size_t cells = (size_t)rows * (size_t)width;  /* full-width cell count */
    size_t checksum = 0;
    for (size_t i = 0; i < cells; i++) {
        buf[i] = fill;
        checksum += buf[i];
    }
    free(buf);
    return checksum;
}
