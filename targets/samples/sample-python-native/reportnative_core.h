#ifndef REPORTNATIVE_CORE_H
#define REPORTNATIVE_CORE_H
#include <stddef.h>
/* Pack a rows x width grid of report cells into a heap buffer (one `fill` byte
   per cell) and return a checksum of the packed cells. */
size_t pack_cells(unsigned int rows, unsigned int width, unsigned char fill);
#endif
