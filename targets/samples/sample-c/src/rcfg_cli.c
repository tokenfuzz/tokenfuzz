/*
 * rcfg_cli.c — command-line front end for the RCF decoder.
 *
 * Reads an RCF stream from the file named on the command line and decodes it.
 * This is the entry point an audit harness drives: it turns a file of bytes
 * into a single rcfg_decode() call over the exact input length.
 */
#include "rcfg.h"

#include <stdio.h>
#include <stdlib.h>

/* Read the whole file into a freshly allocated buffer sized to its exact
 * length. The caller owns the returned buffer. */
static uint8_t *read_file(const char *path, size_t *len_out)
{
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    return NULL;
  }

  long size = 0;
  if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0 ||
      fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    return NULL;
  }

  uint8_t *buf = malloc((size_t)size);
  if (buf == NULL) {
    fclose(fp);
    return NULL;
  }
  if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
    free(buf);
    fclose(fp);
    return NULL;
  }

  fclose(fp);
  *len_out = (size_t)size;
  return buf;
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    fprintf(stderr, "usage: %s stream-file\n", argv[0]);
    return 2;
  }

  size_t   len = 0;
  uint8_t *data = read_file(argv[1], &len);
  if (data == NULL) {
    fprintf(stderr, "could not read input\n");
    return 2;
  }

  int fields = rcfg_decode(data, len);
  free(data);

  if (fields < 0) {
    fprintf(stderr, "not an RCF stream\n");
    return 1;
  }
  printf("decoded %d field(s)\n", fields);
  return 0;
}
