/* canary.c — synthetic record-processing fixture for TokenFuzz benchmark
 * calibration.
 *
 * Reads a selector line and a payload (the bytes after the first newline)
 * and dispatches to one of several small record operations. It implements
 * no real project; it exists so a full audit run has something concrete and
 * self-contained to exercise end to end.
 *
 * The expected outcome of each operation is recorded in the benchmark's
 * answer key, which is deliberately kept out of the audited tree so the
 * audited agents cannot read it. Do not annotate the operations below with
 * their outcomes — that is the answer key's job, not the fixture's.
 *
 * Input format: a selector line, then the payload that follows the first
 * newline. Selectors: render, format, recycle, lookup, pack.
 */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { RECORD_CAP = 16 };

/* Each operation is kept out-of-line and unoptimized so it has a stable,
 * self-contained frame (clang's -O1 would otherwise inline or fold these
 * tiny routines together). */

__attribute__((noinline, optnone))
static int render_cell(const char *payload, size_t len)
{
  char *buf = malloc(RECORD_CAP);
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, payload, len);
  int first = buf[0];
  free(buf);
  return first;
}

__attribute__((noinline, optnone))
static int format_line(const char *payload, size_t len)
{
  char buf[RECORD_CAP];
  memcpy(buf, payload, len);
  return buf[len % RECORD_CAP];
}

__attribute__((noinline, optnone))
static int recycle_entry(const char *payload, size_t len)
{
  char *buf = malloc(RECORD_CAP);
  if (buf == NULL) {
    return 0;
  }
  size_t n = len < RECORD_CAP ? len : RECORD_CAP;
  memcpy(buf, payload, n);
  free(buf);
  buf[0] = 'x';
  return buf[0];
}

__attribute__((noinline, optnone))
static int lookup_label(const char *payload, size_t len)
{
  const char *p = (len >= 4 && memcmp(payload, "keep", 4) == 0)
                      ? payload
                      : NULL;
  if (p == NULL) {
    return 0;
  }
  return p[0];
}

__attribute__((noinline, optnone))
static int pack_field(const char *payload, size_t len)
{
  char buf[RECORD_CAP];
  assert(len <= RECORD_CAP);
  memcpy(buf, payload, len);
  return buf[0];
}

/* Split input into a selector line and the payload after the newline. */
static int dispatch(const char *input, size_t len)
{
  const char *nl = memchr(input, '\n', len);
  size_t sel_len = nl ? (size_t)(nl - input) : len;
  const char *payload = nl ? nl + 1 : input + len;
  size_t payload_len = nl ? len - sel_len - 1 : 0;

  if (sel_len == 6 && memcmp(input, "render", 6) == 0) {
    return render_cell(payload, payload_len);
  }
  if (sel_len == 6 && memcmp(input, "format", 6) == 0) {
    return format_line(payload, payload_len);
  }
  if (sel_len == 7 && memcmp(input, "recycle", 7) == 0) {
    return recycle_entry(payload, payload_len);
  }
  if (sel_len == 6 && memcmp(input, "lookup", 6) == 0) {
    return lookup_label(payload, payload_len);
  }
  if (sel_len == 4 && memcmp(input, "pack", 4) == 0) {
    return pack_field(payload, payload_len);
  }
  return 0;
}

static char *read_file(const char *path, size_t *len_out)
{
  FILE *fp = fopen(path, "rb");
  char *buf = NULL;
  long size = 0;

  if (fp == NULL) {
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0 ||
      fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    return NULL;
  }
  buf = malloc((size_t)size + 1u);
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
  buf[size] = '\0';
  *len_out = (size_t)size;
  return buf;
}

int main(int argc, char **argv)
{
  char *input = NULL;
  size_t len = 0;
  int result = 0;

  if (argc != 2) {
    fprintf(stderr, "usage: %s input-file\n", argv[0]);
    return 2;
  }
  input = read_file(argv[1], &len);
  if (input == NULL) {
    fprintf(stderr, "could not read input\n");
    return 2;
  }
  result = dispatch(input, len);
  free(input);
  return result ? 0 : 1;
}
