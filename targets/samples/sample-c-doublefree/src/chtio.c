/*
 * chtio.c — Chunk Transfer stream reader implementation.
 *
 * The reader is a single forward pass over a flat type-length-value field
 * sequence (see include/chtio.h for the wire layout). Each field type has a
 * small handler that folds the field into a transfer context; the context owns
 * the reassembly buffer and accumulates lightweight summaries (digest, label
 * count, mode) that a caller can read back after the pass completes.
 */
#include "chtio.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Staging buffers are deliberately small: the format is meant for short
 * control-plane transfers, not bulk data. */
enum {
  CHT_LABEL_CAP = 64, /* transfer label buffer, NUL-terminated */
  CHT_TRAIL_CAP = 32  /* stream trailer scratch                */
};

/* Rolling transfer state threaded through every handler. The context owns
 * `chunk` for as long as a transfer is in flight. */
typedef struct {
  uint8_t *chunk;   /* reassembly buffer of the in-flight transfer, or NULL */
  uint16_t cap;     /* capacity of that buffer                              */
  uint16_t used;    /* bytes assembled into it so far                       */
  uint32_t digest;  /* digest of the last sealed transfer                   */
  size_t   labels;  /* count of recorded labels                             */
  uint8_t  mode;    /* value of the last optional note                      */
} cht_ctx;

/* ── Small endian / hashing helpers ──────────────────────────────────── */

static uint16_t read_be16(const uint8_t *p)
{
  return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t fnv1a(const uint8_t *p, size_t n)
{
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n; i++) {
    h ^= p[i];
    h *= 16777619u;
  }
  return h;
}

/* ── Field handlers ──────────────────────────────────────────────────── */

/* OPEN: begin a transfer by sizing its reassembly buffer. The value carries a
 * u16 capacity. Re-opening while a transfer is in flight releases the previous
 * buffer and starts over. */
static void handle_open(cht_ctx *ctx, const uint8_t *val, uint16_t len)
{
  if (len < 2) {
    return;
  }

  uint16_t cap = read_be16(val);
  uint8_t *chunk = malloc(cap ? cap : 1);
  if (chunk == NULL) {
    return;
  }

  free(ctx->chunk);
  ctx->chunk = chunk;
  ctx->cap   = cap;
  ctx->used  = 0;
}

/* PUSH: append payload bytes to the in-flight transfer. A payload that does
 * not fit the remaining window is a framing violation: the partial transfer is
 * released and the caller is told to stop the pass. */
static int handle_push(cht_ctx *ctx, const uint8_t *val, uint16_t len)
{
  if (ctx->chunk == NULL) {
    return 0;
  }

  if ((size_t)ctx->used + len > ctx->cap) {
    /* Release the partial transfer and abort the pass. */
    free(ctx->chunk);
    ctx->used = 0;
    return -1;
  }

  memcpy(ctx->chunk + ctx->used, val, len);
  ctx->used = (uint16_t)(ctx->used + len);
  return 0;
}

/* SEAL: digest the bytes assembled so far. */
static void handle_seal(cht_ctx *ctx)
{
  if (ctx->chunk != NULL) {
    ctx->digest = fnv1a(ctx->chunk, ctx->used);
  }
}

/* LABEL: record a short transfer label. A label longer than the buffer is
 * truncated to what fits; the result is always NUL-terminated. */
static void handle_label(cht_ctx *ctx, const uint8_t *val, uint16_t len)
{
  char label[CHT_LABEL_CAP];
  size_t n = len < sizeof(label) - 1 ? len : sizeof(label) - 1;

  memcpy(label, val, n);
  label[n] = '\0';
  ctx->labels += strlen(label) ? 1 : 0;
}

/* NOTE: an optional mode note. The value is only inspected when it spells
 * "on"; otherwise the field carries no note and is ignored. */
static void handle_note(cht_ctx *ctx, const uint8_t *val, uint16_t len)
{
  const uint8_t *note = (len >= 2 && memcmp(val, "on", 2) == 0) ? val : NULL;

  if (note == NULL) {
    return;
  }
  ctx->mode = note[len - 1];
}

/* TRAIL: a bounded stream trailer. Its length must fit the scratch buffer; a
 * longer trailer indicates a corrupt stream and trips a debug invariant. */
static void handle_trail(cht_ctx *ctx, const uint8_t *val, uint16_t len)
{
  uint8_t scratch[CHT_TRAIL_CAP];

  assert(len <= sizeof(scratch));
  memcpy(scratch, val, len);
  ctx->digest ^= fnv1a(scratch, len);
}

/* ── Dispatch and top-level pass ─────────────────────────────────────── */

/* Returns 0 to continue the pass, or negative to abort it. */
static int dispatch(cht_ctx *ctx, uint8_t type, const uint8_t *val,
                    uint16_t len)
{
  switch (type) {
    case CHT_T_OPEN:  handle_open(ctx, val, len); break;
    case CHT_T_PUSH:  return handle_push(ctx, val, len);
    case CHT_T_SEAL:  handle_seal(ctx); break;
    case CHT_T_LABEL: handle_label(ctx, val, len); break;
    case CHT_T_NOTE:  handle_note(ctx, val, len); break;
    case CHT_T_TRAIL: handle_trail(ctx, val, len); break;
    default:          break; /* unknown tag: skip */
  }
  return 0;
}

int cht_read(const uint8_t *data, size_t len)
{
  if (data == NULL || len < CHT_MAGIC_LEN ||
      memcmp(data, CHT_MAGIC, CHT_MAGIC_LEN) != 0) {
    return -1;
  }

  cht_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));

  const uint8_t *p = data + CHT_MAGIC_LEN;
  size_t remaining = len - CHT_MAGIC_LEN;
  int fields = 0;
  int rc = 0;

  while (remaining >= CHT_FIELD_HEADER) {
    uint8_t  type = p[0];
    uint16_t flen = read_be16(p + 1);
    p += CHT_FIELD_HEADER;
    remaining -= CHT_FIELD_HEADER;

    /* Clamp the value to what is actually present so a handler never walks off
     * the end of the stream on the declared length alone. */
    if (flen > remaining) {
      flen = (uint16_t)remaining;
    }

    rc = dispatch(&ctx, type, p, flen);
    if (rc != 0) {
      break;
    }

    p += flen;
    remaining -= flen;
    fields++;
  }

  /* Release the transfer buffer before returning. */
  free(ctx.chunk);
  return rc == 0 ? fields : -2;
}
