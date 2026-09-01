/*
 * gauge.c — Gauge Reading Frame decoder implementation.
 *
 * The decoder is a single forward pass over a flat type-length-value field
 * sequence (see include/gauge.h for the wire layout). Each field type has a
 * small handler that folds the field into a frame context; the context
 * accumulates the running totals and tags a collector reads back after the
 * pass completes.
 */
#include "gauge.h"

#include <stdlib.h>
#include <string.h>

/* Staging buffers are deliberately small: the format is meant for short
 * telemetry frames, not bulk data. */
enum {
  GAU_LABEL_CAP  = 64, /* series label buffer, NUL-terminated */
  GAU_WINDOW_CAP = 32  /* smoothing window scratch            */
};

/* One decoded gauge reading. The raw value and unit come from the fixed head
 * of a SAMPLE body; the scale is a trailing attribute the reading may or may
 * not carry. */
typedef struct {
  uint16_t value;
  uint16_t scale;
  uint8_t  unit;
} gau_point;

/* Rolling decode state threaded through every handler. */
typedef struct {
  uint32_t total;    /* running total of the scaled readings */
  uint32_t smoothed; /* last smoothed total                  */
  size_t   points;   /* count of decoded readings            */
  size_t   labels;   /* count of series labels               */
  uint8_t  units;    /* union of the unit tags seen          */
} gau_ctx;

/* ── Small endian helper ─────────────────────────────────────────────── */

static uint16_t read_be16(const uint8_t *p)
{
  return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

/* ── Field handlers ──────────────────────────────────────────────────── */

/* Fill a reading from a SAMPLE body. The body is a big-endian u16 raw value
 * followed by optional per-reading attributes: byte 2 selects the unit, and a
 * body long enough to carry one supplies an explicit big-endian u16 scale. */
static void decode_point(gau_point *pt, const uint8_t *val, uint16_t len)
{
  pt->value = read_be16(val);
  pt->unit  = len > 2 ? val[2] : 0;

  if (len >= 5) {
    pt->scale = read_be16(val + 3);
  }
}

/* SAMPLE: decode one reading and fold it into the frame totals. */
static void handle_sample(gau_ctx *ctx, const uint8_t *val, uint16_t len)
{
  gau_point pt;

  if (len < 2) {
    return;
  }

  decode_point(&pt, val, len);

  /* A scale of zero means "unscaled"; any other scale divides the reading. */
  if (pt.scale != 0) {
    ctx->total += pt.value / pt.scale;
  } else {
    ctx->total += pt.value;
  }

  ctx->units |= pt.unit;
  ctx->points++;
}

/* WINDOW: smooth the running total over a caller-declared window. The value's
 * first byte selects the window length, clamped to the scratch array; every
 * slot the averaging loop reads was written by the seeding loop above it. */
static void handle_window(gau_ctx *ctx, const uint8_t *val, uint16_t len)
{
  uint32_t slots[GAU_WINDOW_CAP];

  if (len < 1) {
    return;
  }

  size_t n = val[0] < GAU_WINDOW_CAP ? val[0] : GAU_WINDOW_CAP;
  for (size_t i = 0; i < n; i++) {
    slots[i] = ctx->total + (uint32_t)i;
  }

  uint32_t smoothed = 0;
  for (size_t i = 0; i < n; i++) {
    smoothed += slots[i];
  }
  ctx->smoothed = n > 0 ? smoothed / (uint32_t)n : ctx->total;
}

/* LABEL: record a short series label. A label longer than the buffer is
 * truncated to what fits; the result is always NUL-terminated. */
static void handle_label(gau_ctx *ctx, const uint8_t *val, uint16_t len)
{
  char label[GAU_LABEL_CAP];
  size_t n = len < sizeof(label) - 1 ? len : sizeof(label) - 1;

  memcpy(label, val, n);
  label[n] = '\0';
  ctx->labels += strlen(label) ? 1 : 0;
}

/* NOTE: an optional unit note. The value is only inspected when it spells
 * "unit"; otherwise the field carries no note and is ignored. */
static void handle_note(gau_ctx *ctx, const uint8_t *val, uint16_t len)
{
  const uint8_t *note = (len >= 4 && memcmp(val, "unit", 4) == 0) ? val : NULL;

  if (note == NULL) {
    return;
  }
  ctx->units |= note[len - 1];
}

/* ── Dispatch and top-level pass ─────────────────────────────────────── */

static void dispatch(gau_ctx *ctx, uint8_t type, const uint8_t *val,
                     uint16_t len)
{
  switch (type) {
    case GAU_T_SAMPLE: handle_sample(ctx, val, len); break;
    case GAU_T_WINDOW: handle_window(ctx, val, len); break;
    case GAU_T_LABEL:  handle_label(ctx, val, len); break;
    case GAU_T_NOTE:   handle_note(ctx, val, len); break;
    default:           break; /* unknown tag: skip */
  }
}

int gau_decode(const uint8_t *data, size_t len)
{
  if (data == NULL || len < GAU_MAGIC_LEN ||
      memcmp(data, GAU_MAGIC, GAU_MAGIC_LEN) != 0) {
    return -1;
  }

  gau_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));

  const uint8_t *p = data + GAU_MAGIC_LEN;
  size_t remaining = len - GAU_MAGIC_LEN;
  int fields = 0;

  while (remaining >= GAU_FIELD_HEADER) {
    uint8_t  type = p[0];
    uint16_t flen = read_be16(p + 1);
    p += GAU_FIELD_HEADER;
    remaining -= GAU_FIELD_HEADER;

    /* Clamp the value to what is actually present so a handler never walks off
     * the end of the frame on the declared length alone. */
    if (flen > remaining) {
      flen = (uint16_t)remaining;
    }

    dispatch(&ctx, type, p, flen);

    p += flen;
    remaining -= flen;
    fields++;
  }

  return fields;
}
