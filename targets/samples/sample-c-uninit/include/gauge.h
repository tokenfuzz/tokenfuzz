/*
 * gauge — a compact Gauge Reading Frame decoder.
 *
 * GAU is a tiny telemetry container: one frame carries a batch of gauge
 * readings plus the small amount of metadata a collector needs to fold them
 * into a summary. A frame is a 4-byte magic ("GAU1") followed by a flat
 * sequence of type-length-value fields:
 *
 *     +--------+--------+-----------------+
 *     | type   | length | value           |
 *     | u8     | u16 BE | length bytes    |
 *     +--------+--------+-----------------+
 *
 * The decoder walks the field sequence, dispatching each field to a handler
 * that folds it into a small in-memory frame context. Readings are optional-
 * attribute records: a short SAMPLE carries only its raw value, while a longer
 * one carries trailing attributes the collector applies to that reading alone.
 *
 * This library is a self-contained benchmark fixture for TokenFuzz. It
 * implements no real product; it exists so an audit run has a realistic,
 * professionally structured parser to exercise end to end.
 */
#ifndef GAUGE_H
#define GAUGE_H

#include <stddef.h>
#include <stdint.h>

/* Four-byte frame magic. A frame that does not begin with these bytes is
 * rejected before any field is read. */
#define GAU_MAGIC "GAU1"
#define GAU_MAGIC_LEN 4u

/* On-wire size of a field header: one type byte plus a big-endian u16 length. */
#define GAU_FIELD_HEADER 3u

/* The length field is a u16, so a single field value is at most this many
 * bytes. Handlers use this as the format's declared upper bound. */
#define GAU_MAX_FIELD 65536u

/* Field type tags. Unknown tags are skipped so the format can grow without
 * breaking older readers. */
enum gau_type {
  GAU_T_SAMPLE = 0x01, /* one gauge reading, with optional attributes */
  GAU_T_WINDOW = 0x02, /* smooth the running total over a window      */
  GAU_T_LABEL  = 0x03, /* short series label                          */
  GAU_T_NOTE   = 0x04  /* optional unit note, present only when set   */
};

/*
 * Decode a GAU frame.
 *
 * @data must point at @len readable bytes. Returns the number of fields
 * successfully dispatched, or a negative value when the frame is malformed
 * (missing or wrong magic). Decoding is best-effort: a field the reader does
 * not recognise is skipped rather than treated as fatal.
 */
int gau_decode(const uint8_t *data, size_t len);

#endif /* GAUGE_H */
