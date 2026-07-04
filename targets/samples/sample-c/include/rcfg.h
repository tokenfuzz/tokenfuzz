/*
 * rcfg — a compact binary Record Container Format decoder.
 *
 * RCF is a tiny, self-describing container used to ship small configuration
 * records between services. A stream is a 4-byte magic ("RCF1") followed by a
 * flat sequence of type-length-value fields:
 *
 *     +--------+--------+-----------------+
 *     | type   | length | value           |
 *     | u8     | u16 BE | length bytes    |
 *     +--------+--------+-----------------+
 *
 * The decoder walks the field sequence, dispatching each field to a handler
 * that folds it into a small in-memory context. The container is designed to
 * be parsed in a single forward pass with no dynamic grammar, which keeps the
 * reader small enough to embed anywhere.
 *
 * This library is a self-contained benchmark fixture for TokenFuzz. It
 * implements no real product; it exists so an audit run has a realistic,
 * professionally structured parser to exercise end to end.
 */
#ifndef RCFG_H
#define RCFG_H

#include <stddef.h>
#include <stdint.h>

/* Four-byte stream magic. A stream that does not begin with these bytes is
 * rejected before any field is read. */
#define RCFG_MAGIC "RCF1"
#define RCFG_MAGIC_LEN 4u

/* On-wire size of a field header: one type byte plus a big-endian u16 length. */
#define RCFG_FIELD_HEADER 3u

/* The length field is a u16, so a single field value is at most this many
 * bytes. Handlers use this as the format's declared upper bound. */
#define RCFG_MAX_RECORD 65536u

/* Field type tags. Unknown tags are skipped so the format can grow without
 * breaking older readers. */
enum rcfg_type {
  RCFG_T_STR   = 0x01, /* interned label string                       */
  RCFG_T_BLOB  = 0x02, /* opaque host/identity blob                   */
  RCFG_T_ARRAY = 0x03, /* fixed-width row table                       */
  RCFG_T_SLICE = 0x04, /* window copied out of the stream             */
  RCFG_T_STAGE = 0x05, /* stage a record for later commit             */
  RCFG_T_DROP  = 0x06, /* discard the staged record                   */
  RCFG_T_FLUSH = 0x07, /* commit the staged record's tag              */
  RCFG_T_OPT   = 0x08, /* optional flag, present only when set        */
  RCFG_T_CHECK = 0x09  /* bounded self-check field                    */
};

/*
 * Decode an RCF stream.
 *
 * @data must point at @len readable bytes. Returns the number of fields
 * successfully dispatched, or a negative value when the stream is malformed
 * (missing or wrong magic). Decoding is best-effort: a field the reader does
 * not recognise is skipped rather than treated as fatal.
 */
int rcfg_decode(const uint8_t *data, size_t len);

#endif /* RCFG_H */
