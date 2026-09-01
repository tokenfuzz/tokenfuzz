/*
 * chtio — a compact Chunk Transfer stream reader.
 *
 * CHT is a tiny framing format used to ship a payload to a peer in small
 * chunks over a byte stream. A stream is a 4-byte magic ("CHT1") followed by a
 * flat sequence of type-length-value fields:
 *
 *     +--------+--------+-----------------+
 *     | type   | length | value           |
 *     | u8     | u16 BE | length bytes    |
 *     +--------+--------+-----------------+
 *
 * The reader walks the field sequence, dispatching each field to a handler
 * that folds it into a small in-memory transfer context. One transfer owns one
 * reassembly buffer at a time: OPEN sizes it, PUSH appends into it, SEAL
 * digests it. A field that violates the framing rules aborts the pass so the
 * peer's remaining bytes are never interpreted.
 *
 * This library is a self-contained benchmark fixture for TokenFuzz. It
 * implements no real product; it exists so an audit run has a realistic,
 * professionally structured parser to exercise end to end.
 */
#ifndef CHTIO_H
#define CHTIO_H

#include <stddef.h>
#include <stdint.h>

/* Four-byte stream magic. A stream that does not begin with these bytes is
 * rejected before any field is read. */
#define CHT_MAGIC "CHT1"
#define CHT_MAGIC_LEN 4u

/* On-wire size of a field header: one type byte plus a big-endian u16 length. */
#define CHT_FIELD_HEADER 3u

/* The length field is a u16, so a single field value is at most this many
 * bytes. Handlers use this as the format's declared upper bound. */
#define CHT_MAX_FIELD 65536u

/* Field type tags. Unknown tags are skipped so the format can grow without
 * breaking older readers. */
enum cht_type {
  CHT_T_OPEN  = 0x01, /* begin a transfer, sizing its buffer      */
  CHT_T_PUSH  = 0x02, /* append payload bytes to the transfer     */
  CHT_T_SEAL  = 0x03, /* digest the bytes assembled so far        */
  CHT_T_LABEL = 0x04, /* short transfer label                     */
  CHT_T_NOTE  = 0x05, /* optional mode note, present only when on */
  CHT_T_TRAIL = 0x06  /* bounded stream trailer                   */
};

/*
 * Read a CHT stream.
 *
 * @data must point at @len readable bytes. Returns the number of fields
 * successfully dispatched, or a negative value when the stream is malformed
 * (missing or wrong magic, or a field that violates the framing rules).
 * Reading is best-effort: a field the reader does not recognise is skipped
 * rather than treated as fatal.
 */
int cht_read(const uint8_t *data, size_t len);

#endif /* CHTIO_H */
