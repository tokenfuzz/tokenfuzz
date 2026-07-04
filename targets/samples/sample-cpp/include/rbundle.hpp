/*
 * rbundle — a compact binary Record Bundle Format decoder (C++).
 *
 * RBF is a tiny, self-describing container used to ship small configuration
 * records between services. A stream is a 4-byte magic ("RBF1") followed by a
 * flat sequence of type-length-value fields:
 *
 *     +--------+--------+-----------------+
 *     | type   | length | value           |
 *     | u8     | u16 BE | length bytes    |
 *     +--------+--------+-----------------+
 *
 * The decoder walks the field sequence, dispatching each field to a handler
 * that folds it into a small in-memory context. It is written in modern C++
 * with standard containers so an audit run has a realistic, professionally
 * structured parser to exercise end to end. It implements no real product; it
 * exists only as a self-contained benchmark fixture for TokenFuzz.
 */
#ifndef RBUNDLE_HPP
#define RBUNDLE_HPP

#include <cstddef>
#include <cstdint>

namespace rbundle {

/* Four-byte stream magic. A stream that does not begin with these bytes is
 * rejected before any field is read. */
constexpr char MAGIC[] = "RBF1";
constexpr std::size_t MAGIC_LEN = 4;

/* On-wire size of a field header: one type byte plus a big-endian u16 length. */
constexpr std::size_t FIELD_HEADER = 3;

/* Field type tags. Unknown tags are skipped so the format can grow without
 * breaking older readers. */
enum Type : std::uint8_t {
  T_TABLE  = 0x01, /* fixed-width row table                        */
  T_HOST   = 0x02, /* opaque host/identity blob                    */
  T_SLICE  = 0x03, /* window copied out of the stream              */
  T_APPEND = 0x04, /* append tag bytes to the running record log   */
  T_STAGE  = 0x05, /* stage a record for later commit              */
  T_DROP   = 0x06, /* discard the staged record                    */
  T_FLUSH  = 0x07, /* commit the staged record's tag               */
  T_OPT    = 0x08, /* optional flag, present only when set          */
  T_CHECK  = 0x09  /* bounded self-check field                      */
};

/*
 * Decode an RBF stream.
 *
 * `data` must point at `len` readable bytes. Returns the number of fields
 * successfully dispatched, or a negative value when the stream is malformed
 * (missing or wrong magic). Decoding is best-effort: a field the reader does
 * not recognise is skipped rather than treated as fatal.
 */
int decode(const std::uint8_t *data, std::size_t len);

}  // namespace rbundle

#endif  // RBUNDLE_HPP
