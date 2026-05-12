#pragma once
#include <cstring>
#include <cstddef>

namespace uS { namespace prefix_flatten_detail {
// Writes `remaining = totalLen - alreadySent` bytes into `out` (assumed sized properly)
// by walking [header, prefix, body] from `alreadySent`. Pure function — directly testable.
inline void flattenRemainder(char *out,
                             const char *headerSrc, size_t headerLen,
                             const char *prefixSrc, size_t prefixLen,
                             const char *bodySrc, size_t bodyLen,
                             size_t alreadySent) {
    size_t pos = 0;
    size_t cursor = alreadySent;
    if (cursor < headerLen) {
        size_t take = headerLen - cursor;
        std::memcpy(out + pos, headerSrc + cursor, take);
        pos += take; cursor += take;
    }
    if (cursor < headerLen + prefixLen) {
        size_t pStart = cursor - headerLen;
        size_t take = prefixLen - pStart;
        std::memcpy(out + pos, prefixSrc + pStart, take);
        pos += take; cursor += take;
    }
    if (cursor < headerLen + prefixLen + bodyLen) {
        size_t bStart = cursor - headerLen - prefixLen;
        size_t take = bodyLen - bStart;
        std::memcpy(out + pos, bodySrc + bStart, take);
    }
}
}} // namespace uS::prefix_flatten_detail
