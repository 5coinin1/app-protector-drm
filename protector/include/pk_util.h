/* Tiện ích: đọc/ghi file, kiểm tra tồn tại, tạo thư mục, timestamp. */
#ifndef PK_UTIL_H
#define PK_UTIL_H

#include <stddef.h>

/* Đọc toàn bộ file vào buffer cấp phát động. Trả 0 nếu OK, -1 nếu lỗi.
 * Caller phải free(*out). */
int pk_read_file(const char *path, unsigned char **out, size_t *out_len);

/* Ghi buffer ra file. Trả 0 nếu OK, -1 nếu lỗi. */
int pk_write_file(const char *path, const unsigned char *data, size_t len);

/* 1 nếu file/thư mục tồn tại. */
int pk_exists(const char *path);

/* Tạo thư mục (đệ quy, kiểu mkdir -p). Trả 0 nếu OK. */
int pk_mkdir_p(const char *path);

/* Ghi timestamp ISO-8601 UTC vào buf (cần >= 21 byte). */
void pk_iso8601_utc(char *buf, size_t buf_size);

#endif /* PK_UTIL_H */
