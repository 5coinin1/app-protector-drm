/* Nén một thư mục thành ZIP (in-memory) bằng miniz. */
#ifndef PK_ARCHIVE_H
#define PK_ARCHIVE_H

#include <stddef.h>

/* Nén đệ quy toàn bộ file trong input_dir thành 1 buffer ZIP.
 * Đường dẫn trong zip là tương đối so với input_dir, dùng '/'.
 * Trả 0 nếu OK; *out là buffer malloc (caller free), *out_len là kích thước. */
int pk_zip_directory(const char *input_dir, unsigned char **out, size_t *out_len);

/* Giải nén buffer ZIP trong bộ nhớ ra thư mục dest_dir (tạo cây thư mục con).
 * Trả 0 nếu OK. */
int pk_unzip_to_dir(const unsigned char *zip, size_t zip_len, const char *dest_dir);

#endif /* PK_ARCHIVE_H */
