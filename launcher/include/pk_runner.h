/* Chạy tiến trình + quản lý thư mục tạm (Windows). */
#ifndef PK_RUNNER_H
#define PK_RUNNER_H

#include <stddef.h>

/* Lấy thư mục chứa file exe đang chạy (không có dấu '/' cuối). Trả 0 nếu OK. */
int pk_exe_dir(char *out, size_t cap);

/* Tạo một thư mục tạm duy nhất (vd %TEMP%\pklaunch_<pid>_<tick>). Trả 0 nếu OK. */
int pk_make_temp_dir(char *out, size_t cap);

/* Chạy exe_path với thư mục làm việc workdir, chờ thoát, trả exit code qua *exit_code.
 * Trả 0 nếu khởi chạy được. */
int pk_run_and_wait(const char *exe_path, const char *workdir, int *exit_code);

/* Xóa đệ quy thư mục (rm -rf). Trả 0 nếu OK. */
int pk_remove_dir_recursive(const char *path);

#endif /* PK_RUNNER_H */
