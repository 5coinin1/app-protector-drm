#include "pk_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

int pk_read_file(const char *path, unsigned char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);

    unsigned char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(buf); return -1; }
    buf[sz] = '\0';  /* tiện khi dùng như chuỗi */
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

int pk_write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(data, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
}

int pk_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int pk_mkdir_p(const char *path) {
    char tmp[1024];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);

    /* chuẩn hóa '\\' -> '/' để xử lý đồng nhất */
    for (size_t i = 0; i < len; i++)
        if (tmp[i] == '\\') tmp[i] = '/';

    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (!pk_exists(tmp)) mkdir(tmp);
            tmp[i] = '/';
        }
    }
    if (!pk_exists(tmp)) {
        if (mkdir(tmp) != 0) return -1;
    }
    return 0;
}

void pk_iso8601_utc(char *buf, size_t buf_size) {
    time_t now = time(NULL);
    struct tm tm_utc;
#if defined(_WIN32)
    gmtime_s(&tm_utc, &now);
#else
    gmtime_r(&now, &tm_utc);
#endif
    strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}
