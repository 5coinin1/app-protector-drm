#include "pk_archive.h"
#include "pk_util.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "miniz.h"

/* Thêm đệ quy tất cả file trong base_dir/rel vào archive.
 * rel = đường dẫn tương đối hiện tại ("" ở gốc). Trả 0 nếu OK. */
static int add_dir(mz_zip_archive *zip, const char *base_dir, const char *rel) {
    char abs_path[2048];
    if (rel[0] == '\0')
        snprintf(abs_path, sizeof(abs_path), "%s", base_dir);
    else
        snprintf(abs_path, sizeof(abs_path), "%s/%s", base_dir, rel);

    DIR *d = opendir(abs_path);
    if (!d) {
        fprintf(stderr, "loi: khong mo duoc thu muc %s\n", abs_path);
        return -1;
    }

    struct dirent *ent;
    int rc = 0;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char child_rel[2048];
        if (rel[0] == '\0')
            snprintf(child_rel, sizeof(child_rel), "%s", ent->d_name);
        else
            snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, ent->d_name);

        char child_abs[2048];
        snprintf(child_abs, sizeof(child_abs), "%s/%s", base_dir, child_rel);

        struct stat st;
        if (stat(child_abs, &st) != 0) { rc = -1; break; }

        if (S_ISDIR(st.st_mode)) {
            rc = add_dir(zip, base_dir, child_rel);
            if (rc != 0) break;
        } else if (S_ISREG(st.st_mode)) {
            /* mức nén mặc định (DEFAULT_LEVEL = 6) */
            if (!mz_zip_writer_add_file(zip, child_rel, child_abs, NULL, 0,
                                        MZ_DEFAULT_COMPRESSION)) {
                fprintf(stderr, "loi: khong them duoc file %s vao zip\n", child_rel);
                rc = -1;
                break;
            }
        }
    }
    closedir(d);
    return rc;
}

int pk_zip_directory(const char *input_dir, unsigned char **out, size_t *out_len) {
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_writer_init_heap(&zip, 0, 0)) {
        fprintf(stderr, "loi: khong khoi tao duoc zip writer\n");
        return -1;
    }

    if (add_dir(&zip, input_dir, "") != 0) {
        mz_zip_writer_end(&zip);
        return -1;
    }

    void *buf = NULL;
    size_t buf_len = 0;
    if (!mz_zip_writer_finalize_heap_archive(&zip, &buf, &buf_len)) {
        fprintf(stderr, "loi: khong finalize duoc zip\n");
        mz_zip_writer_end(&zip);
        return -1;
    }
    mz_zip_writer_end(&zip);

    /* copy ra buffer do caller quan ly (miniz dung free noi bo) */
    unsigned char *copy = malloc(buf_len);
    if (!copy) { free(buf); return -1; }
    memcpy(copy, buf, buf_len);
    free(buf);

    *out = copy;
    *out_len = buf_len;
    return 0;
}

int pk_unzip_to_dir(const unsigned char *zip, size_t zip_len, const char *dest_dir) {
    mz_zip_archive za;
    memset(&za, 0, sizeof(za));
    if (!mz_zip_reader_init_mem(&za, zip, zip_len, 0)) {
        fprintf(stderr, "loi: zip khong hop le\n");
        return -1;
    }

    int rc = 0;
    mz_uint n = mz_zip_reader_get_num_files(&za);
    for (mz_uint i = 0; i < n; i++) {
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&za, i, &st)) { rc = -1; break; }

        char dest[2048];
        snprintf(dest, sizeof(dest), "%s/%s", dest_dir, st.m_filename);

        if (mz_zip_reader_is_file_a_directory(&za, i)) {
            pk_mkdir_p(dest);
            continue;
        }

        /* tao thu muc cha truoc khi giai nen file */
        char *slash = strrchr(dest, '/');
        if (slash) {
            *slash = '\0';
            pk_mkdir_p(dest);
            *slash = '/';
        }

        if (!mz_zip_reader_extract_to_file(&za, i, dest, 0)) {
            fprintf(stderr, "loi: khong giai nen duoc %s\n", st.m_filename);
            rc = -1;
            break;
        }
    }

    mz_zip_reader_end(&za);
    return rc;
}
