#include "pk_runner.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <windows.h>

int pk_exe_dir(char *out, size_t cap) {
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, sizeof(path));
    if (n == 0 || n >= sizeof(path)) return -1;

    /* cắt ở dấu phân tách cuối cùng ('\\' hoặc '/') */
    char *p = path + n;
    while (p > path && *p != '\\' && *p != '/') p--;
    *p = '\0';
    snprintf(out, cap, "%s", path);
    return 0;
}

int pk_make_temp_dir(char *out, size_t cap) {
    char tmp[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(tmp), tmp);  /* kết thúc bằng '\\' */
    if (n == 0 || n > sizeof(tmp)) return -1;

    snprintf(out, cap, "%spklaunch_%lu_%lu", tmp,
             (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    if (!CreateDirectoryA(out, NULL)) {
        fprintf(stderr, "loi: khong tao duoc thu muc tam %s\n", out);
        return -1;
    }
    return 0;
}

int pk_run_and_wait(const char *exe_path, const char *workdir, int *exit_code) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL ok = CreateProcessA(
        exe_path,   /* lpApplicationName */
        NULL,       /* lpCommandLine */
        NULL, NULL, FALSE, 0, NULL,
        workdir,    /* thư mục làm việc = thư mục tạm */
        &si, &pi);
    if (!ok) {
        fprintf(stderr, "loi: khong chay duoc app (CreateProcess err=%lu)\n", GetLastError());
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    *exit_code = (int)code;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

int pk_remove_dir_recursive(const char *path) {
    DIR *d = opendir(path);
    if (!d) {
        /* có thể là file */
        return remove(path) == 0 ? 0 : -1;
    }
    struct dirent *ent;
    int rc = 0;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char child[2048];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        struct stat st;
        if (stat(child, &st) != 0) { rc = -1; continue; }
        if (S_ISDIR(st.st_mode)) {
            pk_remove_dir_recursive(child);
        } else {
            DeleteFileA(child);
        }
    }
    closedir(d);
    if (!RemoveDirectoryA(path)) rc = -1;
    return rc;
}
