#include "pk_fingerprint.h"
#include "pk_crypto.h"

#include <stdio.h>
#include <string.h>

#include <windows.h>

/* Đọc MachineGuid (ID máy do Windows tạo lúc cài) — định danh ổn định. */
static int read_machine_guid(char *buf, DWORD cap) {
    DWORD type = 0, sz = cap;
    LSTATUS rc = RegGetValueA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography",
        "MachineGuid",
        RRF_RT_REG_SZ,
        &type, buf, &sz);
    return (rc == ERROR_SUCCESS) ? 0 : -1;
}

int pk_hardware_hash(char *out, size_t cap) {
    if (cap < PK_SHA256 * 2 + 1) return -1;

    char guid[128] = {0};
    if (read_machine_guid(guid, sizeof(guid)) != 0) {
        /* fallback nếu không đọc được registry */
        snprintf(guid, sizeof(guid), "no-machine-guid");
    }

    char host[256] = {0};
    DWORD hlen = sizeof(host);
    if (!GetComputerNameA(host, &hlen)) snprintf(host, sizeof(host), "unknown-host");

    /* Trộn rồi băm SHA-256 -> hex. */
    char material[512];
    int n = snprintf(material, sizeof(material), "%s|%s", guid, host);
    if (n <= 0) return -1;

    pk_sha256_hex((const unsigned char *)material, (size_t)n, out);
    return 0;
}
