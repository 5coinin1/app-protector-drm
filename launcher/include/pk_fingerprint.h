/* Hardware fingerprint (hardware binding). */
#ifndef PK_FINGERPRINT_H
#define PK_FINGERPRINT_H

#include <stddef.h>

/* Tính hardware_hash ổn định của máy (SHA-256 hex của MachineGuid + tên máy).
 * out cần >= 65 byte. Trả 0 nếu OK. */
int pk_hardware_hash(char *out, size_t cap);

#endif /* PK_FINGERPRINT_H */
