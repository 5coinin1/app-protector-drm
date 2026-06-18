/* DemoApp — Sample App cho hệ DRM, đồng thời là CRACK-ME minh họa Anti-Reverse Engineering.
 *
 * PHẠM VI: toàn bộ anti-RE nằm TRONG app này. KHÔNG đụng protector/launcher/server.
 *
 * Hai chế độ:
 *   - FREE  : mở trực tiếp hoặc chạy qua launcher (không có license) -> in banner như cũ.
 *             => giữ nguyên đường demo DRM (launcher vẫn chạy app bình thường).
 *   - PREMIUM: cung cấp license đúng qua argv[1] hoặc biến môi trường DEMOAPP_LICENSE
 *             -> giải mã và in FLAG bí mật. Đây là "logic đáng bảo vệ" của crack-me.
 *
 * Lớp phòng thủ trong app (defense-in-depth ở tầng nội dung được protect):
 *   1. String obfuscation : chuỗi nhạy cảm bị XOR (0x5A) -> `strings DemoApp.exe` không lộ.
 *   2. API hiding         : NtQueryInformationProcess resolve động qua tên đã obfuscate
 *                           -> không nằm trong Import Table (IAT).
 *   3. Anti-debugging      : nhiều check khác cơ chế (IsDebuggerPresent, PEB.BeingDebugged,
 *                           CheckRemoteDebuggerPresent, ProcessDebugPort, RDTSC timing).
 *   4. Anti-debug "silent": phát hiện debugger KHÔNG báo lỗi to, mà ĐẦU ĐỘC khóa giải mã
 *                           FLAG -> FLAG ra rác -> nhìn như "license sai". Khó bẻ hơn 1 cú
 *                           patch jump so với check "ồn ào".
 *   5. Control-flow flattening: hàm try_premium bị băm phẳng thành dispatcher while/switch
 *                           (thủ công, tương đương Tigress --Transform=Flatten) -> CFG rối.
 *   6. Phát hiện tool RE     : quét tiến trình đang chạy (x64dbg/IDA/Ghidra/procmon...) -> nếu thấy
 *                           thì ĐẦU ĐỘC khóa (silent) + cảnh báo "ồn ào" để demo.
 *   7. Self-checksum (.text) : tự băm vùng code của try_premium lúc chạy; nếu bị PATCH (vá byte/
 *                           sửa jump) thì checksum lệch -> đầu độc khóa -> FLAG ra rác.
 *   8. Quét software breakpoint: dò byte 0xCC (INT3 do debugger đặt) trong code try_premium ->
 *                           đặt breakpoint vào hàm là khóa hỏng (silent).
 *
 * LƯU Ý QUAN TRỌNG: cipher/KDF trong file này (FNV-1a + xorshift) là cơ chế DẠY HỌC,
 * CỐ TÌNH yếu để sinh viên reverse được. Nó ĐỘC LẬP và KHÔNG thay thế crypto thật của hệ
 * DRM (AES-256-GCM + Ed25519 ở protector/launcher). Đừng nhầm hai thứ.
 *
 * Build (MSYS2 MinGW64):  gcc -O2 -s DemoApp.c -o DemoApp.exe
 *   ( -s strip symbol; không cần -lntdll vì NtQuery... resolve động )
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <winternl.h>   /* PEB, BeingDebugged */
#include <tlhelp32.h>   /* CreateToolhelp32Snapshot — liệt kê tiến trình (phát hiện tool RE) */

/* Forward declaration: các check toàn vẹn (self-checksum / quét breakpoint) cần địa chỉ try_premium. */
static void try_premium(const char *license);

/* ------------------------------------------------------------------ *
 * Dữ liệu đã obfuscate (sinh tự động, xem comment cuối file).
 * ------------------------------------------------------------------ */

/* License đúng KHÔNG lưu dạng plaintext; chỉ lưu FNV-1a 64-bit của nó. */
#define H_CORRECT 0xac3374bc9ec4c162ULL

/* FLAG đã mã hóa = FLAG XOR keystream(seed = FNV-1a(license đúng)). */
#define FLAGLEN 27
static const unsigned char FLAG_CIPHER[27] = {0x26,0x8c,0x84,0x23,0x53,0xbf,0xbd,0xd8,0x42,0x96,0xf0,0xe6,0x3b,0xd4,0x86,0x0f,0xd1,0x30,0x8f,0x74,0x68,0x6a,0x5f,0xe8,0x31,0xfa,0xa3};

/* Chuỗi nhạy cảm XOR 0x5A (byte cuối giải ra '\0'). */
static const unsigned char s_ntdll[10]  = {0x34,0x2e,0x3e,0x36,0x36,0x74,0x3e,0x36,0x36,0x5a};
static const unsigned char s_ntqip[26]  = {0x14,0x2e,0x0b,0x2f,0x3f,0x28,0x23,0x13,0x34,0x3c,0x35,0x28,0x37,0x3b,0x2e,0x33,0x35,0x34,0x0a,0x28,0x35,0x39,0x3f,0x29,0x29,0x5a};
static const unsigned char s_env[16]    = {0x1e,0x1f,0x17,0x15,0x1b,0x0a,0x0a,0x05,0x16,0x13,0x19,0x1f,0x14,0x09,0x1f,0x5a};
static const unsigned char s_ok[54]     = {0x01,0x0a,0x08,0x1f,0x17,0x13,0x0f,0x17,0x07,0x7a,0x16,0x33,0x39,0x3f,0x34,0x29,0x3f,0x7a,0x32,0x35,0x2a,0x7a,0x36,0x3f,0x7b,0x7a,0x17,0x35,0x7a,0x31,0x32,0x35,0x3b,0x7a,0x2e,0x33,0x34,0x32,0x7a,0x34,0x3b,0x34,0x3d,0x7a,0x39,0x3b,0x35,0x7a,0x39,0x3b,0x2a,0x74,0x50,0x5a};
static const unsigned char s_label[18]  = {0x01,0x0a,0x08,0x1f,0x17,0x13,0x0f,0x17,0x07,0x7a,0x1c,0x16,0x1b,0x1d,0x7a,0x67,0x7a,0x5a};
static const unsigned char s_deny[62]   = {0x01,0x0a,0x08,0x1f,0x17,0x13,0x0f,0x17,0x07,0x7a,0x16,0x33,0x39,0x3f,0x34,0x29,0x3f,0x7a,0x31,0x32,0x35,0x34,0x3d,0x7a,0x32,0x35,0x2a,0x7a,0x36,0x3f,0x7a,0x32,0x35,0x3b,0x39,0x7a,0x37,0x35,0x33,0x7a,0x2e,0x28,0x2f,0x35,0x34,0x3d,0x7a,0x38,0x33,0x7a,0x39,0x3b,0x34,0x7a,0x2e,0x32,0x33,0x3f,0x2a,0x74,0x50,0x5a};
static const unsigned char s_prefix[6]  = {0x1c,0x16,0x1b,0x1d,0x21,0x5a};

/* Giải obfuscate XOR vào dst (đã gồm '\0'). dst phải đủ chỗ.
 * Khóa để `volatile`: nếu không, -O2 sẽ constant-fold cả hàm này lúc compile và
 * nhúng thẳng chuỗi plaintext vào binary (obfuscation vô hiệu!). volatile buộc
 * đọc khóa lúc runtime -> phép XOR chỉ chạy khi thực thi -> binary chỉ chứa bytes mã. */
static volatile unsigned char XKEY = 0x5A;
static char *deobf(const unsigned char *src, size_t n, char *dst) {
    unsigned char k = XKEY;
    for (size_t i = 0; i < n; i++) dst[i] = (char)(src[i] ^ k);
    return dst;
}

/* ------------------------------------------------------------------ *
 * KDF dạy học: FNV-1a 64-bit + keystream xorshift64.  (KHÔNG phải crypto thật)
 * ------------------------------------------------------------------ */
static uint64_t fnv1a(const char *s) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 0x100000001b3ULL;
    return h;
}
static uint64_t xs64(uint64_t x) {
    if (x == 0) x = 1;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

/* ------------------------------------------------------------------ *
 * Anti-debugging.
 *   anti_debug_poison(): trả 0 nếu sạch, hằng số khác 0 nếu phát hiện debugger.
 *   Giá trị này ĐẦU ĐỘC seed giải mã FLAG -> hỏng thầm lặng (silent), không
 *   phải một câu lệnh nhảy đơn lẻ dễ patch.
 *   (RDTSC timing chỉ dùng cho cảnh báo "ồn ào" — không đưa vào gate vì dễ
 *    false-positive khi CPU bận, sẽ làm hỏng cả lần chạy hợp lệ.)
 * ------------------------------------------------------------------ */
typedef LONG(NTAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
#define ProcessDebugPort 7

static int chk_peb_being_debugged(void) {
#if defined(__x86_64__)
    PPEB peb = NULL;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
    return peb ? (int)peb->BeingDebugged : 0;
#else
    return (int)IsDebuggerPresent();
#endif
}

static int chk_remote_debugger(void) {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present ? 1 : 0;
}

static int chk_debug_port(void) {
    char nm1[16], nm2[32];
    HMODULE nt = GetModuleHandleA(deobf(s_ntdll, sizeof(s_ntdll), nm1));
    if (!nt) return 0;
    pNtQIP fn = (pNtQIP)(void *)GetProcAddress(nt, deobf(s_ntqip, sizeof(s_ntqip), nm2));
    if (!fn) return 0;
    ULONG_PTR port = 0;
    if (fn(GetCurrentProcess(), ProcessDebugPort, &port, sizeof(port), NULL) == 0 && port != 0)
        return 1;
    return 0;
}

/* ------------------------------------------------------------------ *
 * (6) Phát hiện công cụ RE đang chạy (x64dbg/IDA/procmon...).
 *     Tên tiến trình lưu XOR 0x5A -> `strings DemoApp.exe` không lộ.
 * ------------------------------------------------------------------ */
#define N_RETOOLS 16
#define RETOOL_W 24
static const unsigned char s_retools[N_RETOOLS][RETOOL_W] = {
    {0x22,0x6c,0x6e,0x3e,0x38,0x3d,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* x64dbg.exe */
    {0x22,0x69,0x68,0x3e,0x38,0x3d,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* x32dbg.exe */
    {0x22,0x63,0x6c,0x3e,0x38,0x3d,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* x96dbg.exe */
    {0x35,0x36,0x36,0x23,0x3e,0x38,0x3d,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* ollydbg.exe */
    {0x2d,0x33,0x34,0x3e,0x38,0x3d,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* windbg.exe */
    {0x33,0x3e,0x3b,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* ida.exe */
    {0x33,0x3e,0x3b,0x6c,0x6e,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* ida64.exe */
    {0x3e,0x34,0x29,0x2a,0x23,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* dnspy.exe */
    {0x2a,0x3f,0x29,0x2e,0x2f,0x3e,0x33,0x35,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* pestudio.exe */
    {0x2a,0x28,0x35,0x39,0x37,0x35,0x34,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* procmon.exe */
    {0x2a,0x28,0x35,0x39,0x37,0x35,0x34,0x6c,0x6e,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* procmon64.exe */
    {0x2d,0x33,0x28,0x3f,0x29,0x32,0x3b,0x28,0x31,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* wireshark.exe */
    {0x33,0x37,0x37,0x2f,0x34,0x33,0x2e,0x23,0x3e,0x3f,0x38,0x2f,0x3d,0x3d,0x3f,0x28,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a},  /* immunitydebugger.exe */
    {0x32,0x2e,0x2e,0x2a,0x3e,0x3f,0x38,0x2f,0x3d,0x3d,0x3f,0x28,0x2f,0x33,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* httpdebuggerui.exe */
    {0x3c,0x33,0x3e,0x3e,0x36,0x3f,0x28,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* fiddler.exe */
    {0x28,0x3f,0x39,0x36,0x3b,0x29,0x29,0x74,0x34,0x3f,0x2e,0x74,0x3f,0x22,0x3f,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a},  /* reclass.net.exe */
};

static int re_tool_running(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int found = 0;
    if (Process32First(snap, &pe)) {
        do {
            char name[RETOOL_W];
            for (int i = 0; i < N_RETOOLS && !found; i++) {
                deobf(s_retools[i], RETOOL_W, name);
                if (_stricmp(pe.szExeFile, name) == 0) found = 1;
            }
        } while (!found && Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* ------------------------------------------------------------------ *
 * (7)(8) Toàn vẹn code try_premium: self-checksum + quét software breakpoint.
 *     Đọc N byte đầu của hàm try_premium lúc chạy:
 *       - (7) băm (FNV-1a) so với TP_CKSUM -> lệch nghĩa là bị PATCH.
 *       - (8) đếm byte 0xCC (INT3) -> debugger đặt software breakpoint vào hàm.
 *     Cả hai đầu độc khóa (silent) thay vì báo lỗi to.
 * ------------------------------------------------------------------ */
#define TP_SCAN_LEN 96
/* Checksum chuẩn của 96 byte đầu try_premium (đo từ binary sạch — xem comment cuối file).
 * Đổi try_premium thì PHẢI đo lại giá trị này (giống FLAG_CIPHER). Đo: DEMOAPP_SELFTEST=1. */
#define TP_CKSUM 0x6f4efa2aaa752c75ULL

static uint64_t text_checksum(const unsigned char *p, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x100000001b3ULL;
    return h;
}

static int text_checksum_tampered(void) {
    const unsigned char *p = (const unsigned char *)(uintptr_t)&try_premium;
    return text_checksum(p, TP_SCAN_LEN) != (uint64_t)TP_CKSUM;
}

static int has_software_breakpoint(void) {
    const volatile unsigned char *p = (const volatile unsigned char *)(uintptr_t)&try_premium;
    for (size_t i = 0; i < TP_SCAN_LEN; i++)
        if (p[i] == 0xCC) return 1;
    return 0;
}

/* mask = 0 nếu flag==0, = 0xFFFF...FFFF nếu flag!=0 (tránh nhánh if rõ ràng) */
static uint64_t mask_of(int flag) { return (uint64_t)(-(int64_t)(flag != 0)); }

/* noinline: giữ TP_CKSUM (trong text_checksum_tampered) KHÔNG bị inline vào try_premium,
 * nếu không thì đổi TP_CKSUM lại làm đổi bytes try_premium -> self-checksum tự mâu thuẫn. */
__attribute__((noinline)) static uint64_t anti_debug_poison(void) {
    uint64_t m = 0;
    m |= mask_of((int)IsDebuggerPresent());
    m |= mask_of(chk_peb_being_debugged());
    m |= mask_of(chk_remote_debugger());
    m |= mask_of(chk_debug_port());
    m |= mask_of(re_tool_running());          /* (6) tool RE đang chạy */
    m |= mask_of(text_checksum_tampered());   /* (7) code try_premium bị patch */
    m |= mask_of(has_software_breakpoint());  /* (8) có INT3 trong try_premium */
    return m & 0x9E3779B97F4A7C15ULL;  /* poison khác 0 nếu bất kỳ check nào dính */
}

/* Check "ồn ào" để minh họa tương phản: dễ tìm, dễ patch (so với silent ở trên). */
static void noisy_timing_notice(void) {
    unsigned long long t0 = __builtin_ia32_rdtsc();
    volatile int s = 0;
    for (int i = 0; i < 2000; i++) s += i;
    unsigned long long t1 = __builtin_ia32_rdtsc();
    if ((t1 - t0) > 5000000ULL)
        fprintf(stderr, "[!] canh bao: thoi gian thuc thi bat thuong (nghi single-step)\n");
}

/* ------------------------------------------------------------------ *
 * Tính năng PREMIUM (logic đáng bảo vệ): giải mã + in FLAG.
 * ------------------------------------------------------------------ */
/* CONTROL-FLOW FLATTENING (thủ công — tương đương Tigress --Transform=Flatten).
 * Luồng tuyến tính ban đầu (check license -> derive -> decrypt loop -> verify -> in)
 * bị "băm phẳng": mọi basic block trở thành 1 case của dispatcher while(1)/switch, nối
 * với nhau qua biến `state` (giá trị xáo trộn, không tuần tự). CFG trong Ghidra/IDA
 * biến thành hình "bàn chải" (mọi block đổ về 1 switch) -> rất khó suy thứ tự thực thi.
 * HÀNH VI GIỮ NGUYÊN so với bản chưa flatten.
 *
 * Mẹo demo: build bản obfuscate này với -O0 hoặc -O1 để dispatcher hiện rõ trong Ghidra
 * (gcc -O2 có thể tối ưu/khôi phục một phần luồng). */
/* noinline+used: giữ try_premium là hàm độc lập để self-checksum/quét breakpoint đọc đúng code nó. */
__attribute__((noinline, used)) static void try_premium(const char *license) {
    enum { ST_LIC = 0x5b, ST_DERIVE = 0x2e, ST_DECRYPT = 0x91,
           ST_VERIFY = 0x47, ST_OK = 0xc3, ST_DENY = 0x7f, ST_END = 0x00 };
    char buf[128];
    char flag[FLAGLEN + 1];
    char prefix[8];
    uint64_t seed = 0, x = 0;
    int i = 0;
    int state = ST_LIC;

    for (;;) {
        switch (state) {
        case ST_LIC: {
            /* Opaque predicate: L*(L+1) luôn chẵn với mọi L -> nhánh luôn đúng, nhưng L
             * (độ dài license) chỉ biết lúc runtime nên -O2 không hằng-số-hóa được. */
            size_t L = strlen(license);
            if (((L * (L + 1)) & 1u) == 0)
                state = (fnv1a(license) == H_CORRECT) ? ST_DERIVE : ST_DENY;
            else
                state = ST_DENY; /* dead branch (không bao giờ chạy) */
            break;
        }
        case ST_DERIVE:
            seed = fnv1a(license) ^ anti_debug_poison();
            x = seed;
            i = 0;
            state = ST_DECRYPT;
            break;
        case ST_DECRYPT:
            if (i < FLAGLEN) {
                x = xs64(x);
                flag[i] = (char)(FLAG_CIPHER[i] ^ (unsigned char)(x & 0xFF));
                i++;
                state = ST_DECRYPT; /* vòng lặp cũng đi qua dispatcher */
            } else {
                flag[FLAGLEN] = '\0';
                state = ST_VERIFY;
            }
            break;
        case ST_VERIFY:
            deobf(s_prefix, sizeof(s_prefix), prefix);
            state = (strncmp(flag, prefix, strlen(prefix)) == 0) ? ST_OK : ST_DENY;
            break;
        case ST_OK:
            printf("%s", deobf(s_ok, sizeof(s_ok), buf));
            printf("%s%s\n", deobf(s_label, sizeof(s_label), buf), flag);
            state = ST_END;
            break;
        case ST_DENY:
            printf("%s", deobf(s_deny, sizeof(s_deny), buf));
            state = ST_END;
            break;
        case ST_END:
        default:
            return;
        }
    }
}

int main(int argc, char **argv) {
    /* Check "ồn ào" (loud) — minh họa cho báo cáo, dễ phát hiện & vô hiệu. */
    if (IsDebuggerPresent())
        fprintf(stderr, "[!] phat hien debugger (loud check)\n");
    if (re_tool_running())
        fprintf(stderr, "[!] phat hien cong cu phan tich/RE dang chay (loud check)\n");
    noisy_timing_notice();

    /* Selftest ẩn (chỉ khi đặt env DEMOAPP_SELFTEST): in checksum + số byte 0xCC của try_premium
     * để LẤY giá trị nhúng vào TP_CKSUM. Không ảnh hưởng người dùng thường. */
    if (getenv("DEMOAPP_SELFTEST")) {
        const unsigned char *tp = (const unsigned char *)(uintptr_t)&try_premium;
        int cc = 0;
        for (size_t i = 0; i < TP_SCAN_LEN; i++)
            if (tp[i] == 0xCC) cc++;
        fprintf(stderr, "[selftest] TP_CKSUM=0x%016llxULL  cc=%d\n",
                (unsigned long long)text_checksum(tp, TP_SCAN_LEN), cc);
    }

    /* Bản FREE — giữ nguyên hành vi cũ để đường demo launcher không đổi. */
    printf("==============================\n");
    printf("  Demo App - phien ban 1.0.0\n");
    printf("  App goc dang chay thanh cong!\n");
    printf("==============================\n");

    /* Lấy license: argv[1] hoặc biến môi trường (tên đã obfuscate). */
    char envname[16];
    const char *license = (argc > 1) ? argv[1]
                                      : getenv(deobf(s_env, sizeof(s_env), envname));
    if (license && *license) {
        try_premium(license);
    } else {
        printf("  (ban FREE - chua co license; nhap license de mo PREMIUM)\n");
    }
    return 0;
}

/* ============================================================================
 * Cách dữ liệu obfuscate được sinh (tham khảo — chạy lại khi đổi FLAG/license):
 *
 *   FLAG    = "FLAG{anti_RE_demo_2026_drm}"
 *   LICENSE = "DRM2-9F4A-7C18-BE63"   (đáp án crack-me)
 *   H_CORRECT  = FNV-1a_64(LICENSE)
 *   keystream  = xorshift64(seed=H_CORRECT) -> mỗi vòng lấy 8 bit thấp
 *   FLAG_CIPHER[i] = FLAG[i] XOR keystream[i]
 *   s_*        = (mỗi byte chuỗi) XOR 0x5A, kèm byte '\0' đã XOR.
 * ========================================================================== */
