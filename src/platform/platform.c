#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "sv.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <conio.h>
#include <direct.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#endif

int platform_read_secret(const char *prompt, char *out, size_t cap)
{
    if (!out || cap < 2) return 0;
    printf("%s", prompt);
    fflush(stdout);
    size_t n = 0;
    int overflow = 0;
#ifdef _WIN32
    int ch;
    while ((ch = _getch()) != '\r' && ch != '\n') {
        if (ch == 3) { out[0] = '\0'; printf("\n"); return 0; }
        if (ch == 8 || ch == 127) {
            if (n) n--;
            continue;
        }
        if (ch >= 32 && ch <= 126) {
            if (n < cap - 1) out[n++] = (char)ch;
            else overflow = 1;
        }
    }
#else
    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) return 0;
    newt = oldt;
    newt.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) != 0) return 0;
    for (;;) {
        unsigned char ch;
        ssize_t got = read(STDIN_FILENO, &ch, 1);
        if (got != 1) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
            platform_secure_zero(out, cap);
            return 0;
        }
        if (ch == '\n' || ch == '\r') break;
        if (ch == 8 || ch == 127) {
            if (n) n--;
            continue;
        }
        if (ch >= 32 && ch <= 126) {
            if (n < cap - 1) out[n++] = (char)ch;
            else overflow = 1;
        }
    }
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt) != 0) {
        platform_secure_zero(out, cap);
        return 0;
    }
#endif
    out[n] = '\0';
    printf("\n");
    if (overflow) {
        platform_secure_zero(out, cap);
        return 0;
    }
    return 1;
}

void platform_secure_zero(void *p, size_t n)
{
    if (!p) return;
#ifdef _WIN32
    SecureZeroMemory(p, n);
#else
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
#endif
}

int platform_mkdir(const char *path)
{
#ifdef _WIN32
    if (_mkdir(path) == 0 || errno == EEXIST) return 1;
#else
    if (mkdir(path, 0700) == 0 || errno == EEXIST) {
        if (chmod(path, 0700) == 0) return 1;
    }
#endif
    return 0;
}

int platform_atomic_replace(const char *tmp, const char *dest)
{
#ifdef _WIN32
    return MoveFileExA(tmp, dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return rename(tmp, dest) == 0;
#endif
}

int platform_clipboard_copy(const char *text)
{
#ifdef _WIN32
    if (!OpenClipboard(NULL)) return 0;
    EmptyClipboard();
    size_t bytes = strlen(text) + 1;
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!h) { CloseClipboard(); return 0; }
    char *dst = (char *)GlobalLock(h);
    if (!dst) { GlobalFree(h); CloseClipboard(); return 0; }
    memcpy(dst, text, bytes);
    GlobalUnlock(h);
    if (!SetClipboardData(CF_TEXT, h)) {
        GlobalFree(h); CloseClipboard(); return 0;
    }
    CloseClipboard();
    return 1;
#else
    FILE *pipe = popen("wl-copy 2>/dev/null", "w");
    if (pipe) {
        size_t n = fwrite(text, 1, strlen(text), pipe);
        int rc = pclose(pipe);
        if (n == strlen(text) && rc == 0) return 1;
    }
    pipe = popen("xclip -selection clipboard 2>/dev/null", "w");
    if (pipe) {
        size_t n = fwrite(text, 1, strlen(text), pipe);
        int rc = pclose(pipe);
        if (n == strlen(text) && rc == 0) return 1;
    }
    return 0;
#endif
}
