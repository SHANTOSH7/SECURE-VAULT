#include "sv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#define RST "\033[0m"
#define WHT "\033[37m"
#define GRY "\033[90m"

void ui_init(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
    printf("\033[?25h");
}
void ui_clear(void) {
#ifdef _WIN32
    system("cls");
#else
    printf("\033[2J\033[H");
#endif
}
void ui_banner(void) {
    printf(GRY "  +----------------------------------------------------------+\n" RST);
    printf(WHT "  |                                                          |\n" RST);
    printf(WHT "  |                       SECUREVAULT                        |\n" RST);
    printf(GRY "  |              PRIVATE CREDENTIAL MANAGER                  |\n" RST);
    printf(WHT "  |                                                          |\n" RST);
    printf(GRY "  +----------------------------------------------------------+\n\n" RST);
}
void ui_message(const char *msg) { printf("\n  %s\n", msg); }
void ui_error(const char *msg) { printf("\n  [ERROR] %s\n", msg); }
void ui_success(const char *msg) { printf("\n  [OK] %s\n", msg); }
void ui_pause(void) {
    char b[8] = {0}; printf("\n  Press ENTER to continue..."); fflush(stdout);
    if (!fgets(b, sizeof b, stdin)) clearerr(stdin);
    if (b[0] && !strchr(b, '\n')) { int c; while ((c=getchar())!='\n' && c!=EOF) {} }
}
int ui_read_line(const char *prompt, char *out, size_t cap, int allow_empty) {
    if (!out || cap < 2) return 0;
    printf("%s", prompt); fflush(stdout);
    if (!fgets(out, (int)cap, stdin)) return 0;
    size_t n = strlen(out);
    if (n && out[n-1] == '\n') out[--n] = '\0';
    else if (!feof(stdin)) { int c; while ((c=getchar())!='\n' && c!=EOF) {} ui_error("Input too long."); return 0; }
    if (n && out[n-1] == '\r') out[--n] = '\0';
    if (!allow_empty && n == 0) { ui_error("This field cannot be empty."); return 0; }
    for (size_t i=0; i<n; i++) if ((unsigned char)out[i] < 32) { ui_error("Control characters are not allowed."); return 0; }
    return 1;
}
int ui_read_secret(const char *prompt, char *out, size_t cap) { return platform_read_secret(prompt, out, cap); }
int ui_read_int(const char *prompt, int min, int max, int *out) {
    char line[64], *end; long v;
    if (!ui_read_line(prompt, line, sizeof line, 0)) return 0;
    errno = 0; v = strtol(line, &end, 10);
    while (*end == ' ' || *end == '\t') end++;
    if (errno || *end || v < min || v > max) { ui_error("Enter a valid menu number."); return 0; }
    *out = (int)v; return 1;
}
void ui_main_menu(void) {
    printf(WHT "  MAIN MENU\n" RST GRY "  ----------------------------------------------------------\n" RST);
    printf("  [1]  Create account\n  [2]  Login\n  [3]  Exit\n");
    printf(GRY "  ----------------------------------------------------------\n" RST);
}
void ui_vault_menu(const char *username) {
    printf(WHT "  VAULT  /  %s\n" RST GRY "  ----------------------------------------------------------\n" RST, username);
    printf("  [1]  Add credential\n  [2]  View credentials\n  [3]  Search credentials\n  [4]  Update credential\n  [5]  Delete credential\n  [6]  Generate password\n  [7]  Check password strength\n  [8]  Detect duplicate passwords\n  [9]  Security dashboard\n  [10] Password security audit\n  [11] Copy password to clipboard\n  [12] Create encrypted backup\n  [13] Restore encrypted backup\n  [14] Change master password\n  [15] Logout\n");
    printf(GRY "  ----------------------------------------------------------\n" RST);
}
