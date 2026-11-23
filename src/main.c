#include "sv.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    int choice, running = 1, failed_logins = 0;
    Session session;
    memset(&session, 0, sizeof session);
    ui_init();
    if (!storage_init()) {
        ui_error("Could not initialize data directories. Check folder permissions.");
        return 1;
    }
    while (running) {
        ui_clear(); ui_banner(); ui_main_menu();
        if (!ui_read_int("\n  Select an option: ", 1, 3, &choice)) { ui_pause(); continue; }
        switch (choice) {
            case 1:
                if (auth_register(&session)) { ui_pause(); vault_menu(&session); }
                else ui_pause();
                break;
            case 2:
                if (auth_login(&session)) { failed_logins = 0; ui_pause(); vault_menu(&session); }
                else {
                    failed_logins++;
                    if (failed_logins >= 5) {
                        ui_error("Five failed login attempts in this application run. Exiting.");
                        running = 0;
                    } else {
                        printf("  Failed attempts: %d/5\n", failed_logins);
                        ui_pause();
                    }
                }
                break;
            case 3:
                ui_success("Thank you for using SecureVault."); running = 0;
                break;
        }
    }
    auth_logout(&session);
    return 0;
}
