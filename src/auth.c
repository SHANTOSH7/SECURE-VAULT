#include "sv.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static int valid_username_input(const char *u) {
    size_t n=strlen(u); if(n<3||n>SV_USER_MAX)return 0;
    for(size_t i=0;i<n;i++) if(!isalnum((unsigned char)u[i])&&u[i]!='_'&&u[i]!='-') return 0;
    return 1;
}
static int password_policy(const char *p) {
    size_t n=strlen(p); if(n<12||n>SV_PASSWORD_MAX)return 0;
    int upper=0,lower=0,digit=0,symbol=0;
    for(size_t i=0;i<n;i++){unsigned char c=(unsigned char)p[i];if(isupper(c))upper=1;else if(islower(c))lower=1;else if(isdigit(c))digit=1;else symbol=1;}
    return upper&&lower&&digit&&symbol;
}
int auth_register(Session *session) {
    char username[SV_USER_MAX+2],password[SV_PASSWORD_MAX+2],confirm[SV_PASSWORD_MAX+2];
    UserRecord user;int ok=0;char path[256];
    memset(&user,0,sizeof user);memset(session,0,sizeof *session);
    ui_clear();ui_banner();printf("  CREATE ACCOUNT\n\n");
    if(!ui_read_line("  Username (3-32; letters, digits, _ or -): ",username,sizeof username,0))goto done;
    if(!valid_username_input(username)){ui_error("Username format is invalid.");goto done;}
    if(storage_user_exists(username)){ui_error("That username is already registered.");goto done;}
    if(!ui_read_secret("  Master password (12+ chars; upper/lower/digit/symbol): ",password,sizeof password))goto done;
    if(!password_policy(password)){ui_error("Password does not meet the required policy.");goto done;}
    if(!ui_read_secret("  Confirm master password: ",confirm,sizeof confirm))goto done;
    if(strcmp(password,confirm)!=0){ui_error("Passwords do not match.");goto done;}
    strcpy(user.username,username);user.iterations=SV_PBKDF2_ITERATIONS;
    if(!crypto_random(user.salt,sizeof user.salt)||!crypto_derive(password,user.salt,user.iterations,session->enc_key,session->verify_key)||!crypto_make_verifier(username,session->verify_key,user.verifier)){
        ui_error("Cryptographic initialization failed.");goto done;
    }
    if(!storage_save_vault(username,session->enc_key,&session->vault)){ui_error("Could not initialize encrypted vault.");goto done;}
    if(!storage_add_user(&user)){storage_vault_path(username,path,sizeof path);remove(path);ui_error("Could not save user registry entry.");goto done;}
    strcpy(session->username,username);session->authenticated=1;ok=1;
    ui_success("Account created. Your encrypted vault is ready.");
done:
    platform_secure_zero(password,sizeof password);platform_secure_zero(confirm,sizeof confirm);platform_secure_zero(&user,sizeof user);
    if(!ok){platform_secure_zero(session,sizeof *session);}
    return ok;
}
int auth_login(Session *session) {
    char username[SV_USER_MAX+2],password[SV_PASSWORD_MAX+2];UserRecord user;unsigned char verifier[32];int ok=0;
    memset(session,0,sizeof *session);memset(&user,0,sizeof user);memset(password,0,sizeof password);
    ui_clear();ui_banner();printf("  LOGIN\n\n");
    if(!ui_read_line("  Username: ",username,sizeof username,0))goto done;
    if(!ui_read_secret("  Master password: ",password,sizeof password))goto done;
    if(!storage_find_user(username,&user)){ui_error("Invalid username or password.");goto done;}
    if(!crypto_derive(password,user.salt,user.iterations,session->enc_key,session->verify_key)||!crypto_make_verifier(username,session->verify_key,verifier)){
        ui_error("Authentication could not be completed.");goto done;
    }
    if(!crypto_equal(verifier,user.verifier,sizeof verifier)){ui_error("Invalid username or password.");goto done;}
    if(!storage_load_vault(username,session->enc_key,&session->vault)){ui_error("Vault authentication failed. File may be damaged or tampered with.");goto done;}
    strcpy(session->username,username);session->authenticated=1;ok=1;ui_success("Authentication successful.");
done:
    platform_secure_zero(password,sizeof password);platform_secure_zero(verifier,sizeof verifier);platform_secure_zero(&user,sizeof user);
    if(!ok)platform_secure_zero(session,sizeof *session);
    return ok;
}
void auth_logout(Session *session){if(session)platform_secure_zero(session,sizeof *session);}
int auth_change_master(Session *session){
    char current[SV_PASSWORD_MAX+2],next[SV_PASSWORD_MAX+2],confirm[SV_PASSWORD_MAX+2];UserRecord user;unsigned char old_enc[32],old_ver[32],check[32];int ok=0;
    memset(&user,0,sizeof user);
    if(!ui_read_secret("  Current master password: ",current,sizeof current))goto done;
    if(!storage_find_user(session->username,&user)||!crypto_derive(current,user.salt,user.iterations,old_enc,old_ver)||!crypto_make_verifier(session->username,old_ver,check)||!crypto_equal(check,user.verifier,32)){ui_error("Current password is incorrect.");goto done;}
    if(!ui_read_secret("  New master password (12+ chars; upper/lower/digit/symbol): ",next,sizeof next)||!password_policy(next)){ui_error("New password does not meet policy.");goto done;}
    if(!ui_read_secret("  Confirm new master password: ",confirm,sizeof confirm)||strcmp(next,confirm)!=0){ui_error("New passwords do not match.");goto done;}
    unsigned char new_enc[32],new_ver[32];
    user.iterations=SV_PBKDF2_ITERATIONS;
    if(!crypto_random(user.salt,sizeof user.salt)||!crypto_derive(next,user.salt,user.iterations,new_enc,new_ver)||!crypto_make_verifier(session->username,new_ver,user.verifier)){ui_error("Could not derive new keys.");goto change_done;}
    if(!storage_save_vault(session->username,new_enc,&session->vault)){ui_error("Could not re-encrypt vault.");goto change_done;}
    if(!storage_update_user(&user)){
        if(storage_save_vault(session->username,old_enc,&session->vault))
            ui_error("Could not update account metadata; old vault encryption was restored.");
        else
            ui_error("CRITICAL: metadata update and rollback failed. Preserve your current files and backup immediately.");
        goto change_done;
    }
    memcpy(session->enc_key,new_enc,32);memcpy(session->verify_key,new_ver,32);ui_success("Master password changed.");ok=1;
change_done:
    platform_secure_zero(new_enc,sizeof new_enc);platform_secure_zero(new_ver,sizeof new_ver);
done:
    platform_secure_zero(current,sizeof current);platform_secure_zero(next,sizeof next);platform_secure_zero(confirm,sizeof confirm);
    platform_secure_zero(old_enc,sizeof old_enc);platform_secure_zero(old_ver,sizeof old_ver);platform_secure_zero(check,sizeof check);platform_secure_zero(&user,sizeof user);
    return ok;
}
