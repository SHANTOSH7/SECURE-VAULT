#include "sv.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static void print_masked(size_t n){for(size_t i=0;i<n&&i<24;i++)putchar('*');if(n>24)printf("...");}
void vault_list(const Vault *v,int reveal_passwords){
    printf("\n  SAVED CREDENTIALS  (%zu)\n",v->count);
    printf("  %-4s %-24s %-22s %-14s %s\n","#","WEBSITE","USERNAME","CATEGORY","PASSWORD");
    printf("  --------------------------------------------------------------------------------\n");
    if(!v->count){printf("  No credentials saved yet.\n");return;}
    for(size_t i=0;i<v->count;i++){
        const Credential *c=&v->items[i];
        printf("  %-4zu %-24.24s %-22.22s %-14.14s ",i+1,c->website,c->username,c->category);
        if(reveal_passwords)printf("%s",c->password);else print_masked(strlen(c->password));
        putchar('\n');
    }
}
int vault_add(Session *s){
    Credential c;memset(&c,0,sizeof c);
    if(s->vault.count>=SV_MAX_CREDS){ui_error("Vault has reached its credential limit.");return 0;}
    printf("\n  ADD CREDENTIAL\n\n");
    if(!ui_read_line("  Website / application: ",c.website,sizeof c.website,0)||
       !ui_read_line("  Username / email: ",c.username,sizeof c.username,0)||
       !ui_read_secret("  Password: ",c.password,sizeof c.password)||
       !ui_read_line("  Category: ",c.category,sizeof c.category,0)||
       !ui_read_line("  Notes (optional): ",c.notes,sizeof c.notes,1))goto fail;
    if(c.password[0] == '\0') { ui_error("Credential password cannot be empty."); goto fail; }
    c.updated_at=(int64_t)time(NULL);s->vault.items[s->vault.count]=c;s->vault.count++;
    if(!storage_save_vault(s->username,s->enc_key,&s->vault)){s->vault.count--;platform_secure_zero(&s->vault.items[s->vault.count],sizeof(Credential));ui_error("Could not persist encrypted vault.");goto fail;}
    ui_success("Credential added and encrypted.");platform_secure_zero(&c,sizeof c);return 1;
fail:platform_secure_zero(&c,sizeof c);return 0;
}
int vault_search(const Vault *v,const char *term){
    int found=0;printf("\n  SEARCH RESULTS\n");
    for(size_t i=0;i<v->count;i++)if(strstr(v->items[i].website,term)||strstr(v->items[i].username,term)||strstr(v->items[i].category,term)){
        printf("  [%zu] %-28s %-24s (%s)\n",i+1,v->items[i].website,v->items[i].username,v->items[i].category);found++;}
    if(!found) printf("  No matching credentials.\n");
    return found;
}
static int choose_index(const Vault *v,size_t *idx){int n;if(!v->count){ui_error("Vault is empty.");return 0;}vault_list(v,0);if(!ui_read_int("\n  Credential number: ",1,(int)v->count,&n))return 0;*idx=(size_t)(n-1);return 1;}
int vault_update(Session *s){
    size_t i;
    Credential *c;
    Credential original;
    char website[SV_WEBSITE_MAX+1]={0}, user[SV_USERNAME_MAX+1]={0};
    char category[SV_CATEGORY_MAX+1]={0}, notes[SV_NOTES_MAX+1]={0};
    char password[SV_PASSWORD_MAX+1]={0};
    if(!choose_index(&s->vault,&i)) return 0;
    c=&s->vault.items[i];
    original=*c;
    printf("\n  Leave a field empty to keep its current value.\n");
    if(!ui_read_line("  New website: ",website,sizeof website,1)) goto cancel;
    if(*website) strcpy(c->website,website);
    if(!ui_read_line("  New username: ",user,sizeof user,1)) goto cancel;
    if(*user) strcpy(c->username,user);
    if(!ui_read_secret("  New password (empty keeps current): ",password,sizeof password)) goto cancel;
    if(*password) strcpy(c->password,password);
    if(!ui_read_line("  New category: ",category,sizeof category,1)) goto cancel;
    if(*category) strcpy(c->category,category);
    if(!ui_read_line("  New notes: ",notes,sizeof notes,1)) goto cancel;
    if(*notes) strcpy(c->notes,notes);
    c->updated_at=(int64_t)time(NULL);
    if(!storage_save_vault(s->username,s->enc_key,&s->vault)) {
        *c=original;
        ui_error("Could not save changes; original record restored in memory.");
        goto cleanup;
    }
    ui_success("Credential updated.");
    goto cleanup;
cancel:
    *c=original;
cleanup:
    platform_secure_zero(&original,sizeof original);
    platform_secure_zero(website,sizeof website); platform_secure_zero(user,sizeof user);
    platform_secure_zero(category,sizeof category); platform_secure_zero(notes,sizeof notes);
    platform_secure_zero(password,sizeof password);
    return 1;
}

int vault_delete(Session *s){
    size_t i;if(!choose_index(&s->vault,&i))return 0;
    char answer[8];if(!ui_read_line("  Delete this credential? (y/N): ",answer,sizeof answer,0))return 0;
    if(strcmp(answer,"y")&&strcmp(answer,"Y")){ui_message("Deletion cancelled.");return 0;}
    platform_secure_zero(&s->vault.items[i],sizeof(Credential));
    for(size_t j=i;j+1<s->vault.count;j++)s->vault.items[j]=s->vault.items[j+1];
    s->vault.count--;memset(&s->vault.items[s->vault.count],0,sizeof(Credential));
    if(!storage_save_vault(s->username,s->enc_key,&s->vault)){
        if(!storage_load_vault(s->username,s->enc_key,&s->vault)) ui_error("Save failed and vault reload failed; restart before continuing.");
        else ui_error("Could not save deletion; original vault reloaded.");
        return 0;
    }
    ui_success("Credential deleted.");return 1;
}
static void do_view_details(const Vault *v){
    size_t i;
    char answer[8];
    if(!choose_index(v,&i)) return;
    printf("\n  WEBSITE  : %s\n  USERNAME : %s\n  CATEGORY : %s\n  NOTES    : %s\n",v->items[i].website,v->items[i].username,v->items[i].category,v->items[i].notes);
    if(ui_read_line("  Reveal password on screen? (y/N): ",answer,sizeof answer,0) && (answer[0]=='y'||answer[0]=='Y'))
        printf("  PASSWORD : %s\n",v->items[i].password);
    else
        printf("  PASSWORD : [hidden]\n");
}
static void do_strength_check(void){
    char password[SV_PASSWORD_MAX+1];
    int score;
    if(!ui_read_secret("  Enter password to analyse (input hidden): ",password,sizeof password)){
        ui_error("Password input was too long or unavailable.");
        platform_secure_zero(password,sizeof password);
        return;
    }
    if(password[0]=='\0'){
        ui_error("Password cannot be empty.");
        platform_secure_zero(password,sizeof password);
        return;
    }
    score=password_strength(password);
    if(score==0) ui_message("Strength: WEAK");
    else if(score==1) ui_message("Strength: FAIR");
    else if(score==2) ui_message("Strength: GOOD");
    else ui_message("Strength: STRONG");
    platform_secure_zero(password,sizeof password);
}
static void do_duplicate_report(const Vault *v){
    size_t pairs=0;
    printf("\n  DUPLICATE PASSWORD REPORT\n  ----------------------------------------------\n");
    for(size_t i=0;i<v->count;i++){
        for(size_t j=0;j<i;j++){
            if(strcmp(v->items[i].password,v->items[j].password)==0){
                printf("  [REUSED] %s shares a password with %s\n",v->items[i].website,v->items[j].website);
                pairs++;
            }
        }
    }
    if(!pairs) printf("  No duplicate passwords detected.\n");
    else printf("\n  Reuse relationships found: %zu\n",pairs);
    printf("  Password values are never displayed in this report.\n");
}
static void do_generator(void){
    int len,upper=1,lower=1,digits=1,symbols=1;char p[SV_PASSWORD_MAX+1];
    if(!ui_read_int("  Password length (8-64): ",8,64,&len))return;
    if(!password_generate(p,(size_t)len,upper,lower,digits,symbols)){ui_error("Secure random generation failed.");return;}
    printf("\n  Generated password: %s\n",p);
    char choice[8];if(ui_read_line("  Copy to clipboard? (y/N): ",choice,sizeof choice,0)&&(choice[0]=='y'||choice[0]=='Y')){
        if(platform_clipboard_copy(p))ui_success("Password copied. Clear your clipboard manually after use.");else ui_error("Clipboard utility unavailable or copy failed.");}
    platform_secure_zero(p,sizeof p);
}
static void do_copy(const Vault *v){size_t i;if(!choose_index(v,&i))return;if(platform_clipboard_copy(v->items[i].password))ui_success("Password copied. Clear your clipboard manually after use.");else ui_error("Clipboard unavailable. Install wl-clipboard or xclip on Linux.");}
static void do_backup(Session *s){char path[512];if(storage_backup(s->username,path,sizeof path))printf("\n  Encrypted backup created: %s\n",path);else ui_error("Backup creation failed.");}
static void do_restore(Session *s){char path[512],answer[8];if(!ui_read_line("  Backup file path: ",path,sizeof path,0))return;
    if(!ui_read_line("  Restore will replace the current vault. Continue? (y/N): ",answer,sizeof answer,0))return;
    if(answer[0]!='y'&&answer[0]!='Y'){ui_message("Restore cancelled.");return;}
    if(storage_restore(s->username,s->enc_key,path)){if(storage_load_vault(s->username,s->enc_key,&s->vault))ui_success("Encrypted backup restored.");else ui_error("Restored vault could not be loaded.");}
    else ui_error("Backup invalid, incompatible, or unreadable.");
}
void vault_menu(Session *s){int choice,running=1;char term[SV_WEBSITE_MAX+2];
    while(running&&s->authenticated){ui_clear();ui_banner();ui_vault_menu(s->username);
        if(!ui_read_int("\n  Select an option: ",1,15,&choice)){ui_pause();continue;}
        switch(choice){
            case 1:vault_add(s);break;
            case 2:vault_list(&s->vault,0);do_view_details(&s->vault);break;
            case 3:if(ui_read_line("  Search website, username or category: ",term,sizeof term,0))vault_search(&s->vault,term);break;
            case 4:vault_update(s);break;
            case 5:vault_delete(s);break;
            case 6:do_generator();break;
            case 7:do_strength_check();break;
            case 8:do_duplicate_report(&s->vault);break;
            case 9:password_dashboard(&s->vault);break;
            case 10:password_audit(&s->vault);break;
            case 11:do_copy(&s->vault);break;
            case 12:do_backup(s);break;
            case 13:do_restore(s);break;
            case 14:auth_change_master(s);break;
            case 15:running=0;break;
        }
        if(running)ui_pause();
    }
    auth_logout(s);
}
