#include "sv.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

int password_generate(char *out,size_t length,int use_upper,int use_lower,int use_digits,int use_symbols){
    const char *sets[4]={"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz","0123456789","!@#$%^&*()-_=+[]{};:,.?/"};
    int enabled[4]={use_upper,use_lower,use_digits,use_symbols};char pool[128];size_t pooln=0;
    if(!out||length<8||length>SV_PASSWORD_MAX)return 0;
    for(int i=0;i<4;i++)if(enabled[i]){size_t n=strlen(sets[i]);memcpy(pool+pooln,sets[i],n);pooln+=n;}
    if(!pooln)return 0;
    unsigned char rnd[SV_PASSWORD_MAX*2];size_t made=0;
    while(made<length){size_t need=(length-made)*2;if(need>sizeof rnd)need=sizeof rnd;if(RAND_bytes(rnd,(int)need)!=1){platform_secure_zero(rnd,sizeof rnd);return 0;}
        for(size_t i=0;i<need&&made<length;i++){unsigned int limit=256u-(256u%(unsigned int)pooln);if(rnd[i]<limit)out[made++]=pool[rnd[i]%pooln];}
    }
    out[length]='\0';platform_secure_zero(rnd,sizeof rnd);platform_secure_zero(pool,sizeof pool);return 1;
}
int password_strength(const char *p){
    size_t n=strlen(p);int score=0,upper=0,lower=0,digit=0,symbol=0;
    if(n>=8) score++;
    if(n>=12) score++;
    if(n>=16) score++;
    for(size_t i=0;i<n;i++){unsigned char c=(unsigned char)p[i];if(isupper(c))upper=1;else if(islower(c))lower=1;else if(isdigit(c))digit=1;else symbol=1;}
    score+=upper+lower+digit+symbol;
    if(strstr(p,"1234")||strstr(p,"password")||strstr(p,"qwerty")||strstr(p,"admin"))score-=2;
    if(n<8) return 0;
    if(score<=3) return 1;
    if(score<=5) return 2;
    return 3;
}
void password_dashboard(const Vault *v){
    size_t weak=0,strong=0,duplicates=0;
    for(size_t i=0;i<v->count;i++){int s=password_strength(v->items[i].password);if(s<2)weak++;else strong++;
        for(size_t j=0;j<i;j++)if(strcmp(v->items[i].password,v->items[j].password)==0){duplicates++;break;}}
    printf("\n  SECURITY DASHBOARD\n  ----------------------------------------------\n");
    printf("  Total credentials       : %zu\n",v->count);
    printf("  Strong / good passwords : %zu\n",strong);
    printf("  Weak / fair passwords   : %zu\n",weak);
    printf("  Reused password entries : %zu\n",duplicates);
    printf("  ----------------------------------------------\n");
    printf("  Categories:\n");
    for(size_t i=0;i<v->count;i++){
        int seen=0;
        for(size_t j=0;j<i;j++) if(strcmp(v->items[i].category,v->items[j].category)==0){seen=1;break;}
        if(!seen){size_t count=0;for(size_t j=i;j<v->count;j++)if(strcmp(v->items[i].category,v->items[j].category)==0)count++;
            printf("    %-20.20s %zu\n",v->items[i].category,count);}
    }
    if(weak||duplicates)printf("  Recommendation: review weak and reused passwords.\n");else printf("  No weak or reused passwords detected by these checks.\n");
}
void password_audit(const Vault *v){
    size_t weak=0,duplicates=0;
    printf("\n  PASSWORD SECURITY AUDIT\n  ----------------------------------------------\n");
    if(v->count==0){printf("  Your vault is empty. Add credentials to run an audit.\n");return;}
    for(size_t i=0;i<v->count;i++){
        int s=password_strength(v->items[i].password);int duplicate=0;
        for(size_t j=0;j<i;j++)if(strcmp(v->items[i].password,v->items[j].password)==0){duplicate=1;break;}
        if(s<2){printf("  [REVIEW] %s — weak or fair password\n",v->items[i].website);weak++;}
        if(duplicate){printf("  [REUSE]  %s — password is reused\n",v->items[i].website);duplicates++;}
    }
    if(!weak&&!duplicates)printf("  No weak or reused passwords detected.\n");
    printf("\n  Findings: %zu weak/fair, %zu reused.\n",weak,duplicates);
    printf("  Note: this is a local heuristic, not a breach-database check.\n");
}
