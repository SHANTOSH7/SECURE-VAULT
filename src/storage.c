#define _POSIX_C_SOURCE 200809L
#include "sv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#ifdef _WIN32
#include <io.h>
#define PATH_SEP "\\"
#else
#include <unistd.h>
#include <sys/stat.h>
#define PATH_SEP "/"
#endif

#define SERIAL_MAGIC "SVPL0001"
#define MAX_FILE_SIZE (4u * 1024u * 1024u)

typedef struct { unsigned char *p; size_t n, cap; } Buffer;
static int reserve(Buffer *b, size_t add) {
    if (add > SIZE_MAX - b->n) return 0;
    size_t need = b->n + add;
    if (need <= b->cap) return 1;
    size_t nc = b->cap ? b->cap : 256;
    while (nc < need) { if (nc > SIZE_MAX/2) return 0; nc *= 2; }
    unsigned char *q = (unsigned char *)realloc(b->p, nc);
    if (!q) return 0;
    b->p=q; b->cap=nc; return 1;
}
static int append(Buffer *b, const void *p, size_t n) {
    if (!reserve(b,n)) return 0;
    if (n) memcpy(b->p+b->n,p,n);
    b->n+=n;
    return 1;
}
static int put16(Buffer *b, uint16_t v) { unsigned char x[2]={(unsigned char)(v>>8),(unsigned char)v}; return append(b,x,2); }
static int put64(Buffer *b, uint64_t v) { unsigned char x[8]; for(int i=7;i>=0;i--){x[i]=(unsigned char)v;v>>=8;} return append(b,x,8); }
static int get16(const unsigned char **p,const unsigned char *end,uint16_t *v){ if((size_t)(end-*p)<2)return 0;*v=(uint16_t)(((*p)[0]<<8)|(*p)[1]);*p+=2;return 1; }
static int get64(const unsigned char **p,const unsigned char *end,uint64_t *v){ if((size_t)(end-*p)<8)return 0;uint64_t x=0;for(int i=0;i<8;i++)x=(x<<8)|(*p)[i];*p+=8;*v=x;return 1; }
static int putstr(Buffer *b,const char *s){ size_t n=strlen(s); if(n>UINT16_MAX)return 0; return put16(b,(uint16_t)n)&&append(b,s,n); }
static int getstr(const unsigned char **p,const unsigned char *end,char *out,size_t cap){ uint16_t n; if(!get16(p,end,&n)||(size_t)(end-*p)<n||n>=cap)return 0; memcpy(out,*p,n);out[n]='\0';*p+=n;return 1; }
static int serialize_vault(const Vault *v, unsigned char **out,size_t *len){
    Buffer b={0}; unsigned char count[4];
    if(v->count>SV_MAX_CREDS)return 0;
    memcpy(count,"SVPL",4); if(!append(&b,count,4))goto fail;
    count[0]=(unsigned char)(v->count>>24);count[1]=(unsigned char)(v->count>>16);count[2]=(unsigned char)(v->count>>8);count[3]=(unsigned char)v->count;
    if(!append(&b,count,4))goto fail;
    for(size_t i=0;i<v->count;i++){
        const Credential *c=&v->items[i];
        if(!putstr(&b,c->website)||!putstr(&b,c->username)||!putstr(&b,c->password)||!putstr(&b,c->category)||!putstr(&b,c->notes)||!put64(&b,(uint64_t)c->updated_at))goto fail;
    }
    *out=b.p;*len=b.n;return 1;
fail: if(b.p){platform_secure_zero(b.p,b.cap);free(b.p);}return 0;
}
static int deserialize_vault(const unsigned char *data,size_t len,Vault *v){
    if(len<8||memcmp(data,"SVPL",4)!=0)return 0;
    uint32_t count=((uint32_t)data[4]<<24)|((uint32_t)data[5]<<16)|((uint32_t)data[6]<<8)|data[7];
    if(count>SV_MAX_CREDS)return 0;
    const unsigned char *p=data+8,*end=data+len;
    Vault *temp=(Vault *)calloc(1,sizeof *temp);
    if(!temp) return 0;
    for(uint32_t i=0;i<count;i++){
        Credential *c=&temp->items[i];uint64_t ts;
        if(!getstr(&p,end,c->website,sizeof c->website)||!getstr(&p,end,c->username,sizeof c->username)||!getstr(&p,end,c->password,sizeof c->password)||!getstr(&p,end,c->category,sizeof c->category)||!getstr(&p,end,c->notes,sizeof c->notes)||!get64(&p,end,&ts)||ts>(uint64_t)INT64_MAX){
            platform_secure_zero(temp,sizeof *temp);free(temp);return 0;
        }
        c->updated_at=(int64_t)ts;
    }
    if(p!=end){platform_secure_zero(temp,sizeof *temp);free(temp);return 0;}
    temp->count=count;*v=*temp;platform_secure_zero(temp,sizeof *temp);free(temp);return 1;
}
static void to_hex(const unsigned char *in,size_t n,char *out){static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){out[i*2]=h[in[i]>>4];out[i*2+1]=h[in[i]&15];}out[n*2]='\0';}
static int from_hex(const char *in,unsigned char *out,size_t n){for(size_t i=0;i<n;i++){int a,b;char x=in[i*2],y=in[i*2+1];a=(x>='0'&&x<='9')?x-'0':(x>='a'&&x<='f')?x-'a'+10:(x>='A'&&x<='F')?x-'A'+10:-1;b=(y>='0'&&y<='9')?y-'0':(y>='a'&&y<='f')?y-'a'+10:(y>='A'&&y<='F')?y-'A'+10:-1;if(a<0||b<0)return 0;out[i]=(unsigned char)((a<<4)|b);}return in[n*2]=='\0';}
static int valid_username(const char *u){size_t n=strlen(u);if(!n||n>SV_USER_MAX)return 0;for(size_t i=0;i<n;i++)if(!((u[i]>='a'&&u[i]<='z')||(u[i]>='A'&&u[i]<='Z')||(u[i]>='0'&&u[i]<='9')||u[i]=='_'||u[i]=='-'))return 0;return 1;}
int storage_init(void){
    if(!platform_mkdir("data")||!platform_mkdir(SV_VAULT_DIR)||!platform_mkdir(SV_BACKUP_DIR)) return 0;
#ifndef _WIN32
    if(access(SV_REGISTRY, F_OK) == 0 && chmod(SV_REGISTRY, 0600) != 0) return 0;
#endif
    return 1;
}
int storage_user_exists(const char *username){UserRecord r;return storage_find_user(username,&r);}
int storage_add_user(const UserRecord *u){
    if(!u||!valid_username(u->username)||storage_user_exists(u->username))return 0;
    FILE *f=fopen(SV_REGISTRY,"ab");if(!f)return 0;
#ifndef _WIN32
    chmod(SV_REGISTRY, 0600);
#endif
    char salt[SV_SALT_LEN*2+1],ver[65];to_hex(u->salt,SV_SALT_LEN,salt);to_hex(u->verifier,32,ver);
    int ok=fprintf(f,"%s:%u:%s:%s\n",u->username,u->iterations,salt,ver)>0;
    if(fflush(f)!=0)ok=0;
#ifndef _WIN32
    if(ok && fsync(fileno(f))!=0)ok=0;
#endif
    if(fclose(f)!=0)ok=0;
    return ok;
}
int storage_find_user(const char *username,UserRecord *out){
    FILE *f=fopen(SV_REGISTRY,"rb");if(!f)return 0;
    char line[256],name[SV_USER_MAX+1],salt[SV_SALT_LEN*2+1],ver[65];unsigned iter;int found=0;
    while(fgets(line,sizeof line,f)){
        if(sscanf(line,"%32[^:]:%u:%32[0-9a-fA-F]:%64[0-9a-fA-F]",name,&iter,salt,ver)==4&&strcmp(name,username)==0){
            UserRecord r;memset(&r,0,sizeof r);strcpy(r.username,name);r.iterations=iter;
            if(iter<100000||iter>5000000||!from_hex(salt,r.salt,SV_SALT_LEN)||!from_hex(ver,r.verifier,32))break;
            if(out) *out=r;
            found=1;
            break;
        }
    }
    fclose(f);return found;
}
int storage_vault_path(const char *username,char *out,size_t cap){
    if(!valid_username(username))return 0;
    int n=snprintf(out,cap,"%s/%s.svlt",SV_VAULT_DIR,username);return n>0&&(size_t)n<cap;
}
static int read_file(const char *path,unsigned char **data,size_t *len){
    FILE *f=fopen(path,"rb");long n;unsigned char *p;if(!f)return 0;
    if(fseek(f,0,SEEK_END)!=0||(n=ftell(f))<0||(unsigned long)n>MAX_FILE_SIZE||fseek(f,0,SEEK_SET)!=0){fclose(f);return 0;}
    p=(unsigned char *)malloc((size_t)n? (size_t)n:1);if(!p){fclose(f);return 0;}
    if(n&&fread(p,1,(size_t)n,f)!=(size_t)n){free(p);fclose(f);return 0;}fclose(f);*data=p;*len=(size_t)n;return 1;
}
static int write_atomic(const char *path,const unsigned char *data,size_t len){
    char tmp[512];if(snprintf(tmp,sizeof tmp,"%s.tmp",path)>=(int)sizeof tmp)return 0;
    FILE *f=fopen(tmp,"wb");if(!f)return 0;
#ifndef _WIN32
    chmod(tmp, 0600);
#endif
    int ok=(len==0||fwrite(data,1,len,f)==len);if(fflush(f)!=0)ok=0;
#ifndef _WIN32
    if(ok&&fsync(fileno(f))!=0)ok=0;
#endif
    if(fclose(f)!=0)ok=0;
    if(!ok){remove(tmp);return 0;}
    if(!platform_atomic_replace(tmp,path)){remove(tmp);return 0;}return 1;
}
int storage_save_vault(const char *username,const unsigned char key[32],const Vault *vault){
    unsigned char *plain=NULL,*enc=NULL;size_t plen=0,elen=0;char path[256];int ok=0;
    if(!serialize_vault(vault,&plain,&plen)||!storage_vault_path(username,path,sizeof path))goto done;
    if(!crypto_encrypt(username,key,plain,plen,&enc,&elen))goto done;
    ok=write_atomic(path,enc,elen);
done: if(plain){platform_secure_zero(plain,plen);free(plain);}if(enc){platform_secure_zero(enc,elen);free(enc);}return ok;
}
int storage_load_vault(const char *username,const unsigned char key[32],Vault *vault){
    unsigned char *enc=NULL,*plain=NULL;size_t elen=0,plen=0;char path[256];int ok=0;
    if(!storage_vault_path(username,path,sizeof path)||!read_file(path,&enc,&elen))goto done;
    if(!crypto_decrypt(username,key,enc,elen,&plain,&plen))goto done;
    ok=deserialize_vault(plain,plen,vault);
done: if(enc){platform_secure_zero(enc,elen);free(enc);}if(plain){platform_secure_zero(plain,plen);free(plain);}return ok;
}
int storage_backup(const char *username,char *out_path,size_t cap){
    char src[256], suffix[9];
    unsigned char *data=NULL, random[4];
    size_t len=0; time_t now=time(NULL); int ok=0;
    if(!storage_vault_path(username,src,sizeof src)||!read_file(src,&data,&len))goto done;
    if(!crypto_random(random,sizeof random))goto done;
    static const char hex[]="0123456789abcdef";
    for(size_t i=0;i<sizeof random;i++){suffix[i*2]=hex[random[i]>>4];suffix[i*2+1]=hex[random[i]&15];}
    suffix[8]='\0';
    int n=snprintf(out_path,cap,"%s/%s_%lld_%s.svbackup",SV_BACKUP_DIR,username,(long long)now,suffix);
    platform_secure_zero(random,sizeof random);
    if(n<=0||(size_t)n>=cap)goto done;
    ok=write_atomic(out_path,data,len);
done:if(data){platform_secure_zero(data,len);free(data);}return ok;
}
int storage_restore(const char *username,const unsigned char key[32],const char *backup_path){
    unsigned char *enc=NULL,*plain=NULL;size_t elen=0,plen=0;Vault *check=NULL;char dest[256];int ok=0;
    if(!storage_vault_path(username,dest,sizeof dest)||!read_file(backup_path,&enc,&elen))goto done;
    check=(Vault *)malloc(sizeof *check);
    if(!check)goto done;
    if(!crypto_decrypt(username,key,enc,elen,&plain,&plen)||!deserialize_vault(plain,plen,check))goto done;
    ok=write_atomic(dest,enc,elen);
done:if(check){platform_secure_zero(check,sizeof *check);free(check);}if(enc){platform_secure_zero(enc,elen);free(enc);}if(plain){platform_secure_zero(plain,plen);free(plain);}return ok;
}

int storage_update_user(const UserRecord *u){
    FILE *in=fopen(SV_REGISTRY,"rb");if(!in)return 0;
    char tmpname[]="data/users.dat.tmp";FILE *out=fopen(tmpname,"wb");if(!out){fclose(in);return 0;}
    char line[256],name[SV_USER_MAX+1],salt[SV_SALT_LEN*2+1],ver[65];unsigned iter;int found=0,ok=1;
    char new_salt[SV_SALT_LEN*2+1],new_ver[65];to_hex(u->salt,SV_SALT_LEN,new_salt);to_hex(u->verifier,32,new_ver);
    while(fgets(line,sizeof line,in)){
        if(sscanf(line,"%32[^:]:%u:%32[0-9a-fA-F]:%64[0-9a-fA-F]",name,&iter,salt,ver)==4&&strcmp(name,u->username)==0){
            if(fprintf(out,"%s:%u:%s:%s\n",u->username,u->iterations,new_salt,new_ver)<0) ok=0;
            found=1;
        }else if(fputs(line,out)==EOF)ok=0;
    }
    if(fflush(out)!=0)ok=0;
#ifndef _WIN32
    if(ok&&fsync(fileno(out))!=0)ok=0;
#endif
    if(fclose(in)!=0)ok=0;
    if(fclose(out)!=0)ok=0;
    if(!ok||!found){remove(tmpname);return 0;}
    if(!platform_atomic_replace(tmpname,SV_REGISTRY)){remove(tmpname);return 0;}return 1;
}
