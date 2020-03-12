#define WITH_STDLIB
#include<pbc/pbc.h>
#include "libecc/src/hash/sha256.h"

#define MAX_SIGNERS 16

/* define data structure */
typedef struct{
	pairing_t pairing;
    element_t g1;
    element_t g2;
}BDN_param;

typedef BDN_param* BDN_param_t;

typedef struct{
    element_t private_key;
    element_t public_key;
}BDN_keypair;

typedef BDN_keypair *BDN_keypair_t;

typedef struct{
	BDN_param_t param;
	char* message;
	uint32_t len;
    uint32_t signers;
    BDN_keypair kp;
	element_t public_key[MAX_SIGNERS];
    element_t s[MAX_SIGNERS];
    uint32_t recv_s_number;
}BDN_context;

/* init pairing=based curve with type A */
void pbc_type_A_pairing_init(pairing_t pairing){
    char s[16384];
    FILE *fp = stdin;
    char file[] = "TypeA_pairing.param";
    fp = fopen(file, "r");
    if (!fp) pbc_die("error opening %s",file);
    size_t count = fread(s, 1, 16384, fp);
    if (!count) pbc_die("input error");
    fclose(fp);

    if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
}

/* H0 from char* to a element in G1 */
void H0(element_t dst, char* src,uint32_t len){
    char hashofmsg[SHA256_DIGEST_SIZE];
    sha256(src,len,hashofmsg);
    element_from_hash(dst,hashofmsg,SHA256_DIGEST_SIZE);
}
/* H1 from G2xG2xG2...G2 to a element in Z_r */
void H1(element_t dst, element_t src1,element_t* src2,uint32_t src2len){
    char hashofmsg[SHA256_DIGEST_SIZE];
    uint32_t maplen = element_length_in_bytes(src1);
    char map[maplen];
    sha256_context ctx;
    sha256_init(&ctx);

    element_to_bytes(map,src1);
    sha256_update(&ctx,map,maplen);

    for(int i=0;i<src2len;i++){
        element_to_bytes(map,src2[i]);
        sha256_update(&ctx,map,maplen);
    }

    sha256_final(&ctx,hashofmsg);

    element_from_hash(dst,hashofmsg,SHA256_DIGEST_SIZE);
}

/* init params with type A pairing.
(see details in  https://crypto.stanford.edu/pbc/manual/ch08s03.html
   random generate generator g1 in G1 and g2 in G2*/
void BDN_param_generate(BDN_param_t params){
    pbc_type_A_pairing_init(params->pairing);
    element_init_G1(params->g1,params->pairing);
    element_init_G2(params->g2,params->pairing);
    element_random(params->g1);
    element_random(params->g2);
}

/* random generate private_key & public key */
void BDN_keypair_generate(BDN_param* param,BDN_keypair_t kpair){
    element_init_Zr(kpair->private_key,param->pairing);
    element_init_G2(kpair->public_key,param->pairing);
    element_random(kpair->private_key);
    element_pow_zn(kpair->public_key, param->g2 , kpair->private_key);
}

static void element_copy(element_t dst,element_t src){
    /* MUST element src initalize */
    if(src->field==NULL){
        pbc_die("src not initalize!");
    }
    /* init element dst */
    element_init_same_as(dst,src);
    /* stack for convert */
    unsigned char tmp[element_length_in_bytes(src)];
    /* src -> tmp -> dst */
    element_to_bytes(tmp,src);
    element_from_bytes(dst,tmp);
}

static void BDN_sig_context_init(
    BDN_context* ctx, /* context of BDN signature */
    BDN_param_t params,
    BDN_keypair_t kpair,
    element_t* publickey,
    uint32_t signers,
    char* message,
    uint32_t len){
    
    /* copy message to ctx */
    ctx->message = message;
    ctx->len = len;
    ctx->signers = signers;
    /* copy params to ctx */
    ctx->param = params;
    /* copy key pair to ctx */
    element_copy(ctx->kp.private_key,kpair->private_key);
    element_copy(ctx->kp.public_key,kpair->public_key);
    /* copy public key list to context */
    for(int i=0;i<signers;i++){
        element_copy(ctx->public_key[i],publickey[i]);
    }
    /* init element s */
    for(int i=0;i<signers;i++){
        element_init_G1(ctx->s[i],ctx->param->pairing);
        element_set1(ctx->s[i]);
    }
    ctx->recv_s_number = 0;
}

void BDN_sig_recv_s(BDN_context* ctx,element_t s){
    for(int i=0;i<ctx->recv_s_number;i++){
        if(element_cmp(ctx->s[i],s)==0){
            return ;
        }
    }
    element_copy(ctx->s[ctx->recv_s_number],s);
    ctx->recv_s_number += 1;
}

void BDN_sig_send_s(BDN_context* ctx,element_t s){
    /* init a list */
    element_t a;
    element_init_Zr(a,ctx->param->pairing);
    H1(a,ctx->kp.public_key,ctx->public_key,ctx->signers);

    /* init s */
    element_init_G1(s,ctx->param->pairing);
    H0(s,ctx->message,ctx->len);

    /* s = H0(m)^a_i^sk_i */
    element_pow_zn(s,s,a);
    element_pow_zn(s,s,ctx->kp.private_key);

    for(int i=0;i<ctx->recv_s_number;i++){
        if(element_cmp(ctx->s[i],s)==0){
            return ;
        }
    }
    element_copy(ctx->s[ctx->recv_s_number],s);
    ctx->recv_s_number += 1;
}


int BDN_sig_finalize(BDN_context* ctx,element_t sig){
    if(ctx->signers!=ctx->recv_s_number){
        return -1;
    }
    if(ctx->recv_s_number<=1){
        return -1;
    }
    /* init sig */
    element_init_G1(sig,ctx->param->pairing);
    /* compute signature */
    element_copy(sig,ctx->s[0]);
    for(int i=1;i<ctx->recv_s_number;i++){
        element_mul(sig,sig,ctx->s[i]);
    }
    return 0;
    
}

/* return 0 if accept this signature; return 1 meaning refuse this signature*/
int BDN_verify(
    BDN_param_t param,
    element_t* publickey_list,
    uint32_t signers,
    element_t sig,
    char* msg,
    uint32_t mlen){
    /* aggregate public key list */
    element_t apk,tmp,a;
    element_init_G2(apk,param->pairing);
    element_init_G2(tmp,param->pairing);
    element_init_Zr(a,param->pairing);
    H1(a,publickey_list[0],publickey_list,signers);
    element_pow_zn(apk,publickey_list[0],a);
    for(int i=1;i<signers;i++){
        H1(a,publickey_list[i],publickey_list,signers);
        element_pow_zn(tmp,publickey_list[i],a);
        element_mul(apk,apk,tmp);
    }
    /* compute H0(m) */
    element_t H0m;
    element_init_G1(H0m,param->pairing);
    H0(H0m,msg,mlen);
    /* verify signature */
    element_t left,right;
    element_init_GT(left,param->pairing);
    element_init_GT(right,param->pairing);
    pairing_apply(left,sig,param->g2,param->pairing);
    pairing_apply(right,H0m,apk,param->pairing);
    if(element_cmp(left,right)==0){
        return 0;
    }else{
        return -1;
    }
}

#define SIGNERS 3
int main(){

    printf("Hello BDN signature!\n");
    char msg[] = "helloBDN!";
    uint32_t len = sizeof(msg);
    BDN_param param;
    BDN_context ctx[SIGNERS];
    BDN_keypair kpairs[SIGNERS];
    element_t public_keylist[SIGNERS];
    element_t s[SIGNERS];
    element_t sig[SIGNERS];

    /* random generate param */
    BDN_param_generate(&param);
    
    /* generate private key & public key */
    for(int i=0;i<SIGNERS;i++){
        BDN_keypair_generate(&param,&(kpairs[i]));
    }

    /* init public key list */
    for(int i=0;i<SIGNERS;i++){
        element_copy(public_keylist[i],kpairs[i].public_key);
    }
    
    /* initing sign protocol for all signers */
    for(int i=0;i<SIGNERS;i++){
        BDN_sig_context_init(&(ctx[i]),&param,&(kpairs[i]),public_keylist,SIGNERS,msg,len);
    }

    /* collect all s from all signers */
    for(int i=0;i<SIGNERS;i++){
        BDN_sig_send_s(&(ctx[i]),s[i]);
    }

    /* recv s for all signers */
    for(int i=0;i<SIGNERS;i++){
        for(int j=0;j<SIGNERS;j++){
            BDN_sig_recv_s(&(ctx[i]),s[j]);
        }
    }

    /* finalize all signature */
    for(int i=0;i<SIGNERS;i++){
        BDN_sig_finalize(&ctx[i],sig[i]);
    }

    /* check equal for all signature */
    for(int i=1;i<SIGNERS;i++){
        if(element_cmp(sig[0],sig[i])!=0){
            pbc_die("(%d,%d) signature check fail ",0,i);
        }
    }

    printf("check signature pass\n");

    if(BDN_verify(&param,public_keylist,SIGNERS,sig[0],msg,len)==0){
        printf("check verify pass\n");
    }else{
        printf("check verify refuse\n");
    }

    return 0;
}
