#include "libecc/src/libsig.h"

void hex_dump(unsigned char* m,int mlen){
    for(int i=0;i<mlen;i++){
        ext_printf("%02x",m[i]);
    }
    ext_printf("\n");
}

int main(){
    ext_printf("hello ECDSA secp256r1\n");
    unsigned char message[] = "hello world";
    unsigned char hashedmsg[32];
    sha256(message,11,hashedmsg);
    hex_dump(hashedmsg,32);
    // import secp256r1 params
    ec_params ecparams;
    import_params(&ecparams,&secp256r1_str_params);
    // generate random key pair
    ec_key_pair eckey;
    int k = ec_key_pair_gen(&eckey,&ecparams,ECDSA);
    if(k==-1){
        ext_printf("key pair generate failed !");
        return 0;
    }
    // sign hashed message
    int ecdsa_sign_len = 64;
    unsigned char sig[ecdsa_sign_len];
    k = ec_sign(sig,ecdsa_sign_len,&eckey,hashedmsg,32,ECDSA,SHA256);
    if(k==-1){
        ext_printf("sign failed !");
        return 0;
    }
    hex_dump(sig,ecdsa_sign_len);
    //virfy signature
    k = ec_verify(sig,ecdsa_sign_len,&(eckey.pub_key),hashedmsg,32,ECDSA,SHA256);
    if(k==-1){
        ext_printf("verify failed !");
        return 0;
    }
    return 0;
}
