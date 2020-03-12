#include "libecc/src/libsig.h"
#include "libecc/src/external_deps/time.h"

void hex_dump(unsigned char* m,int mlen){
    unsigned char* cm = (unsigned)m;
    for(int i=0;i<mlen;i++){
        ext_printf("%02x",cm[i]);
    }
    ext_printf("\n");
}

int main(){
    ext_printf("hello ECDSA secp256k1\n");
    unsigned char message[] = "hello world";
    unsigned char hashedmsg[32];
    sha256(message,11,hashedmsg);

    ext_printf("twiced sha256 hash value:");
    hex_dump(hashedmsg,32);

    // import secp256r1 params
    ec_params ecparams;
    import_params(&ecparams,&secp256k1_str_params);
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

    ext_printf("ECDSA signature for hash value:");
    hex_dump(sig,ecdsa_sign_len);

    //virfy signature
    k = ec_verify(sig,ecdsa_sign_len,&(eckey.pub_key),hashedmsg,32,ECDSA,SHA256);
    if(k==-1){
        ext_printf("verify failed !");
        return 0;
    }
    // performance test
    u64 times = 1000;
    u64 current_time,next_time;
    double times_per_sec;
    ec_key_pair pairs[times];
    unsigned char sigs[times][ecdsa_sign_len];

    get_ms_time(&current_time);
    //ext_printf("current_time: %ulld\n",current_time);
    for(int i=0;i<times;i++){
        ec_key_pair_gen(&(pairs[i]),&ecparams,ECDSA);
    }
    get_ms_time(&next_time);
    //ext_printf("next_time: %ulld\n",next_time);
    times_per_sec = (times*1000)/(next_time-current_time);
    ext_printf("key pair generate rate: %.1lf(times per sec)\n",times_per_sec);

    get_ms_time(&current_time);
    //ext_printf("current_time: %ulld\n",current_time);
    for(int i=0;i<times;i++){
        ec_sign(sigs[i],ecdsa_sign_len,&(pairs[i]),hashedmsg,32,ECDSA,SHA256);
    }
    get_ms_time(&next_time);
    //ext_printf("next_time: %ulld\n",next_time);
    times_per_sec = (times*1000)/(next_time-current_time);
    ext_printf("sign function rate: %.1lf(times per sec)\n",times_per_sec);

    get_ms_time(&current_time);
    //ext_printf("current_time: %ulld\n",current_time);
    for(int i=0;i<times;i++){
        ec_verify(sigs[i],ecdsa_sign_len,&((pairs[i]).pub_key),hashedmsg,32,ECDSA,SHA256);
    }
    get_ms_time(&next_time);
    //ext_printf("next_time: %ulld\n",next_time);
    times_per_sec = (times*1000)/(next_time-current_time);
    ext_printf("verify function rate: %.1lf(times per sec)\n",times_per_sec);
    return 0;
}
