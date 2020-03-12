DEPENDS = libecc/src/external_deps/print.o libecc/src/external_deps/time.o libecc/src/external_deps/rand.o
libsign = libecc/build/libsign.a

all:BN ECDSA MuSig libecc

RY:RY.c
	# install gmp pbc; run "export usr/local/lib/libpbc.so.1"
	gcc -g RY.c $(libsign) $(DEPENDS) -L. -lpbc -lgmp -o build/RY

DBN:DBN.c
	# install gmp pbc; run "export usr/local/lib/libpbc.so.1"
	gcc -g BDN.c $(libsign) $(DEPENDS) -L. -lpbc -lgmp -o build/BDN

ECDSA: ECDSA_secp256r1.c ECDSA_secp256k1.c
	gcc -g ECDSA_secp256r1.c $(libsign) $(DEPENDS) -o build/ECDSA_secp256r1
	gcc -g ECDSA_secp256k1.c $(libsign) $(DEPENDS) -o build/ECDSA_secp256k1

BN: BN_secp256k1.c BN.c BN.h
	gcc -g -c BN.c -o build/BN.o
	gcc -g build/BN.o BN_secp256k1.c $(libsign) $(DEPENDS) -o build/BN_secp256k1

MuSig: MuSig.c MuSig.h
	gcc -g -c MuSig.c -o build/MuSig.o
	gcc -g build/MuSig.o MuSig_secp256k1.c $(libsign) $(DEPENDS) -o build/MuSig_secp256k1

libecc: libecc/*
	cd libecc;make debug


clean:
	rm build/*
