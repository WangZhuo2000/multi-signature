import gmpy2,math

def showCstyleData(number):
    number_str = hex(number)[2:]
    if(len(number_str)%2==1):
        number_str = "0"+number_str
    newline_hit = 0
    print("{")
    for i in range(0,len(number_str),2):
        if(newline_hit==8):
            print("")
            newline_hit = 1
        else:
            newline_hit += 1
        if(i+2<len(number_str)):
            print("0x"+number_str[i:i+2]+", ",end="")
        else:
            print("0x"+number_str[i:i+2]+"",end="")
    print("")
    print("};")


def drive_r_from_p(p):
    return (2**p_bit_size) % p

def drive_rsq_from_p(p):
    return (2**(2*p_bit_size)) % p

def drive_mpinv_from_p(p):
    B = 2**64
    pinv = gmpy2.invert(p,B)
    mpinv = (-pinv) % B
    return mpinv
def gen_reciprocal(p):
    B = 2**64
    B3 = B**3
    rec = B3//((p>>(p_bit_size-2*64))+1) - B 
    return rec

# secp256r1 params
rp = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
p_bit_size = 0x100
ra = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
rb = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

rx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
ry = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
r_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
r_cofactor = 0x01

# secp256k1 params
kp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F 
P_bit_size = 0x100
ka = 0x0000000000000000000000000000000000000000000000000000000000000000
kb = 0x0000000000000000000000000000000000000000000000000000000000000007

kx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
ky = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
k_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
k_cofactor = 0x01

showCstyleData(kx)
showCstyleData(ky)
