#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 128

void printBN(char *msg, BIGNUM *a)
{ /* Use BN_bn2hex(a) for hex string
	* Use BN_bn2dec(a) for decimal string */
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main()
{
	//initialize all variables
	BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *M1 = BN_new();
    BIGNUM *M2 = BN_new();
    BIGNUM *C1 = BN_new();
    BIGNUM *C2 = BN_new();

    // assign values
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    //I owe you $2000.
    BN_hex2bn(&M1, "49206f776520796f752024323030302e");
    //I owe you $3000.
    BN_hex2bn(&M2, "49206f776520796f752024333030302e");

    //Encryption
    BN_mod_exp(C1, M1, d, n, ctx);
    BN_mod_exp(C2, M2, d, n, ctx);
    printBN("Signature of M1:", C1);
    printBN("Signature of M2:", C2);

    //Free up memory
    BN_clear_free(n);
    BN_clear_free(d);
    BN_clear_free(M1);
    BN_clear_free(M2);
    BN_clear_free(C1);
    BN_clear_free(C2);
}
