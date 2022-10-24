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
    BN_CTX *ctx = BN_CTX_new();
    //p and q are given
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();

    // a is the exponent for e
    BIGNUM *a = BN_new();
    //product of p*q
    BIGNUM *n = BN_new();
    //e is given
    BIGNUM *e = BN_new();
    //
    BIGNUM *d = BN_new();
    BIGNUM *res = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();


    //initialize p,q,e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    //n = p * q
    BN_mul(n, p, q, ctx);
    printBN("Public Key",n);

    //a(n) = (p-1) * (q-1)
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(a, p_minus_1, q_minus_1, ctx);

    BN_mod_inverse(d, e, a, ctx);

    printBN("private key d= ",d);
    return 0;

    //free up memory
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(n);
    BN_clear_free(res);
    BN_clear_free(a);
    BN_clear_free(e);
    BN_clear_free(d);
    BN_clear_free(p_minus_1);
    BN_clear_free(q_minus_1);

    return 0;
}
