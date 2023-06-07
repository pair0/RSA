/*
입력 : a, e, m
출력 : r = a**e mod m (a를 e승 (mod m)한 결과)
*/

#include <stdio.h>
#include <openssl/bn.h>



void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)
{
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *a_copy = BN_new();
        BN_copy(a_copy, a);

        for(int i = BN_num_bits(e)-2; i >= 0; i--)
        {
                BN_mod_mul(a_copy, a_copy, a_copy, m, ctx); 
                if(BN_is_bit_set(e, i)) //e의 i번 째 비트가 설정되었을 떄 동작
                        BN_mod_mul(a_copy, a_copy, a, m, ctx);
        }

        BN_copy(r, a_copy);
        BN_free(a_copy);
        if(ctx != NULL) BN_CTX_free(ctx);
        return 1;
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *res = BN_new();

        if(argc != 4){
                printf("usage: exp base exponent modulus\n");
                return -1;
        }

        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&e, argv[2]);
        BN_dec2bn(&m, argv[3]);
        printBN("a = ", a);
        printBN("e = ", e);
        printBN("m = ", m);

        ExpMod(res,a,e,m);

        printBN("a**e mod m = ", res);

        if(a != NULL) BN_free(a);
        if(e != NULL) BN_free(e);
        if(m != NULL) BN_free(m);
        if(res != NULL) BN_free(res);

        return 0;
}

