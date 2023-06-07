#include <stdio.h> 
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
    /* Use BN_bn2hex(a) for hex string * Use BN_bn2dec(a) for decimal string */
    char * number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{	
	BIGNUM *rest = BN_new();
	BIGNUM *a_copy = BN_new();
	BIGNUM *b_copy = BN_new();
	BIGNUM *x0 = BN_new();
	BIGNUM *x1 = BN_new();
	BIGNUM *y0 = BN_new();
	BIGNUM *y1 = BN_new();
	BIGNUM *n = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	
	BN_dec2bn(&x0, "1");
	BN_dec2bn(&y0, "0");
	BN_dec2bn(&x1, "0");
	BN_dec2bn(&y1, "1");
	BN_copy(a_copy, a);
	BN_copy(b_copy, b);


	while(1){
		BN_div(n, rest, a_copy, b_copy, ctx);
	
		if(BN_is_zero(rest)) break; //나머지가 0일 때 step
			
		BN_mul(x, x1, n, ctx);
		BN_mul(y, y1, n, ctx);
		BN_sub(x, x0, x); //x 구하기
		BN_sub(y, y0, y); //y 구하기
		
		BN_copy(x0, x1);
		BN_copy(y0, y1);
		BN_copy(x1, x);
		BN_copy(y1, y);
		BN_copy(a_copy, b_copy);
		BN_copy(b_copy, rest);
	}

	return b_copy;
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *gcd;

        if(argc != 3){
                printf("usage: xeuclid num1 num2");
                return -1;
        }
        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&b, argv[2]);
        gcd = XEuclid(x,y,a,b);

        printBN("(a,b) = ", gcd);
        printBN("a = ", a);
        printBN("b = ", b);
        printBN("x = ", x);
        printBN("y = ", y);
        printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

        if(a != NULL) BN_free(a);
        if(b != NULL) BN_free(b);
        if(x != NULL) BN_free(x);
        if(y != NULL) BN_free(y);
        if(gcd != NULL) BN_free(gcd);

        return 0;
}
