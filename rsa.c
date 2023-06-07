#include <stdio.h> 
#include <string.h>
#include <openssl/bn.h>
#include <stdbool.h>

//RSA 구조체
typedef struct _b11rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB11_RSA;

//RSA 구조체를 생성하여 포인터를 리턴하는 함수
BOB11_RSA *BOB11_RSA_new();

//RSA 구조체 포인터를 해제하는 함수
int BOB11_RSA_free(BOB11_RSA *b11rsa);

//밀러라빈
bool bn_miller_rabin_is_prime(BIGNUM *p_q, int k);

//XEuclid
BIGNUM *XEuclid(BIGNUM *x, const BIGNUM *a, const BIGNUM *b);

/*
RSA 키 생성 함수
입력 : nBits (RSA modulus bit size)
출력 : b11rsa (구조체에 n, e, d 가  생성돼 있어야 함)
p=C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7
q=F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F
*/
int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits);

//암호화 복호화 및 다른 연산을 위한 알고리즘 함수
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);

/*
RSA 암호화 함수
입력 : 공개키를 포함한 b11rsa, 메시지 m
출력 : 암호문 c
*/
int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa);
/*
RSA 복호화 함수
입력 : 공개키를 포함한 b11rsa, 암호문 c
출력 : 평문 m
*/
int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa);

/*
다음과 같은 메인 함수에서 작동되도록 하시오.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!주의!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
1. 입출력은 모두 Hexadecimal 표현을 사용할 것!
2. Modular inversion과 modular exponentiation은 반드시 이전에 숙제로 작성했던 것을 사용할 것!
3. libcrypto의 함수는 가감승제와 비트연산, 입출력 함수 외에는 사용하지 말 것 (알아서 이 과정의 교육목표에 맞게 쓰시기 바랍니다).
*/
void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int main (int argc, char *argv[])
{
   
    BOB11_RSA *b11rsa = BOB11_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB11_RSA_KeyGen(b11rsa,1024);
        BN_print_fp(stdout,b11rsa->n);
        printf(" ");
        BN_print_fp(stdout,b11rsa->e);
        printf(" ");
        BN_print_fp(stdout,b11rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b11rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b11rsa->e, argv[2]);
            BOB11_RSA_Enc(out,in, b11rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b11rsa->d, argv[2]);
            BOB11_RSA_Dec(out,in, b11rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b11rsa!= NULL) BOB11_RSA_free(b11rsa);

    return 0;
}


//구조체 생성 함수
BOB11_RSA *BOB11_RSA_new() {
    BOB11_RSA *b11rsa = (BOB11_RSA *)malloc(sizeof(BOB11_RSA)); //동적으로 구조체 선언
    b11rsa->e = BN_new(); //구조체의 e 변수 BN 객체 생성
    b11rsa->d = BN_new(); //구조체의 d 변수 BN 객체 생성
    b11rsa->n = BN_new(); //구조체의 n 변수 BN 객체 생성

    return b11rsa;  //구조체 반환
}

//RSA 구조체 포인터를 해제하는 함수
int BOB11_RSA_free(BOB11_RSA *b11rsa){
    free(b11rsa); //구조체 free
    return 1;
}

bool bn_miller_rabin_is_prime(BIGNUM *n, int k){
    BIGNUM *one = BN_new(); // 숫자 1을 BIGNUM과 연산하기 위해 선언
    BIGNUM *two = BN_new(); // 숫자 2를 BIGNUM과 연산하기 위해 선언
    BN_CTX *ctx = BN_CTX_new(); 
    BIGNUM *n_2 = BN_new(); 
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *n_1 = BN_new();
    BIGNUM *check = BN_new();
    BIGNUM *s_1 = BN_new();
    BN_one(one);
    BN_dec2bn(&two, "2");
    BN_mod(n_2, n, two, ctx);

    if(!BN_cmp(n,two))
        return true;    
    
    if(BN_is_zero(n_2))
        return false;

    BN_sub(n_1,n,one);
    BN_zero(r);
    BN_copy(s ,n_1);
   
    BN_mod(check, s, two, ctx);
    
    while(BN_is_zero(check)){
        BN_add(r,r,one);
        BN_div(s, s_1, s, two, ctx);
        BN_mod(check,s,two,ctx);
    }

    BIGNUM* a = BN_new();
    BIGNUM* BN_i = BN_new();
    BIGNUM* r_1 = BN_new();
    BN_sub(r_1, r, one);
    
    BIGNUM* x = BN_new();
    
    for(int i = 0; i<k; i++){
        BN_zero(BN_i);
        BN_rand_range(a, n_1);
        if(BN_is_zero(a)) 
            BN_add(a,a,two);
        if(BN_is_one(a)) 
            BN_add(a,a,one);
        
        ExpMod(x, a, s, n);

        if((BN_is_one(x)==1) || (BN_cmp(x,n_1)==0)){
            continue;
        }

        for(; BN_cmp(BN_i,r_1); BN_add(BN_i,BN_i,one)){
            ExpMod(x, x, two, n);
            if(!BN_cmp(x, n_1)){
                break;
            }
        }
        if(!BN_cmp(BN_i,r_1)){
            return false;
        }
    }
    return true;
}

BIGNUM *XEuclid(BIGNUM *x, const BIGNUM *a, const BIGNUM *b){	
	BIGNUM *rest = BN_new();
	BIGNUM *a_copy = BN_new();
	BIGNUM *b_copy = BN_new();
    BIGNUM *y = BN_new(); 
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

int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits){
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *X = BN_new();
    BIGNUM *pie = BN_new();
    BIGNUM *sub = BN_new();
    BIGNUM *zero = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BN_zero(zero);
    BN_dec2bn(&one, "1");
    BN_dec2bn(&two, "2");
    BN_CTX *ctx = BN_CTX_new(); 
    
    BN_rand(p, nBits, 1, 1); 
    BN_rand(q, nBits, 1, 1);
    while(true){
        if(bn_miller_rabin_is_prime(p, 1)!=true)
            BN_rand(p, nBits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD); 
        else if(bn_miller_rabin_is_prime(q, 1)!=true)
            BN_rand(q, nBits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD);
        else break;
    }

    BN_dec2bn(&sub, "1");
    BN_mul(b11rsa->n, p, q, ctx);

    //pi(n)값 구하기
    BN_sub(p, p, sub);
    BN_sub(q, q, sub);
    BN_mul(pie, p, q, ctx);

    //e 값 구하기 (2<e<pie) 범위 내에 pie와 서로소인 e 값 구한다.
    BN_rand_range(b11rsa->e, pie);
    if(BN_is_zero(b11rsa->e)) 
        BN_add(b11rsa->e,b11rsa->e,two);
    if(BN_is_one(b11rsa->e)) 
        BN_add(b11rsa->e,b11rsa->e,one);
    X = XEuclid(X, b11rsa->e, pie);
    while(!BN_is_one(X)){
        BN_rand_range(b11rsa->e, pie);
        if(BN_is_zero(b11rsa->e)) 
            BN_add(b11rsa->e,b11rsa->e,two);
        if(BN_is_one(b11rsa->e)) 
            BN_add(b11rsa->e,b11rsa->e,one);
        X = XEuclid(X, b11rsa->e, pie);
    }

    //BN_dec2bn(&b11rsa->e, "65537");

    //d 값 구하기
    X = XEuclid(b11rsa->d, b11rsa->e, pie);
    if(BN_cmp(b11rsa->d, zero) < 0) BN_add(b11rsa->d, b11rsa->d, pie);
    

    return 1;   
}

//Modular Exponentiation (R2L)
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *a_copy = BN_new();
        BN_copy(a_copy, a);

        for(int i = BN_num_bits(e)-2; i >= 0; i--)
        {
                BN_mod_mul(a_copy, a_copy, a_copy, m, ctx); 
                if(BN_is_bit_set(e, i)) //e의 i번 째 비트가 설정되었을 때 동작
                        BN_mod_mul(a_copy, a_copy, a, m, ctx);
        }

        BN_copy(r, a_copy);
        BN_free(a_copy);
        if(ctx != NULL) BN_CTX_free(ctx);
        return 1;
}

/*
RSA 암호화 함수
입력 : 공개키를 포함한 b11rsa, 메시지 m
출력 : 암호문 c
*/
int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa){
    ExpMod(c,m,b11rsa->e,b11rsa->n);
    return 1;
}
/*
RSA 복호화 함수
입력 : 공개키를 포함한 b11rsa, 암호문 c
출력 : 평문 m
*/
int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa){
    ExpMod(m,c,b11rsa->d,b11rsa->n);
    return 1;
}
