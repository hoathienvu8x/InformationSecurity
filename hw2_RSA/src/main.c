#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "rsa.h"

int main() {
    mpz_t n, e, d;
    mpz_init(n);
    mpz_init(e);
    mpz_init(d);
    generate_key(1024, n, e, d);
    gmp_printf("密钥 n：%ZX\n", n);
    gmp_printf("公钥 e：%ZX\n", e);
    gmp_printf("私钥 d：%ZX\n", d);
    char * message = malloc(100);
    strcpy(message, "Hello, world!\n");
    printf("加密前明文：%s", message);
    rsa_encrypt(n, e, 1024/8, &message);
    printf("加密后密文：%s\n", message);
    rsa_decrype(n, d, 1024/8, &message);
    printf("解密后明文：%s", message);

    free(message);
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(d);
}