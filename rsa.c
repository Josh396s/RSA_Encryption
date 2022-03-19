#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include "randstate.h"
#include "numtheory.h"
#include <gmp.h>

//Function that creates parts of a new RSA public key: two large primes p and q, their product n, and the public exponen te
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {
    mpz_t lam, lcm_t, lcm_b, eval, p1, q1, eholder;
    mpz_inits(lam, lcm_t, lcm_b, eval, p1, q1, eholder, NULL);
    uint64_t low, high, numbits, leftover;
    //Generating primes/Calculating n
    low = nbits / 4;
    high = (3 * nbits) / 4;
    numbits = (random() % (high - low + 1)) + low; //Random() using range [low, high]
    leftover = nbits - numbits; //Bits for q
    make_prime(p, numbits, iters); //Prime number P
    make_prime(q, leftover, iters); //Prime number Q
    mpz_mul(n, p, q); //n value
    //Calculating lambda(x)
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(lcm_t, p1, q1);
    mpz_abs(lcm_t, lcm_t); //Top of LCM
    gcd(lcm_b, p1, q1); //Bottom of LCM
    mpz_fdiv_q(lam, lcm_t, lcm_b); //Lambda(n)
    //Generating e
    while (mpz_cmp_ui(eval, 1) != 0) {
        mpz_urandomb(eholder, state, nbits);
        mpz_set(e, eholder);
        gcd(eval, eholder, lam);
    }
    mpz_clears(lam, lcm_t, lcm_b, eval, p1, q1, eholder, NULL);
}

//Function that writes public key to a file
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile, "%Zx\n", n);
    gmp_fprintf(pbfile, "%Zx\n", e);
    gmp_fprintf(pbfile, "%Zx\n", s);
    gmp_fprintf(pbfile, username);
}

//Function that reads public key from a file
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%Zx\n", n);
    gmp_fscanf(pbfile, "%Zx\n", e);
    gmp_fscanf(pbfile, "%Zx\n", s);
    gmp_fscanf(pbfile, "%s", username);
}

//Function that makes private key
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t p1, q1, lcm_t, lcm_b, lam;
    mpz_inits(p1, q1, lcm_t, lcm_b, lam, NULL);
    //Calculating lambda(x)
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(lcm_t, p1, q1);
    mpz_abs(lcm_t, lcm_t); //Top of LCM
    gcd(lcm_b, p1, q1); //Bottom of LCM
    mpz_fdiv_q(lam, lcm_t, lcm_b); //lambda(n)

    mod_inverse(d, e, lam); //Setting d to mod inverse of e mod lambda(n)
    mpz_clears(p1, q1, lcm_t, lcm_b, lam, NULL);
}

//Function that writes the private key to a file
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile, "%Zx\n", n);
    gmp_fprintf(pvfile, "%Zx\n", d);
}

//Function that reads the private keys from a file
void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile, "%Zx\n", n);
    gmp_fscanf(pvfile, "%Zx\n", d);
}

//Function that performs RSA ecnryption
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
}

//Function that encrypts a file
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    mpz_t val, result, m;
    mpz_inits(val, result, m, NULL);
    mpz_set(val, n);
    size_t k = (mpz_sizeinbase(val, 2) - 1) / 8; //(log2(n) - 1) / 8

    uint8_t *block = (uint8_t *) malloc(k * sizeof(uint8_t)); //Da block
    block[0] = 0xFF; //0th byte is 0xFF

    while (!feof(infile)) {
        size_t j = fread(block + 1, sizeof(uint8_t), k - 1, infile);
        if (j > 0) {
            mpz_import(m, j + 1, 1, sizeof(uint8_t), 1, 0, block); //Convert read bytes to mpz
            rsa_encrypt(result, m, e, n); //Encrypt the message
            gmp_fprintf(outfile, "%Zx\n", result);
        }
    }
    free(block);
    mpz_clears(val, result, m, NULL);
}

//Function that performs RSA decryption
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
}

//Function that decrypts the contents of infile
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    mpz_t val, result, c;
    mpz_inits(val, result, c, NULL);
    mpz_set(val, n);
    size_t k = (mpz_sizeinbase(val, 2) - 1) / 8; //(log2(n) - 1) / 8
    size_t j;

    uint8_t *block = (uint8_t *) malloc(k * sizeof(uint8_t)); //Da block
    block[0] = 0xFF;

    while (!feof(infile)) {
        if ((j = gmp_fscanf(infile, "%Zx\n", c))) {
            rsa_decrypt(result, c, d, n);
            mpz_export(block, &j, 1, sizeof(uint8_t), 1, 0, result);
            fwrite(block + 1, sizeof(uint8_t), j - 1, outfile);
        }
    }
    free(block);
    mpz_clears(val, result, c, NULL);
}

//Function that peforms RSA signing
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
}

//Check to see if the signature is correct or not
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t verify;
    mpz_init(verify);
    pow_mod(verify, s, e, n);
    if (mpz_cmp(m, verify) == 0) {
        mpz_clear(verify);
        return true;
    } else {
        mpz_clear(verify);
        return false;
    }
}
