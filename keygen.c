#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"
#include <gmp.h>

void usage();

int main(int argc, char *argv[]) {
    int opt = 0;
    char *pub_file;
    char *priv_file;
    FILE *pbfile;
    FILE *pvfile;
    mpz_t p, q, n, e, d, sign, user;
    mpz_inits(p, q, n, e, d, sign, user, NULL);

    bool verbose = false;
    bool public = false;
    bool private = false;
    uint64_t seed = time(NULL);
    uint64_t n_bits = 256;
    uint64_t iters = 50;

    while ((opt = getopt(argc, argv, "b:i:n:d:s:vh")) != -1) {
        switch (opt) {
        case 'b': n_bits = atoi(optarg); break;
        case 'i': iters = atoi(optarg); break;
        case 'n':
            pub_file = optarg;
        public
            = true;
            break;
        case 'd':
            priv_file = optarg;
        private
            = true;
            break;
        case 's': seed = atoi(optarg); break;
        case 'v': verbose = true; break;
        case 'h': usage(); return 1;
        } //END switch
    } //END getopt()
    if (public == true) { //If user entered a public key file, open it. Else, Open default
        pbfile = fopen(pub_file, "w");
    } else {
        pbfile = fopen("rsa.pub", "w"); //Open public key file
    }
    if (pbfile == NULL) { //Checking to see if public key file opens/exists
        fprintf(stderr, "File does not exist\n");
        return 1;
    }
    if (private == true) { //If user entered a private key file, open it. Else, Open default
        pvfile = fopen(priv_file, "w");
    } else {
        pvfile = fopen("rsa.priv", "w"); //Open private key file
    }
    if (pvfile == NULL) { //Checking to see if private key file opens/exists
        fprintf(stderr, "File does not exst\n");
        return 1;
    }

    mode_t mode = 0600;
    int file = fileno(pvfile);
    fchmod(file, mode); //Private key file permission
    randstate_init(seed); //Initiliaze the random state
    rsa_make_pub(p, q, n, e, n_bits, iters); //Make public key
    rsa_make_priv(d, e, p, q); //Make private key

    char *username = getenv("USER"); //Get current user's namei
    mpz_set_str(user, username, 62); //Convert username to mpz_t
    rsa_sign(sign, user, d, n); //Sign the username

    rsa_write_pub(n, e, sign, username, pbfile); //Write public key to public key file
    rsa_write_priv(n, d, pvfile); //Write private key to private key file

    if (verbose == true) {
        size_t sb = mpz_sizeinbase(sign, 2);
        size_t pb = mpz_sizeinbase(p, 2);
        size_t qb = mpz_sizeinbase(q, 2);
        size_t nb = mpz_sizeinbase(n, 2);
        size_t eb = mpz_sizeinbase(e, 2);
        size_t db = mpz_sizeinbase(d, 2);

        printf("\nuser = %s\n", username);
        gmp_printf("s (%lu bits) = %Zd\n", sb, sign);
        gmp_printf("p (%lu bits) = %Zd\n", pb, p);
        gmp_printf("q (%lu bits) = %Zd\n", qb, q);
        gmp_printf("n (%lu bits) = %Zd\n", nb, n);
        gmp_printf("e (%lu bits) = %Zd\n", eb, e);
        gmp_printf("d (%lu bits) = %Zd\n", db, d);
    }
    fclose(pbfile);
    fclose(pvfile);
    randstate_clear();
    mpz_clears(p, q, n, e, d, sign, user, NULL);
    return 0;
}

void usage(void) {
    printf("SYNOPSIS\n"
           "       Generates an RSA public/private key pair. \n"
           "\n"
           "USAGE\n"
           "\n"
           "       ./keygen [OPTIONS] \n"
           "OPTIONS\n"
           "       -h              Display program help and usage.\n"
           "       -v              Display verbose program output.\n"
           "       -b bits:        Minimum bits needed for public key n (default: 256).\n"
           "       -i iterations   Miller-Rabin iterations for testing primes (default: 50).\n"
           "       -n pbfile       Public key file (default: rsa.pub).\n"
           "       -d pvfile       Private key file (default: rsa.priv).\n"
           "       -s seed         Random seed for testing.\n");
}
