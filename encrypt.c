#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"
#include <gmp.h>

void usage();

int main(int argc, char *argv[]) {
    int opt = 0;
    char user_name;
    char *username = &user_name;
    char *in_file;
    char *out_file;
    char *pub_file;
    FILE *infile = stdin;
    FILE *outfile = stdout;
    FILE *pbfile;

    mpz_t p, q, user, n, e, d, sign;
    mpz_inits(p, q, user, n, e, d, sign, NULL);

    bool verbose = false;
    bool inf = false;
    bool outf = false;
    bool public = false;

    while ((opt = getopt(argc, argv, "i:o:n:vh")) != -1) {
        switch (opt) {
        case 'i':
            in_file = optarg;
            inf = true;
            break;
        case 'o':
            out_file = optarg;
            outf = true;
            break;
        case 'n':
            pub_file = optarg;
        public
            = true;
            break;
        case 'v': verbose = true; break;
        case 'h': usage(); return 1;
        } //END switch
    } //END getopt()
    if (inf == true) { //If user entered an input file, open it. Else, read from stdin
        infile = fopen(in_file, "r");
        if (infile == NULL) { //Checking to see if input file opens/exists
            fprintf(stderr, "File does not exist\n");
            return 1;
        }
    }
    if (outf == true) { //If user entered an output file, open it. Else, print to stdout
        outfile = fopen(out_file, "w");
    }
    if (public == true) { //If user entered a public key file, open it. Else, open "rsa.pub"
        pbfile = fopen(pub_file, "r");
        if (pbfile == NULL) { //Checking to see if public key file opens/exists
            fprintf(stderr, "File does not exist\n");
            return 1;
        }
    } else {
        pbfile = fopen("rsa.pub", "r");
        if (pbfile == NULL) { //Checking to see if public key file opens/exists
            fprintf(stderr, "File does not exist\n");
            return 1;
        }
    }

    rsa_read_pub(n, e, sign, username, pbfile); //Read public key file

    if (verbose == true) { //Verbose enabled
        size_t sb = mpz_sizeinbase(sign, 2);
        size_t nb = mpz_sizeinbase(n, 2);
        size_t eb = mpz_sizeinbase(e, 2);

        printf("\nuser = %s \n", username);
        gmp_printf("s (%lu bits) = %Zd\n", sb, sign);
        gmp_printf("n (%lu bits) = %Zd\n", nb, n);
        gmp_printf("e (%lu bits) = %Zd\n", eb, e);
    }

    mpz_set_str(user, username, 62);

    if (rsa_verify(user, sign, e, n) == false) { //Verify the signature
        fprintf(stderr, "Signature is not verified!\n");
        return 1;
    }

    rsa_encrypt_file(infile, outfile, n, e); //Encrypt the file

    fclose(infile);
    fclose(outfile);
    fclose(pbfile);
    mpz_clears(n, e, sign, user, NULL);
    return 0;
}

void usage(void) {
    printf("SYNOPSIS\n"
           "        Encrypts data using RSA encryption. \n"
           "    Encrypted data is decrypted by the decrypt program. \n"
           "\n"
           "USAGE\n"
           "\n"
           "       ./encrypt [OPTIONS] \n"
           "OPTIONS\n"
           "       -h              Display program help and usage.\n"
           "       -v              Display verbose program output.\n"
           "       -i infile       Input file of data to encrypt (default: stdin).\n"
           "       -o outfile      Output file for encrypted data (default: stdout).\n"
           "       -n pbfile       Public key file (default: rsa.pub).\n");
}
