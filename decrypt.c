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
    char *in_file;
    char *out_file;
    char *priv_file;
    FILE *infile = stdin;
    FILE *outfile = stdout;
    FILE *pvfile;

    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    bool verbose = false;
    bool inf = false;
    bool outf = false;
    bool private = false;

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
            priv_file = optarg;
        private
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
        if (outfile == NULL) { //Checking to see if output file opens/exists
            fprintf(stderr, "File does not exist\n");
            return 1;
        }
    }
    if (private == true) { //If user entered a private key file, open it. Else, open "rsa.pub"
        pvfile = fopen(priv_file, "r");
        if (pvfile == NULL) { //Checking to see if private key file opens/exists
            fprintf(stderr, "File does not exist\n");
            return 1;
        }
    } else {
        pvfile = fopen("rsa.priv", "r");
        if (pvfile == NULL) { //Checking to see if private key file opens/exists
            fprintf(stderr, "File does not exist\n");
            return 1;
        }
    }

    rsa_read_priv(n, d, pvfile); //Read private key file

    if (verbose == true) { //Verbose enabled
        size_t nb = mpz_sizeinbase(n, 2);
        size_t db = mpz_sizeinbase(d, 2);
        gmp_printf("n (%lu bits) = %Zd\n", nb, n);
        gmp_printf("e (%lu bits) = %Zd\n", db, d);
    }

    rsa_decrypt_file(infile, outfile, n, d); //Decrypt the file

    fclose(infile);
    fclose(outfile);
    fclose(pvfile);
    mpz_clears(n, e, d, NULL);
    return 0;
}

void usage(void) {
    printf("SYNOPSIS\n"
           "       Decrypts data using RSA decryption. \n"
           "    Encrypted data is encrypted by the encrypt program. \n"
           "\n"
           "USAGE\n"
           "\n"
           "       ./decrypt [OPTIONS] \n"
           "OPTIONS\n"
           "       -h              Display program help and usage.\n"
           "       -v              Display verbose program output.\n"
           "       -i infile       Input file of data to decrypt (default: stdin).\n"
           "       -o outfile      Output file for decrypted data (default: stdout).\n"
           "       -n pvfile       Private key file (default: rsa.priv).\n");
}
