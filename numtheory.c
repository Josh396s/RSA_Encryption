#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include "numtheory.h"
#include "randstate.h"
#include <gmp.h>

//Function that performs modular exponentiation
void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) { //Working
    mpz_t remainder, power, exp;
    mpz_inits(remainder, power, exp, NULL);
    mpz_set_ui(out, 1); //out = 1
    mpz_set(power, base); //power = base
    mpz_set(exp, exponent);
    while (mpz_cmp_ui(exp, 0) > 0) { //while (exp > 0)
        if (mpz_mod_ui(remainder, exp, 2) == 1) { //if(exponent % 2 == 0)
            mpz_mul(out, out, power);
            mpz_mod(out, out, modulus); //out = (out*power) % modulus
        }
        mpz_mul(power, power, power);
        mpz_mod(power, power, modulus); //power = (power*power) % modulus
        mpz_fdiv_q_ui(exp, exp, 2); //exponent /= 2
    }
    mpz_clears(remainder, power, exp, NULL);
}

//Function that checks to see if a given number is prime using Miller_Rabin primality test
bool is_prime(mpz_t n, uint64_t iters) { //Working
    mpz_t two, nval, s, scheck, max, n1, s1, a, i, r, y, j;
    mpz_inits(two, nval, s, scheck, max, n1, s1, a, i, r, y, j, NULL);
    mpz_set_ui(two, 2); //Two = 2
    mpz_set(nval, n);
    mpz_sub_ui(s, n, 1); //s = n-1
    mpz_sub_ui(n1, n, 1); //n1 = n-1
    mpz_sub_ui(s1, s, 1);

    if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0) { //if(n==2 || n==3)
        mpz_clears(two, nval, s, scheck, max, n1, s1, a, i, r, y, j, NULL);
        return true;
    }

    if ((mpz_cmp_ui(n, 2) < 0) || mpz_cmp_ui(n, 4) == 0) { //if(n<2 || n==4)
        mpz_clears(two, nval, s, scheck, max, n1, s1, a, i, r, y, j, NULL);
        return false;
    }

    while ((mpz_mod_ui(scheck, s, 2) == 0) && (mpz_cmp_ui(s, 0) > 0)) { //while(s % 2 == 0 && s > 0)
        mpz_fdiv_q_ui(s, s, 2); //s/=2
        mpz_add_ui(r, r, 1);
    }

    for (mpz_set_ui(i, 1); mpz_cmp_ui(i, iters) < 0; mpz_add_ui(i, i, 1)) { //for(i=1; i<iters; i++)
        mpz_sub_ui(r, n, 1); //r = n-1
        mpz_sub_ui(max, n, 2); //n-2
        mpz_urandomm(a, state, max); //a = rand[2, n-2]
        if (mpz_cmp_ui(a, 2) < 0) { //If a < 2
            mpz_add_ui(a, a, 2); //a += 2
        }
        pow_mod(y, a, r, nval); // y = pow_mod(result, a, r, n)
        if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, n1) != 0) { //if(y != 1 && y != n-1)
            mpz_set_ui(j, 1); //j = 1

            while (mpz_cmp(j, s1) <= 0 && mpz_cmp(y, n1) != 0) { //while(j <= s-1 && y != n-1)
                pow_mod(y, y, two, nval);
                if (mpz_cmp_ui(y, 1) == 0) { //if( y == 1)
                    mpz_clears(two, nval, s, scheck, max, n1, s1, a, i, r, y, j, NULL);
                    return false;
                }
                mpz_add_ui(j, j, 1); //j++
            }
            if (mpz_cmp(y, n1) != 0) { //if(y != n-1)
                mpz_clears(two, nval, s, scheck, max, n1, s1, a, i, r, y, j, NULL);
                return false;
            }
        }
    }
    mpz_clears(two, nval, s, scheck, max, n1, s1, a, i, r, y, j, NULL); //Clear all mpz inits
    return true;
}

//Function that generates a prime number of at least bits bits
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    mpz_t p_val, temp, i, one, min, result;
    mpz_inits(p_val, temp, i, one, min, result, NULL);

    mpz_set_ui(one, 1);
    mpz_mul_2exp(min, one, bits); //Min number for the prime

    while (is_prime(p, iters) != 1) { //while(is_prime(p, iters) != 1)
        mpz_urandomb(p, state, bits - 1); //p = random()
        mpz_add(result, p, min); //Add minimum value to ensure that p is greater than the bits
        mpz_set(p, result);
    }
    mpz_clears(p_val, temp, i, one, min, result, NULL); //Clear all mpz inits
}

//Function that returns the gcd of two numbers
void gcd(mpz_t d, mpz_t a, mpz_t b) {
    mpz_t temp, a_val, b_val;
    mpz_inits(temp, a_val, b_val, NULL);
    mpz_set(a_val, a);
    mpz_set(b_val, b);

    while (mpz_cmp_ui(b_val, 0) > 0) { //while( b > 0)
        mpz_mod(temp, a_val, b_val); // b = a % b
        mpz_set(a_val, b_val); // a = temp
        mpz_set(b_val, temp);
    }
    mpz_set(d, a_val); //d = a
    mpz_clears(temp, a_val, b_val, NULL);
}

//Function that computes inverse i of a modulo n
void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    mpz_t r, r1, t, t1, q, tempr, tempt, q1;
    mpz_inits(r, r1, t, t1, q, tempr, tempt, q1, NULL);

    mpz_set(r, n); // r = n
    mpz_set(r1, a); // r1 = a
    mpz_set_ui(t, 0); // t = 0
    mpz_set_ui(t1, 1); // t1 = 1

    while (mpz_cmp_ui(r1, 0) != 0) {
        mpz_fdiv_q(q, r, r1); //q = r / r1
        mpz_set(q1, q); //q1 = q
        mpz_set(tempr, r); //tempr = r
        mpz_set(r, r1); //r = r1
        mpz_mul(q, q, r1);
        mpz_sub(r1, tempr, q); //r1 = tempr - q * r1
        mpz_set(tempt, t); //tempt = t
        mpz_set(t, t1); //t = t1
        mpz_mul(q1, q1, t1);
        mpz_sub(t1, tempt, q1); //t1 = tempt - q * t1
    }
    if (mpz_cmp_ui(r, 1) > 0) { //if (r > 1)
        mpz_set_ui(i, 0); //i = 0
    }
    if (mpz_cmp_ui(t, 0) < 0) { //if (t < 0)
        mpz_add(t, t, n); //t += n
    }
    mpz_set(i, t); //i = t
    mpz_clears(r, r1, t, t1, q, tempr, tempt, q1, NULL);
}
