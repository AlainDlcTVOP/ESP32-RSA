/**
 * @file RSA.cpp
 * @author Faroch Mehri (faroch.mehri@ya.se)
 * @brief A library to encrypt, decrypt, sign and verify messages
 * @version 0.1
 * @date 2020-07-13
 *
 * @copyright Copyright (c) 2020
 *
 */

#include <RSA.h>
#include <bignum.h>
#include <Arduino.h>

#if (RSA_SIZE % 2) || (RSA_SIZE < 16) || (RSA_SIZE > 256)
#error RSA_SIZE should be an even number between 16 and 256.
#elif (RSA_BLOCK_SIZE != (RSA_SIZE - 11U))
#error The value of RSA_BLOCK_SIZE is not valid.
#endif

static uint8_t exponent[] ={ 0x01, 0x00, 0x01 };

static int rnd_func(void *param)
{
    ((void *)param);
    return (int)random(0xFFFF);
}

static uint8_t unpad_data(uint8_t *block, uint8_t *output)
{
    uint8_t length = 0;
    if (block[0] == 0x00)
    {
        uint8_t plen = 1;
        while ((plen < RSA_SIZE) && (block[plen] != 0x00))
        {
            plen++;
        }

        if (block[plen] == 0x00)
        {
            plen++;
        }

        if (plen < RSA_SIZE)
        {
            length = RSA_SIZE - plen;
        }
    }

    if (length)
    {
        memcpy(output, block + RSA_SIZE - length, length);
    }

    return length;
}

static void pad_data(uint8_t *input, uint8_t input_length, uint8_t *output)
{
    // 0x00 0xRR ... 0xRR 0x00 ...

    uint8_t plen = RSA_SIZE - input_length;

    output[0] = 0x00;
    randomSeed(micros());
    for (uint8_t i = 1; i < plen; i++)
    {
        output[i] = 1 + random(0xFE);
    }
    output[plen - 1] = 0x00;

    memcpy(output + plen, input, input_length);
}

bool rsa_generate_keys(uint8_t *public_key, uint8_t *private_key)
{
    bool status = false;

    if ((public_key == NULL) || (private_key == NULL))
    {
        return status;
    }

    uint16_t nbits = RSA_SIZE * 8;
    mpi P, Q, DP, DQ, QP, E, N, D, P1, Q1, H, G;
    mpi_init(&P, &Q, &DP, &DQ, &QP, &E, &N, &D, &P1, &Q1, &H, &G, NULL);

    if (!mpi_read_binary(&E, exponent, sizeof(exponent)))
    {
        status = true;

        do // Find primes P and Q with Q < P so that: GCD( E, (P-1)*(Q-1) ) == 1
        {
            if (mpi_gen_prime(&P, (nbits + 1) >> 1, 0, rnd_func, NULL) || mpi_gen_prime(&Q, (nbits + 1) >> 1, 0, rnd_func, NULL))
            {
                status = false;
                break;
            }

            if (mpi_cmp_mpi(&P, &Q) < 0)
            {
                mpi_swap(&P, &Q);
            }

            if (mpi_cmp_mpi(&P, &Q) == 0)
            {
                continue;
            }

            if (mpi_mul_mpi(&N, &P, &Q))
            {
                status = false;
                break;
            }

            if (mpi_msb(&N) != nbits)
            {
                continue;
            }

            if (mpi_sub_int(&P1, &P, 1) || mpi_sub_int(&Q1, &Q, 1) || mpi_mul_mpi(&H, &P1, &Q1) || mpi_gcd(&G, &E, &H))
            {
                status = false;
                break;
            }

        } while (mpi_cmp_int(&G, 1));

        /*
        * D  = E^-1 mod ((P-1)*(Q-1))
        * DP = D mod (P - 1)
        * DQ = D mod (Q - 1)
        * QP = Q^-1 mod P
        */
        if (status && (mpi_inv_mod(&D, &E, &H) || mpi_mod_mpi(&DP, &D, &P1) || mpi_mod_mpi(&DQ, &D, &Q1) || mpi_inv_mod(&QP, &Q, &P)))
        {
            status = false;
        }

        if (status && (mpi_write_binary(&N, public_key, RSA_SIZE) || mpi_write_binary(&D, private_key, RSA_SIZE)))
        {
            status = false;
        }
    }

    mpi_free(&P, &Q, &DP, &DQ, &QP, &E, &N, &D, &P1, &Q1, &H, &G, NULL);

    return status;
}

bool rsa_public_encrypt(uint8_t *data, uint8_t data_size, uint8_t *public_key, uint8_t *cipher)
{
    bool status = false;

    if ((data_size == 0) || (data_size > RSA_BLOCK_SIZE))
    {
        return status;
    }

    if ((data == NULL) || (public_key == NULL) || (cipher == NULL))
    {
        return status;
    }

    mpi M, E, N, X;
    mpi_init(&M, &E, &N, &X, NULL);

    // Pad Data
    uint8_t buffer[RSA_SIZE];
    pad_data(data, data_size, buffer);

    // Message
    if (!mpi_read_binary(&M, buffer, RSA_SIZE))
    {
        // Public Exponent
        if (!mpi_read_binary(&E, exponent, sizeof(exponent)))
        {
            // Public Key
            if (!mpi_read_binary(&N, public_key, RSA_SIZE))
            {
                // X = M^E mod N
                if (!mpi_exp_mod(&X, &M, &E, &N, NULL))
                {
                    // Export result to a binary buffer
                    if (!mpi_write_binary(&X, cipher, RSA_SIZE))
                    {
                        status = true;
                    }
                }
            }
        }
    }

    mpi_free(&M, &E, &N, &X, NULL);

    return status;
}

uint8_t rsa_private_decrypt(uint8_t *cipher, uint8_t *public_key, uint8_t *private_key, uint8_t *data)
{
    uint8_t length = 0;

    if ((cipher == NULL) || (public_key == NULL) || (private_key == NULL) || (data == NULL))
    {
        return length;
    }

    mpi M, D, N, X;
    mpi_init(&M, &D, &N, &X, NULL);

    // Cipher
    if (!mpi_read_binary(&M, cipher, RSA_SIZE))
    {
        // Public Key
        if (!mpi_read_binary(&N, public_key, RSA_SIZE))
        {
            // Private Key
            if (!mpi_read_binary(&D, private_key, RSA_SIZE))
            {
                // X = M^D mod N
                if (!mpi_exp_mod(&X, &M, &D, &N, NULL))
                {
                    uint8_t buffer[RSA_SIZE] ={};

                    // Export result to a binary buffer
                    if (!mpi_write_binary(&X, buffer, RSA_SIZE))
                    {
                        length = unpad_data(buffer, data);
                    }
                }
            }
        }
    }

    mpi_free(&M, &D, &N, &X, NULL);

    return length;
}

bool rsa_private_encrypt(uint8_t *data, uint8_t data_size, uint8_t *public_key, uint8_t *private_key, uint8_t *cipher)
{
    bool status = false;

    if ((data_size == 0) || (data_size > RSA_BLOCK_SIZE) || (data == NULL) || (public_key == NULL) || (private_key == NULL) || (cipher == NULL))
    {
        return status;
    }

    mpi M, N, D, X;
    mpi_init(&M, &N, &D, &X, NULL);

    // Pad Data
    uint8_t buffer[RSA_SIZE];
    pad_data(data, data_size, buffer);

    // Message
    if (!mpi_read_binary(&M, buffer, RSA_SIZE))
    {
        // Public Key
        if (!mpi_read_binary(&N, public_key, RSA_SIZE))
        {
            // Private Key
            if (!mpi_read_binary(&D, private_key, RSA_SIZE))
            {
                // X = M^D mod N
                if (!mpi_exp_mod(&X, &M, &D, &N, NULL))
                {
                    // Export result to a binary buffer
                    if (!mpi_write_binary(&X, cipher, RSA_SIZE))
                    {
                        status = true;
                    }
                }
            }
        }
    }

    mpi_free(&M, &N, &D, &X, NULL);

    return status;
}

uint8_t rsa_public_decrypt(uint8_t *cipher, uint8_t *public_key, uint8_t *data)
{
    uint8_t length = 0;
    if ((cipher == NULL) || (public_key == NULL) || (data == NULL))
    {
        return length;
    }

    mpi M, E, N, X;
    mpi_init(&M, &E, &N, &X, NULL);

    // Cipher
    if (!mpi_read_binary(&M, cipher, RSA_SIZE))
    {
        // Public Exponent
        if (!mpi_read_binary(&E, exponent, sizeof(exponent)))
        {
            // Public Key
            if (!mpi_read_binary(&N, public_key, RSA_SIZE))
            {
                // X = M^E mod N
                if (!mpi_exp_mod(&X, &M, &E, &N, NULL))
                {
                    uint8_t buffer[RSA_SIZE] ={};

                    // Export result to a binary buffer
                    if (!mpi_write_binary(&X, buffer, RSA_SIZE))
                    {
                        length = unpad_data(buffer, data);
                    }
                }
            }
        }
    }

    mpi_free(&M, &E, &N, &X, NULL);

    return length;
}
