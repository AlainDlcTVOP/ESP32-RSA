/**
 * @file RSA.h
 * @author Faroch Mehri (faroch.mehri@ya.se)
 * @brief A library to encrypt, decrypt, sign and verify messages
 * @version 0.1
 * @date 2020-07-13
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#ifndef RSA_H
#define RSA_H

#include <stdint.h>

#define RSA_SIZE (64U)
#define RSA_BLOCK_SIZE (RSA_SIZE - 11U)

/**
 * @brief This function is used to generate a pair of RSA keys
 * 
 * @param public_key A buffer for the public key. Size of this buffer should be RSA_SIZE.
 * @param private_key A buffer for the private key. Size of this buffer should be RSA_SIZE.
 * @return true If the keys is generated successfully.
 * @return false If the keys generation is failed.
 */
bool rsa_generate_keys(uint8_t *public_key, uint8_t *private_key);

/**
 * @brief This function is used to encrypt a buffer of data using an RSA public key.
 * 
 * @param data A pointer to the data buffer.
 * @param data_size Size of the data in bytes. It should be at most RSA_BLOCK_SIZE.
 * @param public_key The public key used to encrypt the data.
 * @param cipher The encrypted data.
 * @return true If encryption is successful.
 * @return false If encryption is failed.
 */
bool rsa_public_encrypt(uint8_t *data, uint8_t data_size, uint8_t *public_key, uint8_t cipher[RSA_SIZE]);

/**
 * @brief This function is used to decrypt a cipher by an RSA private key.
 * 
 * @param cipher The encrypted data.
 * @param public_key The public key.
 * @param private_key The private key.
 * @param data A buffer for the decrypted data. Size of the buffer should be at least RSA_BLOCK_SIZE.
 * @return uint8_t Size of the decrypted data in bytes.
 */
uint8_t rsa_private_decrypt(uint8_t cipher[RSA_SIZE], uint8_t *public_key, uint8_t *private_key, uint8_t *data);

/**
 * @brief This function is used to encrypt a buffer of data using an RSA private key.
 * 
 * @param data A pointer to the data buffer.
 * @param data_size Size of the data. data_size should be at most RSA_BLOCK_SIZE.
 * @param public_key The public key.
 * @param private_key The private key.
 * @param cipher The encrypted data.
 * @return true If encryption is successful.
 * @return false If encryption is failed.
 */
bool rsa_private_encrypt(uint8_t *data, uint8_t data_size, uint8_t *public_key, uint8_t *private_key, uint8_t cipher[RSA_SIZE]);

/**
 * @brief This function is used to decrypt a cipher an RSA public key.
 * 
 * @param cipher The encrypted data.
 * @param public_key The public key.
 * @param data A buffer for the decrypted data. Size of the buffer should be at least RSA_BLOCK_SIZE.
 * @return uint8_t Size of the decrypted data in bytes.
 */
uint8_t rsa_public_decrypt(uint8_t cipher[RSA_SIZE], uint8_t *public_key, uint8_t *data);

#endif /* RSA_H */
