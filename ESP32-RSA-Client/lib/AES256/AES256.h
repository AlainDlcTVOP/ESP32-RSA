/**
 * @file AES256.h
 * @author Faroch Mehri (faroch.mehri@ya.se)
 * @brief A library based on https://github.com/kokke/tiny-AES-c.git to encrypt/decrypt data using AES-256
 * @version 0.1
 * @date 2020-07-18
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#ifndef AES256_H
#define AES256_H

#include <stdint.h>

#define AES_KEY_SIZE (32U)
#define AES_BLOCK_SIZE (15U)
#define AES_CIPHER_SIZE (16U)

/**
 * @brief Initialize the AES-256 key (32 bytes)
 * 
 * @param key The AES-256 key(32 bytes). If key is NULL, a random AES-256 key is generated.
 * @return const uint8_t* A pointer to a const which points to the current AES-256 key (32 bytes)
 */
const uint8_t *aes256_init_key(uint8_t key[AES_KEY_SIZE]);

/**
 * @brief This function is used to encrypt data usign AES-256
 * 
 * @param data The data which is supposed to be encrypted.
 * @param data_size Size of the data. It should be at most AES_BLOCK_SIZE bytes.
 * @param cipher The encrypted data, 16 bytes length.
 * @return bool true if the encryption is successful, otherwise false.
 */
bool aes256_encrypt(uint8_t *data, uint8_t data_size, uint8_t cipher[AES_CIPHER_SIZE]);

/**
 * @brief This function is used to decrypt a cipher which is encrypted usign AES-256
 * 
 * @param cipher The encrypted cipher, 16 bytes length.
 * @param data A buffer of at least AES_BLOCK_SIZE bytes for the decrypted data.
 * @return uint8_t Size of the decrypted data.
 */
uint8_t aes256_decrypt(uint8_t cipher[AES_CIPHER_SIZE], uint8_t data[AES_BLOCK_SIZE]);

#endif /* AES256_H */