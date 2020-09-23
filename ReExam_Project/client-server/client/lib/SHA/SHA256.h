/**
 * @file SHA256.h
 * @author Faroch Mehri (faroch.mehri@ya.se)
 * @brief A library based on https://github.com/amosnier/sha-2 to hash messages using SHA-256
 * @version 0.1
 * @date 2020-07-17
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define HASH_SIZE (32U)

/**
 * @brief This function calculates the hash value of data using SHA-256
 * 
 * @param data A pointer to the data
 * @param data_size Size of the data in bytes
 * @param hash The array of the hash. The size of this array should be 32
 */
void sha256(uint8_t *data, uint32_t data_size, uint8_t hash[HASH_SIZE]);

#endif /* SHA256_H */
