#ifndef CLIENT_H
#define CLIENT_H

#include <WiFi.h>
#include <Arduino.h>
#include <esp32-hal.h>
#include <IPAddress.h>
#include <WiFiClient.h>
#include <RSA.h>
#include <SHA256.h>
#include <AES256.h>

#define SERVER "192.168.1.135"

#define PORT (12345U)

#define BUFFER_SIZE (128U)
#define SESSION_ID_SIZE (3U)
#define SESSION_PERIOD (60000U)
#define AUTH_MES_SIZE (84U)
#define RSA_MES_SIZE (52U)
#define REQUEST_MES_SIZE (36U)

enum sending_types
{
    LED_ON = 1,
    LED_OFF,
    LED_STATUS,
    TEMPERATURE,
    END_SESSION,
};

enum receiving_types
{
    REQUEST_DONE = 0,
    ERROR
};

typedef struct
{
    uint8_t session_Id[SESSION_ID_SIZE] = {};
    uint8_t message[AES_BLOCK_SIZE - 1];
    receiving_types type;
} response_info;

/**
 * @brief This function is used to print data in hex
 * @param data which is suppose to be print in Hex
 * @param size  size of the data
 */
void print_data(const uint8_t *data, uint8_t size);

/**
 * @brief  This function is used to display the menu choice of the service
 * @param authorized - it's boolean which is the authorization status 
 * @return char - The character which indicates the choice 
 */
char services_menu(bool authorized);

/**
 * @brief Received buffer is decrypted by AES/RSA based on the message length
 *  and stored the message details in the struct response_info
 * @param old_decrypted_details - struct response_info 
 * @param mes_len length of the received message from client
 * @param message The received  buffer from server
 * @return  response_info which holds the session id , server message and receiving types(enum)
 */
response_info message_parsing(response_info old_decrypted_details, uint8_t mes_len, uint8_t *message);

/**
 * @brief This function is used to check the received hash and hash calculated from encrypted data are same.
 * @param mes_len length of the received buffer from client
 * @param the_whole_message The received buffer
 * @return boolean value
 */
bool check_hash(uint8_t mes_len, uint8_t *the_whole_message);

/**
 * @brief This function is used to build the request to server using session id and request
 * @param session_id The id for the session
 * @param request - sending_types(enum)
 * @param buffer  which will hold the encrypted message and hash.
 */
void build_request(const uint8_t *session_id, sending_types request, char *buffer);

/**
 * @brief This function is used for authentication before any data send
 * @param buffer which will hold the message (signed by client private key and encrypted by server public key)
 * and hash of the message.
 */
void authorization(uint8_t *buffer);

/**
 * @brief This function is used to check the message length of the received buffer from server
 * @param mes which is holding the received buffer.
 * @return uint8_t length of the received buffer.
 */
uint8_t check_mes_len(uint8_t *mes);

#endif /* CLIENT_H */
