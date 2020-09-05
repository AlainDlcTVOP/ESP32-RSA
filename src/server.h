#ifndef SERVER_H
#define SERVER_H

#define PORT (12345U)
#define BUFFER_SIZE (256U)

#define SESSION_PERIOD (60000U)
#define AUTH_MES_SIZE (84U)
#define REQ_MES_SIZE (36U)
#define SESSION_ID (3U)
#include <SHA256.h>
#include <RSA.h>
#include <AES256.h>
enum sending_types
{
    LED_ON = 1,
    LED_OFF,
    LED_STATUS,
    TEMPERATURE,
    END_SESSION
};

enum receiving_types
{
    REQUEST_DONE = 0,
    ERROR
};

typedef struct
{
    uint8_t the_secret[HASH_SIZE] = {};
    uint8_t session_Id[SESSION_ID] = {};
    uint8_t request[AES_BLOCK_SIZE - SESSION_ID] = {};
} message_info;

typedef struct
{
    uint8_t session_Id[SESSION_ID] = {};
    uint32_t end_session;
} session_t;

message_info message_decrypting(uint8_t mes_len, uint8_t *message);

#endif /* SERVER_H */
