#ifndef SERVER_H
#define SERVER_H
#include <RSA.h>
#include <SHA256.h>
#include <AES256.h>
#define BUFSIZE (3 * RSA_SIZE)
enum Request
{
    AUTH,
    CLOSE,
    TEMPERATURE,
    TURN_LED_ON,
    TURN_LED_OFF
};

enum Status
{
    OKAY,
    UNAUTH,
    EXPIRED,
    TIMEOUT,
    WAITING,
    HASH_ERROR,
    BAD_REQUEST,
    DISCONNECTED,
    UNKNOWN_ERROR
};

typedef struct
{
    uint8_t data[BUFSIZE];
    size_t length;
} response_t;

#endif /* SERVER_H */
