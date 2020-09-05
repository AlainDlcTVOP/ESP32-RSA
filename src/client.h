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

#endif /* CLIENT_H */
