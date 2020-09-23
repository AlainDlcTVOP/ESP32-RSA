#include <RSA.h>
#include <WiFi.h>
#include <SHA256.h>
#include <AES256.h>
#include <Arduino.h>
#include <IPAddress.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
#include <server.h>
#include <esp32-hal.h>

#define SSID "YA-LOCAL"
#define PASSWORD "utbildning2020"

#define PORT 80
#define BUFSIZE (3 * RSA_SIZE)
#define SESSION_PERIOD (60000U)

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
    uint8_t length;
} response_t;

typedef struct
{
    uint8_t session_Id[SESSION_PERIOD] = {};
    uint32_t end_session;
} session_t;

static uint8_t client_public_key[RSA_SIZE] = {
    0xD1, 0x13, 0x2B, 0x14, 0x8E, 0xA4, 0x70, 0x89, 0xA0, 0x3E, 0x3B, 0x2E, 0x3F, 0xDD, 0xDC, 0xC0,
    0xBD, 0x88, 0x49, 0x2B, 0xFC, 0x04, 0x6C, 0xB9, 0x23, 0x5C, 0x1F, 0x5B, 0x68, 0x6F, 0x00, 0xDD,
    0xF0, 0x8A, 0x9A, 0x12, 0x7C, 0x64, 0x33, 0x8F, 0x6B, 0xF4, 0xC5, 0x62, 0x00, 0x68, 0x20, 0xDE,
    0xD3, 0xA2, 0xA2, 0xEA, 0xD6, 0x04, 0x9C, 0x15, 0xB9, 0x23, 0xC3, 0x8E, 0x02, 0xEC, 0x7E, 0x7B};
static uint8_t server_public_key[RSA_SIZE] = {
    0x92, 0xF4, 0x13, 0xDD, 0x91, 0xFE, 0x15, 0xD3, 0xCA, 0x3D, 0xD8, 0x65, 0x32, 0x8D, 0xC7, 0x64,
    0xA5, 0x7F, 0xF9, 0x4C, 0xE2, 0x9B, 0x03, 0x96, 0xF5, 0xB7, 0x80, 0x55, 0xDE, 0xB0, 0xEA, 0x58,
    0x97, 0x7F, 0x9F, 0x25, 0x8C, 0x45, 0x5A, 0xF4, 0x50, 0x21, 0xF8, 0x95, 0xCC, 0xB8, 0x53, 0xE4,
    0x8C, 0x43, 0xD0, 0x87, 0x08, 0x97, 0xF3, 0x31, 0x39, 0x50, 0x17, 0x5F, 0xE1, 0xCD, 0xC7, 0xD5};
static uint8_t server_private_key[RSA_SIZE] = {
    0x29, 0xD2, 0xC5, 0x84, 0x9D, 0xF4, 0x4E, 0x8A, 0x04, 0x59, 0x2D, 0xA9, 0x3F, 0x86, 0x12, 0x65,
    0x96, 0xA4, 0xA1, 0x73, 0x3C, 0x5B, 0x19, 0xDE, 0x70, 0xF8, 0x54, 0xD2, 0x1B, 0x9B, 0x06, 0x56,
    0xD7, 0x67, 0x93, 0x1A, 0x0B, 0x95, 0x06, 0xD1, 0xF2, 0x04, 0x64, 0xCB, 0x13, 0xDA, 0x9E, 0x25,
    0x18, 0xCA, 0x79, 0xAB, 0x29, 0xCF, 0xE4, 0x02, 0xBA, 0x3E, 0x3B, 0xDC, 0x53, 0x84, 0x43, 0x51};

static WiFiClient client;
static WiFiServer server(PORT);
static uint32_t session_id = 0U;
//void handler_request(request_t *request);
uint8_t message[RSA_BLOCK_SIZE] = {};

unsigned long startMillis; //some global variables available anywhere in the program
unsigned long currentMillis;
const unsigned long period = 60000; //the value is Sa number of milliseconds
bool time_controll();
static void send_response(response_t *res)
{
    sha256(res->data, res->length, res->data + res->length);
    res->length += HASH_SIZE;
    Serial.print("skickar data:");
    for (uint8_t i = 0; i < res->length; i++)
    {
        Serial.printf("%02X ", res->data[i]);
    }
    Serial.println("");

    client.write(res->data, res->length);
    client.flush();
}

void setup()
{
    Serial.begin(9600);
    delay(3000);

    while (WL_CONNECTED != WiFi.status())
    {
        WiFi.begin(SSID, PASSWORD);
        Serial.print(".");

        delay(2000);
    }
    currentMillis = millis();

    Serial.print("\nIP Address: ");
    Serial.println(WiFi.localIP());
    pinMode(LED_BUILTIN, OUTPUT);
    server.begin();
}

void loop()
{

    client = server.available();

    if (client && client.connected())
    {
        Serial.printf("client connect\n");
        // Wait on receiving data from the client
        while (!client.available())
        {
            delay(1);
        }

        // Read the received data
        startMillis = millis();
        Serial.printf("Start time is: %ul", startMillis);
        bool rsa = true;
        uint8_t buffer[BUFSIZE] = {};
        uint8_t length = client.read(buffer, BUFSIZE);

        response_t response = {};
        Serial.printf("Recive message\n");
        if ((length != 2 * RSA_SIZE + HASH_SIZE) && (length != AES_CIPHER_SIZE + HASH_SIZE))
        {
            response.length = 1U;
            response.data[0] = BAD_REQUEST;
        }
        else
        {
            length -= HASH_SIZE;
            uint8_t hash[HASH_SIZE] = {};
            sha256(buffer, length, hash);
            if (memcmp(hash, buffer + length, HASH_SIZE))
            {
                response.length = 1U;
                response.data[0] = HASH_ERROR;
            }
            else if (length == 2 * RSA_SIZE)
            {
                // Authentication (AUTH)
                uint8_t temp[RSA_SIZE] = {};
                uint8_t len = rsa_private_decrypt(buffer, server_public_key, server_private_key, temp);
                len += rsa_private_decrypt(buffer + RSA_SIZE, server_public_key, server_private_key, temp + len);
                if (len != RSA_SIZE)
                {
                    response.length = 1U;
                    response.data[0] = BAD_REQUEST;
                }
                else
                {
                    len = rsa_public_decrypt(temp, client_public_key, temp);
                    if (len != AES_KEY_SIZE + 1)
                    {
                        Serial.println("Bad request");
                        response.length = 1U;
                        response.data[0] = BAD_REQUEST;
                    }
                    else if (temp[0] != AUTH)
                    {
                        Serial.println("Also Bad request");
                        response.length = 1U;
                        response.data[0] = BAD_REQUEST;
                    }
                    else
                    {
                        Serial.println("Good request request");
                        response.length = 1U;
                        response.data[0] = OKAY;
                        aes256_init_key(temp + 1);
                        randomSeed(micros());
                        session_id = random(1U, 0xFFFFFFF);

                        Serial.println("");
                        Serial.printf("Session id for authentication is: %u\n", session_id);
                        for (uint8_t i = 0; i < sizeof(session_id); i++)
                        { //Bit shift session id into response data, with lsb for index 1.
                            response.data[response.length] = (uint8_t)(session_id >> (i * 8));
                            Serial.printf("%02X ", response.data[response.length]);
                            response.length++;
                        }
                        Serial.println("done");
                    }
                }
            }
            else
            {
                // AES

                rsa = false;

                if (aes256_decrypt(buffer, buffer) != 1U + sizeof(session_id))
                {
                    Serial.println("more bad requests");
                    response.length = 1U;
                    response.data[0] = BAD_REQUEST;
                }
                else
                {
                    Serial.println("Vamos!");

                    uint32_t reciveSessionId = 0;
                    for (uint8_t i = 1; i < 5; i++)
                    {
                        reciveSessionId |= (buffer[i] << ((i - 1) * 8));
                    }
                    if ((session_id) != reciveSessionId)
                    {
                        Serial.printf("session id %u reciveid = %u\n", session_id, reciveSessionId);
                        response.length = 1U;
                        response.data[0] = UNAUTH;
                        Serial.println("error in session id");
                    }

                    if (buffer[0] == TEMPERATURE)
                    {
                        Serial.println("Oh its temperature time");
                        char temptemprature[4] = {};

                        response.data[0] = TEMPERATURE;
                        response.length = 1U;
                        for (uint8_t i = 1; i < 5; i++)
                        { //Bit shift session id into response data, with MSB for index 1.
                            response.data[response.length] = (uint8_t)(session_id >> ((i - 1) * 8));
                            Serial.printf("%02X ", response.data[response.length]);
                            response.length++;
                        }

                        dtostrf(temperatureRead(), 4, 1, temptemprature);
                        Serial.printf("temperaturen vi skickar: %.2f\n", temperatureRead());
                        memcpy(response.data + 5, temptemprature, sizeof(temptemprature));
                        response.length += 4;
                    }
                    if (buffer[0] == TURN_LED_ON)
                    {
                        response.length = 1U;
                        for (uint8_t i = 1; i < 5; i++)
                        { //Bit shift session id into response data, with MSB for index 1.
                            response.data[response.length] = (uint8_t)(session_id >> ((i - 1) * 8));
                            Serial.printf("%02X ", response.data[response.length]);
                            response.length++;
                        }
                        digitalWrite(LED_BUILTIN, 1);
                        Serial.println("Turn led on please");
                        response.data[0] = TURN_LED_ON;
                    }
                    if (buffer[0] == TURN_LED_OFF)
                    {
                        response.length = 1U;
                        for (uint8_t i = 1; i < 5; i++)
                        { //Bit shift session id into response data, with MSB for index 1.
                            response.data[response.length] = (uint8_t)(session_id >> ((i - 1) * 8));
                            Serial.printf("%02X ", response.data[response.length]);
                            response.length++;
                        }
                        Serial.println("Turn led off please");
                        digitalWrite(LED_BUILTIN, 0);
                        response.data[0] = TURN_LED_OFF;
                    }
                    if (buffer[0] == CLOSE)
                    {
                        response.length = 1U;
                        for (uint8_t i = 1; i < 5; i++)
                        { //Bit shift session id into response data, with MSB for index 1.
                            response.data[response.length] = (uint8_t)(session_id >> ((i - 1) * 8));
                            Serial.printf("%02X ", response.data[response.length]);
                            response.length++;
                        }
                        Serial.println("Close that connection for me good sir.");
                        response.data[0] = CLOSE;
                    }
                }
            }
        }

        if (rsa)
        {
            for (uint8_t i = 0; i < response.length; i++)
            {
                Serial.printf("%02X ", response.data[i]);
            }
            Serial.println("done");
            uint8_t temp[RSA_SIZE] = {};
            rsa_private_encrypt(response.data, response.length, server_public_key, server_private_key, temp);
            rsa_public_encrypt(temp, RSA_BLOCK_SIZE, client_public_key, response.data);
            response.length = RSA_SIZE;
            rsa_public_encrypt(temp + RSA_BLOCK_SIZE, RSA_SIZE - RSA_BLOCK_SIZE, client_public_key, response.data + response.length);
            response.length += RSA_SIZE;
        }
        else
        {
            aes256_encrypt(response.data, response.length, response.data);
            response.length = AES_CIPHER_SIZE;
        }

        send_response(&response);
    }
    time_controll();
} // This function is handling the clients request
bool time_controll()
{
    currentMillis = millis();                  //get the current "time" (actually the number of milliseconds since the program started)
    if (currentMillis - startMillis >= period) //test whether the period has elapsed
    {

        Serial.setTimeout(period);
        Serial.println("close the connection");
        startMillis = currentMillis;

        response_t response = {};
        session_id = 0;
        response.data[0] = CLOSE;
        response.length = 1U;
        for (uint8_t i = 1; i < 5; i++)
        { //Bit shift session id into response data, with MSB for index 1.
            response.data[response.length] = (uint8_t)(session_id >> ((i - 1) * 8));
            Serial.printf("%02X ", response.data[response.length]);
            response.length++;
        }
        send_response(&response);
    }
    return true;
}