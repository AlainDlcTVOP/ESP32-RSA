#include <WiFi.h>
#include <stdbool.h>
#include <Arduino.h>
#include <IPAddress.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <esp32-hal.h>
#include <client.h>
#include <AES256.h>
#include <RSA.h>
#include <SHA256.h>

#define SSID "comhemCDAF93"
#define PASSWORD "D0FDE93BD1"
/* #define SSID "YA-LOCAL"
#define PASSWORD "utbildning2020" */

static WiFiClient client;
static WiFiServer server(PORT);
static uint8_t tx_counter = 0U;

//#define SSID "comhemCDAF93"
//#define PASSWORD "D0FDE93BD1"

const uint8_t *auth_key;
uint8_t message[RSA_SIZE + RSA_SIZE + HASH_SIZE] = {};
uint8_t hash[HASH_SIZE] = {};
uint8_t save_message[BUFFER_SIZE];

static uint8_t public_key[RSA_SIZE] = {
    0xC3, 0xA5, 0x4E, 0x87, 0xAD, 0xC6, 0xA4, 0x02, 0x11, 0x0B, 0xF2, 0x75, 0xE3, 0xB6, 0x6D, 0xE6,
    0x55, 0xA0, 0x17, 0x60, 0x16, 0xC2, 0x12, 0x58, 0xA9, 0xC6, 0xF5, 0x91, 0xCD, 0xB7, 0xA7, 0xA9};
static uint8_t private_key[RSA_SIZE] = {
    0x56, 0x29, 0x30, 0xE2, 0x73, 0xD7, 0x6D, 0x57, 0x33, 0xA6, 0xAD, 0x4A, 0xD9, 0xD3, 0xF7, 0xA5,
    0x98, 0xF3, 0xFA, 0x07, 0x64, 0x7D, 0xE5, 0xE4, 0x4B, 0x13, 0x5C, 0x90, 0x38, 0xF4, 0x3B, 0x59};
static uint8_t public_key_client[RSA_SIZE] = {
    0xDB, 0x44, 0xDD, 0xA4, 0xB7, 0xAB, 0x9D, 0x86, 0x2B, 0xBD, 0xC1, 0xFD, 0x67, 0xC9, 0x0B, 0xAF,
    0x05, 0x76, 0x3E, 0x4E, 0xD3, 0xD1, 0xDF, 0x9B, 0x7A, 0x75, 0x6E, 0x4C, 0x5F, 0x63, 0x63, 0x75};

void print_data(const uint8_t *data, uint8_t size)
{
    for (uint8_t i = 0; i < size; i++)
    {
        Serial.printf("%02X ", data[i]);
    }
    Serial.println();
}

void setup()
{
    Serial.begin(9600);
    while (!Serial)
    {
        delay(100);
    }

    WiFi.begin(SSID, PASSWORD);

    while (WL_CONNECTED != WiFi.status())
    {
        delay(3000);
        WiFi.begin(SSID, PASSWORD);
        Serial.print(".");
    }
    Serial.print("\nIP Address: ");
    Serial.println(WiFi.localIP());
    pinMode(BUILTIN_LED, OUTPUT);
    server.begin();
}
void loop()
{
    WiFiClient client = server.available();

    if (client.connected() && client.available())
    {
        client.write(save_message, RSA_SIZE + RSA_SIZE + HASH_SIZE);
    }
}

void dekryypt_aes_key()
{ //step 1 :ta emot meddelande

    //step 2 :calculate hash for message1.
    //step 3 : recieve message1.
    //step 4: calculate hash for message1.
    //step 5: compare (calculated)hash for message1, with the hash
    //step 6: decrypt using client private key.
    //step 7: decrypt using server public key.
    uint8_t temp[RSA_SIZE];
    uint8_t temp1[RSA_BLOCK_SIZE];
    uint8_t temp2[RSA_SIZE - RSA_BLOCK_SIZE];
    uint8_t temp3[RSA_SIZE];
    uint8_t temp4[RSA_SIZE];
    uint8_t temp5[RSA_SIZE + RSA_SIZE];
    uint8_t hash[HASH_SIZE];

    // VÄND ALLTING för dekryptera
    auth_key = aes256_init_key(NULL);

    rsa_private_decrypt(save_message, public_key, private_key, temp);
    memcpy(temp1, temp, RSA_BLOCK_SIZE);
    memcpy(temp2, temp + RSA_BLOCK_SIZE, RSA_SIZE - RSA_BLOCK_SIZE);
    rsa_private_decrypt(temp1, public_key_client, private_key, temp);
    rsa_private_decrypt(temp2, public_key_client, private_key, temp4);
    memcpy(temp5, temp3, RSA_SIZE);
    memcpy(temp5 + RSA_SIZE, temp4, RSA_SIZE);

    sha256(temp5, RSA_SIZE + RSA_SIZE, hash);

    memcpy(save_message, temp5, RSA_SIZE + RSA_SIZE);
    memcpy(save_message + RSA_SIZE + RSA_SIZE, hash, HASH_SIZE);
}