#include <RSA.h>
#include <Arduino.h>

static uint8_t client_public_key[RSA_SIZE] = {};
static uint8_t client_private_key[RSA_SIZE] = {};

static void error(const char *msg)
{
    Serial.println(msg);
    while (1)
    {
        delay(1000);
    }
}

static void print_data(const uint8_t *data, uint8_t size)
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
    delay(2000);
}

void loop()
{
    if (!rsa_generate_keys(client_public_key, client_private_key))
    {
        error("Failed to generate the RSA keys!");
    }

    bool status = false;
    uint8_t buffer[RSA_SIZE] = {};
    uint8_t message[RSA_BLOCK_SIZE] = {};

    for (uint8_t i = 0; i < sizeof(message); i++)
    {
        message[i] = random(0xFF);
    }
    print_data(message, sizeof(message));

    if (rsa_public_encrypt(message, sizeof(message), client_public_key, buffer))
    {
        if (rsa_private_decrypt(buffer, client_public_key, client_private_key, buffer))
        {
            if (!memcmp(message, buffer, sizeof(message)))
            {
                status = true;
            }
        }
    }

    if (status)
    {
        print_data(buffer, sizeof(message));
    }
    else
    {
        error("1) Failed");
    }

    status = false;
    if (rsa_private_encrypt(message, sizeof(message), client_public_key, client_private_key, buffer))
    {
        if (rsa_public_decrypt(buffer, client_public_key, buffer))
        {
            if (!memcmp(message, buffer, sizeof(message)))
            {
                status = true;
            }
        }
    }

    if (status)
    {
        print_data(buffer, sizeof(message));
    }
    else
    {
        error("2) Failed");
    }

    Serial.println();
    delay(500);
}