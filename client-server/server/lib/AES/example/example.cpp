#include <AES256.h>
#include <Arduino.h>

static void error(const char *msg)
{
    while (1)
    {
        Serial.println(msg);
        delay(500);
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
    const uint8_t *key = aes256_init_key(NULL);
    Serial.print("AES Key: ");
    print_data(key, AES_KEY_SIZE);

    uint8_t message[AES_BLOCK_SIZE] ={};
    uint8_t length = 1 + random(AES_BLOCK_SIZE - 1);
    for (uint8_t i = 0; i < length; i++)
    {
        message[i] = random(0xFF);
    }
    Serial.print("Message: ");
    print_data(message, length);

    uint8_t cipher[AES_CIPHER_SIZE] ={};
    aes256_encrypt(message, length, cipher);
    Serial.print("Cipher : ");
    print_data(cipher, sizeof(cipher));

    uint8_t text[AES_BLOCK_SIZE] ={};
    aes256_decrypt(cipher, text);
    Serial.print("Text   : ");

    if (memcmp(text, message, length))
    {
        error("Failed!");
    }
    else
    {
        print_data(text, length);
    }

    Serial.println();
    delay(1000);
}