#include <SHA256.h>
#include <Arduino.h>

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
    uint8_t hash[HASH_SIZE] ={};
    uint8_t text[] = "Hello World!";

    sha256(text, sizeof(text), hash);
    Serial.print("SHA1: ");
    print_data(hash, HASH_SIZE);

    Serial.println();
    delay(1000);
}
