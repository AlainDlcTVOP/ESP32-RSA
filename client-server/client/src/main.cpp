#include <RSA.h>
#include <WiFi.h>
#include <SHA256.h>
#include <AES256.h>
#include <Arduino.h>
#include <IPAddress.h>
#include <WiFiClient.h>
#include <esp32-hal.h>
#define SSID "YA-LOCAL"
#define PASSWORD "utbildning2020"

#define PORT 80
#define SERVER "192.168.0.128"
#define BUFSIZE (3 * RSA_SIZE)

// PUBLIC_ENCRYPT(PRIVATE_ENCRYPT(REQ_ID | DATA)) | HASH => AUTH | AES_KEY
// AES_ENCRYPT(REQ_ID | SESSION_ID) | HASH => TEMPERATURE | SESSION_ID

// PUBLIC_DECRYPT(PRIVATE_DECRYPT(RES_STATUS | SESSION_ID)) | HASH => OKAY | SESSION_ID
// AES_DECRYPT(RES_STATUS | DATA) | HASH => OKAY | temperature

enum Request : uint8_t
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
} request_t;

typedef struct
{
    uint8_t data[BUFSIZE];
    uint8_t status;
    uint8_t length;
} response_t;

union Mydata_response {
    uint8_t command : 5;
    float temp;
};
static void authenticate(void);
static void run_command(uint8_t req_id);
static void print_error(uint8_t error_id);
static char read_command(const char *filter);

static WiFiClient client;
static uint32_t session_id = 10U;
static uint8_t server_public_key[RSA_SIZE] = {
    0x92, 0xF4, 0x13, 0xDD, 0x91, 0xFE, 0x15, 0xD3, 0xCA, 0x3D, 0xD8, 0x65, 0x32, 0x8D, 0xC7, 0x64,
    0xA5, 0x7F, 0xF9, 0x4C, 0xE2, 0x9B, 0x03, 0x96, 0xF5, 0xB7, 0x80, 0x55, 0xDE, 0xB0, 0xEA, 0x58,
    0x97, 0x7F, 0x9F, 0x25, 0x8C, 0x45, 0x5A, 0xF4, 0x50, 0x21, 0xF8, 0x95, 0xCC, 0xB8, 0x53, 0xE4,
    0x8C, 0x43, 0xD0, 0x87, 0x08, 0x97, 0xF3, 0x31, 0x39, 0x50, 0x17, 0x5F, 0xE1, 0xCD, 0xC7, 0xD5};
static uint8_t client_public_key[RSA_SIZE] = {
    0xD1, 0x13, 0x2B, 0x14, 0x8E, 0xA4, 0x70, 0x89, 0xA0, 0x3E, 0x3B, 0x2E, 0x3F, 0xDD, 0xDC, 0xC0,
    0xBD, 0x88, 0x49, 0x2B, 0xFC, 0x04, 0x6C, 0xB9, 0x23, 0x5C, 0x1F, 0x5B, 0x68, 0x6F, 0x00, 0xDD,
    0xF0, 0x8A, 0x9A, 0x12, 0x7C, 0x64, 0x33, 0x8F, 0x6B, 0xF4, 0xC5, 0x62, 0x00, 0x68, 0x20, 0xDE,
    0xD3, 0xA2, 0xA2, 0xEA, 0xD6, 0x04, 0x9C, 0x15, 0xB9, 0x23, 0xC3, 0x8E, 0x02, 0xEC, 0x7E, 0x7B};
static uint8_t client_private_key[RSA_SIZE] = {
    0x63, 0xC2, 0x98, 0xB0, 0xC3, 0x6B, 0x55, 0x43, 0x66, 0x11, 0xAB, 0x9D, 0x62, 0xDE, 0x13, 0x22,
    0x68, 0x8D, 0x6A, 0x14, 0xB1, 0xB8, 0xCE, 0xC3, 0xFC, 0x4A, 0x4D, 0xB0, 0x09, 0x01, 0xC6, 0x50,
    0x43, 0x08, 0x4B, 0xC6, 0x6D, 0x16, 0xA6, 0xA8, 0x34, 0x47, 0x46, 0xDF, 0x82, 0xDA, 0x68, 0x52,
    0xF7, 0x31, 0x38, 0xA3, 0xA5, 0xAB, 0x6C, 0x02, 0xF1, 0xA6, 0x97, 0xFF, 0x0B, 0x14, 0x65, 0x01};

static void print_data(uint8_t *data, uint8_t size)
{
    // Serial.printf("%f", (float)data[0]);
    for (uint8_t i = 0; i < size; i++)
    {
        Serial.printf("%02X ", data[i]);
    }
    Serial.println();
}

static void print_error(uint8_t error_id)
{
}

static response_t post(request_t *req)
{
    response_t response = {};
    response.status = WAITING;

    uint32_t mstime = millis();
    // Connect to the server
    client.connect(SERVER, PORT);
    while (!client.connected())
    {
        if ((millis() - mstime) > 10000)
        {
            client.stop();
            response.status = DISCONNECTED;
            return response;
        }
        client.connect(SERVER, PORT);
        delay(500);
    }

    sha256(req->data, req->length, req->data + req->length);
    req->length += HASH_SIZE;

    // Send the data to the server
    client.write(req->data, req->length);
    client.flush();

    mstime = millis();
    // Wait on receiving data from the server
    while (!client.available())
    {
        if ((millis() - mstime) > 5000)
        {
            client.stop();
            response.status = TIMEOUT;
            return response;
        }
        delay(10);
    }

    // Read the received data
    response.length = client.read(response.data, BUFSIZE);

    if ((response.length != 2 * RSA_SIZE + HASH_SIZE) && (response.length != AES_CIPHER_SIZE + HASH_SIZE))
    {
        client.stop();
        response.status = BAD_REQUEST;
        return response;
    }

    uint8_t hash[HASH_SIZE] = {};
    response.length -= HASH_SIZE;
    sha256(response.data, response.length, hash);
    if (memcmp(hash, response.data + response.length, HASH_SIZE))
    {
        client.stop();
        response.status = HASH_ERROR;
        return response;
    }

    // Make the response

    // Close the connection
    client.stop();

    return response;
}

static void run_command(uint8_t req_id)
{
    request_t request = {};
    union Mydata_response data;
    data.command = req_id;
    //memcpy(request.data, &data, request.length);

    request.length = sizeof(data);
    memcpy(request.data, &data, sizeof(data));

    Serial.print("\nSent    : ");
    for (uint8_t i = 0; i < request.length; i++)
    {
        Serial.printf("%02x ", request.data[i]);
    }

    Serial.println();

    response_t response = post(&request);

    Serial.print("Received: ");
    print_data(response.data, response.length);

    print_data(request.data, sizeof(data));
    Serial.println("\n");
}

static void authenticate(void)
{
    session_id = 0;

    request_t request = {};
    request.data[0] = AUTH;
    request.length = 1U;

    const uint8_t *key = aes256_init_key(NULL);
    memcpy(request.data + request.length, key, AES_KEY_SIZE);
    request.length += AES_KEY_SIZE;

    uint8_t buffer[RSA_SIZE] = {};
    rsa_private_encrypt(request.data, request.length, client_public_key, client_private_key, buffer);

    request.length = 0U;
    rsa_public_encrypt(buffer, RSA_BLOCK_SIZE, server_public_key, request.data + request.length);
    request.length = RSA_SIZE;

    rsa_public_encrypt(buffer + RSA_BLOCK_SIZE, RSA_SIZE - RSA_BLOCK_SIZE, server_public_key, request.data + request.length);
    request.length += RSA_SIZE;

    response_t response = post(&request);

    if (response.status == OKAY)
    {
        // assign response.status to sessen_id
    }
    else
    {
        print_error(response.status);
    }
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
        Serial.print(".");
        delay(1000);
    }

    Serial.print("\nIP Address: ");
    Serial.println(WiFi.localIP());
}

void loop()
{
    if (session_id)
    {
        Serial.println("F) Turn The LED Off"); // pinmmode
        Serial.println("O) Turn The LED On");
        Serial.println("T) Get Temperature");
        Serial.println("C) Close");
    }
    else
    {
        Serial.println("A) Authenticate");
    }
    Serial.print("Enter the command: ");

    char command = session_id ? read_command("FOTC\n") : read_command("A\n");

    switch (command)
    {
    case 'A':
        authenticate();
        break;
    case 'O':
        run_command(TURN_LED_ON);
        break;

    case 'F':
        run_command(TURN_LED_OFF);
        break;

    case 'T':
        run_command(TEMPERATURE);
        Serial.printf("TEMP ");
        Serial.printf("%f.2\n", temperatureRead());
        break;

    case 'C':
        run_command(AUTH);
        break;
    default:
        break;
    }
}

static char read_command(const char *filter)
{
    char command = 0;
    bool found = false;

    while (Serial.available())
    {
        (void)Serial.read();
    }

    while (!found)
    {
        if (Serial.available())
        {
            command = toupper(Serial.read());
            for (char *ptr = (char *)filter; *ptr; ptr++)
            {
                if (*ptr == command)
                {
                    found = true;
                    break;
                }
            }
        }
    }

    Serial.printf("%c\n\n", command);

    return command;
}
void read_temp()
{
}