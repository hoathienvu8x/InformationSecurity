#include "kerberos.h"



void kerberos_generate_key_client(int password, uint8_t key_client[8]) {
    uint8_t buffer[100];
    MD5((uint8_t*)&password, 4, buffer);
    printf("MD5 hash result of %d: ", password);
    print_result(buffer);
    memcpy(key_client, buffer, 8);
    correct_key(key_client);
    printf("key-client of %d: ", password);
    print_key(key_client);
}

void print_message(uint8_t * message, int size) {
    for (int i = 0; i < size; ++i) {
        printf("%02x", message[i]);
    }
    printf("\n");
}