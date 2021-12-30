#include "des.h"
#include "md5.h"

typedef struct {
    int id;
    int client_address;
    long validity;
    uint8_t key[8];
} Ticket;

typedef struct {
    int id;
    long timestamp;
} Auth;


void kerberos_generate_key_client(int password, uint8_t key_client[8]);

void print_message(uint8_t * message, int size);