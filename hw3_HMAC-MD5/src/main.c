#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include "md5.h"
#include "hmac.h"

int get_file_size(char * inputfile_name, char * keyfile_name, uint64_t * inputfile_size, uint64_t * keyfile_size) {
    if (keyfile_name == NULL) {
        struct stat inputfile_stat;
        stat(inputfile_name, &inputfile_stat);
        *inputfile_size = inputfile_stat.st_size;
        return 1;
    }
    else {
        struct stat inputfile_stat, keyfile_stat;
        stat(inputfile_name, &inputfile_stat);
        stat(keyfile_name, &keyfile_stat);
        *inputfile_size = inputfile_stat.st_size;
        *keyfile_size = keyfile_stat.st_size;
        if (*inputfile_size >= *keyfile_size) {
            return 1;
        }
        else {
            return 0;
        }
    }
}

int main(int argc, char ** argv) {
    if (argc != 3 && !strcmp(argv[1], "md5") || argc != 4 && !strcmp(argv[1], "hmac")) {
        fprintf(stderr, "This app has two functions:\n");
        fprintf(stderr, "HMAC: ./hmac-md5 hmac inputfile keyfile\n");
        fprintf(stderr, "MD5: ./hmac-md5 md5 inputfile\n");
        exit(1);
    }
    if (!strcmp(argv[1], "md5")) {
        uint64_t inputfile_size;
        get_file_size(argv[2], NULL, &inputfile_size, NULL);
        char * inputfile_buffer = malloc(inputfile_size);

        FILE * inputfile;
        inputfile = fopen(argv[2], "r");
        fread(inputfile_buffer, 1, inputfile_size, inputfile);
        
        uint8_t result[16];
        MD5(inputfile_buffer, inputfile_size, result);
        print_result(result);
        free(inputfile_buffer);
        fclose(inputfile);
    }
    else {
        uint64_t inputfile_size, keyfile_size;
        if (!get_file_size(argv[2], argv[3], &inputfile_size, &keyfile_size)) {
            fprintf(stderr, "error: the length of key is longer than input text\n");
            exit(1);
        }
        char * inputfile_buffer = malloc(inputfile_size);
        char * keyfile_buffer = malloc(keyfile_size);

        FILE *inputfile, *keyfile;
        inputfile = fopen(argv[2], "r");
        keyfile = fopen(argv[3], "r");
        fread(inputfile_buffer, 1, inputfile_size, inputfile);
        fread(keyfile_buffer, 1, keyfile_size, keyfile);
        
        uint8_t result[16];
        HMAC(MD5, inputfile_buffer, inputfile_size, 512, keyfile_buffer, keyfile_size, result);
        print_result(result);
        free(inputfile_buffer);
        free(keyfile_buffer);
        fclose(inputfile);
        fclose(keyfile);
    }
}