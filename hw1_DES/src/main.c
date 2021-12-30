#include <stdio.h>
#include "des.h"

void print_error() {
    fprintf(stderr, "Usage: ./des e or d inputfile keyfile outputfile\n");
    fprintf(stderr, "Example: ./des e inputfile keyfile outputfile\n");
    fprintf(stderr, "you can use '-' instead of keyfile to get a key. Then a keyfile named 'key' will be create in current dirtionary.\n");
}

int main(int argc, char **argv) {
    if (argc != 5) {
        print_error();
    }
    else {
        char buffer[10000], key[8];
        if (argv[1][0] == 'e') {
            FILE *fp_in = NULL, *fp_key = NULL, *fp_out = NULL;
            fp_in = fopen(argv[2], "r");
            
            int i = 0;
            for (char ch; (ch = fgetc(fp_in)) != EOF; ++i) {
                buffer[i] = ch;
            }
            
            buffer[i] = 0;
            if (argv[3][0] != '-') {
                fp_key = fopen(argv[3], "r");
                fscanf(fp_key, "%s", key);
            }
            else {
                generate_key(key);
                fp_key = fopen("key", "w");
                fprintf(fp_key, "%s", key);
            }
            des_encrypt(buffer, buffer, key);
            fp_out = fopen(argv[4], "w");
            fputs(buffer, fp_out);
            fclose(fp_in);
            fclose(fp_key);
            fclose(fp_out);   
        }
        else if (argv[1][0] == 'd'){
            FILE *fp_in = NULL, *fp_key = NULL, *fp_out = NULL;
            fp_in = fopen(argv[2], "r");
            
            int i = 0;
            for (char ch; (ch = fgetc(fp_in)) != EOF; ++i) {
                buffer[i] = ch;
            }
            buffer[i] = 0;

            fp_key = fopen(argv[3], "r");
            fscanf(fp_key, "%s", key);

            des_decrypt(buffer, buffer, key);
            fp_out = fopen(argv[4], "w");
            fputs(buffer, fp_out);
            fclose(fp_in);
            fclose(fp_key);
            fclose(fp_out); 
        }
        else {
            print_error();
        }
    }
    
}

// test 1
// int main(int argc, char **argv) {
//     char key[9], buffer[1000];;
//     key[8] = 0;
//     generate_key(key);
//     char * text = "Hello, world!";
//     des_encrypt(text, buffer, key);
//     des_decrypt(buffer, buffer, key);
//     fprintf(stdout, "%s\n", buffer);
// } 

// test 2
// int main(int argc, char **argv) {
//     char key[9], buffer[1000];;
//     key[8] = 0;
//     for (int i = 0; i < 4; ++i) {
//         key[i] = 0xe0;
//     }
//     for (int i = 4; i < 8; ++i) {
//         key[i] = 0xf1;
//     }

//     FILE *fp_c = NULL;
//     // 打开 openssl 加密的密文
//     fp_c = fopen("/home/luowle/homework/InformationSecurity/hw1_DES/test/ciphertext", "r"); 
//     fscanf(fp_c, "%s", buffer);

//     des_decrypt(buffer, buffer, key);
//     fprintf(stdout, "%s", buffer);
//     fclose(fp_c);
// } 


