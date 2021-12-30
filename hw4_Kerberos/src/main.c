#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <memory.h>
#include <unistd.h>
#include "kerberos.h"
#define BUF_SIZE 1000
int main() {
    srand((unsigned)time(NULL));
    uint8_t buffer[1000];
    uint8_t key_client[8], key_tgs[8], key_ss[8], key_client_tgs[8], key_client_ss[8];
    int comm_sz;
    int my_rank;
    MPI_Init(NULL, NULL);
    MPI_Comm_size(MPI_COMM_WORLD, &comm_sz);
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    // AS 进程
    if (my_rank == 0) {
        // 生成一个 key tgs 并发送给 tgs
        generate_key(key_tgs);
        printf("AS: send key-tgs to TGS: ");
        print_message(key_tgs, 8);
        MPI_Send(key_tgs, 8, MPI_UNSIGNED_CHAR, 1, 0, MPI_COMM_WORLD);

        for (int i = 3; i < comm_sz; ++i) {
            int request_client_id, password;
            MPI_Status recv_status;
            MPI_Recv(&request_client_id, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &recv_status);
            printf("AS: recv request from client %d\n", request_client_id);
            password = request_client_id;
            // 根据 password(rank) 的 MD5 生成 key client
            printf("AS: ");
            kerberos_generate_key_client(password, key_client);
            // 生成一个 key client-tgs
            generate_key(key_client_tgs);
            printf("AS: key-client-tgs origin text of client %d: ", recv_status.MPI_SOURCE);
            print_key(key_client_tgs);
            // 使用 key client 加密 key client-tgs
            int cipher_size = des_encrypt(key_client_tgs, 8, buffer, key_client);
            printf("AS: send key-client-tgs ciphertext after encrypt to client %d: ", recv_status.MPI_SOURCE);
            print_message(buffer, cipher_size);      
            // 将加密的 key client-tgs 发送给client
            MPI_Send(buffer, cipher_size, MPI_UNSIGNED_CHAR, recv_status.MPI_SOURCE, 0, MPI_COMM_WORLD);

            // 创建 message b
            Ticket message_b = {recv_status.MPI_SOURCE, recv_status.MPI_SOURCE, 600};
            memcpy(message_b.key, key_client_tgs, 8);
            printf("AS: message b(TGT) origin text of client %d: client id: %d, address: %d, validity: %d, key_client_tgs: ", recv_status.MPI_SOURCE, message_b.id, message_b.client_address, message_b.validity);
            print_key(message_b.key);

            // 使用 key tgs 加密 message b 的原始数据
            cipher_size = des_encrypt((uint8_t*)&message_b, sizeof(Ticket), buffer, key_tgs);
            printf("AS: send message b(TGT) ciphertext of client %d to client %d: ", recv_status.MPI_SOURCE, recv_status.MPI_SOURCE);
            print_message(buffer, cipher_size);
            MPI_Send(buffer, cipher_size, MPI_UNSIGNED_CHAR, recv_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
        }
    }
    // TGS 进程
    else if (my_rank == 1) {
        long *client_record = malloc(sizeof(long) * comm_sz);
        for (int i = 0; i < comm_sz; ++i) {
            client_record[i] = 0;
        }
        MPI_Recv(key_tgs, 8, MPI_UNSIGNED_CHAR, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        printf("TGS: TGS recv key-tgs from AS: ");
        print_message(key_tgs, 8);
        srand((unsigned)time(NULL) + my_rank);
        generate_key(key_ss);
        printf("TGS: TGS send key-ss to SS: ");
        print_message(key_ss, 8);
        // 发送给 tgs
        MPI_Send(key_ss, 8, MPI_UNSIGNED_CHAR, 2, 0, MPI_COMM_WORLD);
        for (int i = 3; i < comm_sz; ++i) {
            // 接受 message c
            // 接受 service_ID
            int service_ID;
            MPI_Status service_ID_status;
            MPI_Recv(&service_ID, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &service_ID_status);
            printf("TGS: recv service ID: %d from client %d\n", service_ID, service_ID_status.MPI_SOURCE);
            // 接受 message b 并解密
            Ticket message_b;
            MPI_Status cipher_message_b_status;
            MPI_Recv(buffer, BUF_SIZE, MPI_UNSIGNED_CHAR, service_ID_status.MPI_SOURCE, 0, MPI_COMM_WORLD, &cipher_message_b_status);
            int cipher_message_b_size;
            MPI_Get_count(&cipher_message_b_status, MPI_UNSIGNED_CHAR, &cipher_message_b_size);
            printf("TGS: recv message b(TGT) ciphertext from client %d: ", cipher_message_b_status.MPI_SOURCE);
            print_message(buffer, cipher_message_b_size);
            des_decrypt(buffer, cipher_message_b_size, (uint8_t*)&message_b, key_tgs);
            memcpy(key_client_tgs, message_b.key, 8);
            printf("TGS: message b(TGT) origin text after decrypt from client %d: client id: %d, address: %d, validity: %d, key_client_tgs: ", cipher_message_b_status.MPI_SOURCE, message_b.id, message_b.client_address, message_b.validity);
            print_key(message_b.key);
            // 接受 message d 并解密
            Auth message_d;
            MPI_Status cipher_message_d_status;
            MPI_Recv(buffer, BUF_SIZE, MPI_UNSIGNED_CHAR, service_ID_status.MPI_SOURCE, 0, MPI_COMM_WORLD, &cipher_message_d_status);
            int cipher_message_d_size;
            MPI_Get_count(&cipher_message_d_status, MPI_UNSIGNED_CHAR, &cipher_message_d_size);
            printf("TGS: recv message d ciphertext from client %d: ", cipher_message_d_status.MPI_SOURCE);
            print_message(buffer, cipher_message_d_size);
            des_decrypt(buffer, cipher_message_d_size, (uint8_t*)&message_d, message_b.key);
            printf("TGS: message d origin text from client %d: client id: %d, time: %ld\n",cipher_message_d_status.MPI_SOURCE, message_d.id, message_d.timestamp);

            printf("TGS: send service ID: %d to client %d\n", service_ID, cipher_message_d_status.MPI_SOURCE);
            // 判断正确性
            int error_code;
            if (time(NULL) - message_d.timestamp > message_b.validity) {
                error_code = 1;
                MPI_Send(&error_code, 1, MPI_INT, cipher_message_d_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                printf("TGS: timeout error!\n");
            }
            else if (message_b.id != message_d.id) {
                error_code = 2;
                MPI_Send(&error_code, 1, MPI_INT, cipher_message_d_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                printf("TGS: id error!\n");
            }
            else if (client_record[cipher_message_d_status.MPI_SOURCE] >= message_d.timestamp) {
                error_code = 3;
                MPI_Send(&error_code, 1, MPI_INT, cipher_message_d_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                printf("TGS: timestamp error!\n");
            }
            else {
                error_code = 0;
                MPI_Send(&error_code, 1, MPI_INT, cipher_message_d_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                // 发送 service ID (消息E之一)
                MPI_Send(&service_ID, 1, MPI_INT, cipher_message_d_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                // 发送 ST (消息E之一)
                generate_key(key_client_ss);
                Ticket st = {cipher_message_d_status.MPI_SOURCE, cipher_message_d_status.MPI_SOURCE, 600};
                memcpy(st.key, key_client_ss, 8);
                int st_ciphertext_size = des_encrypt((uint8_t*)&st, sizeof(Ticket), buffer, key_ss);
                printf("TGS: message e(ST) origin text of client %d: client id: %d, address: %d, validity: %d, key_client_ss: ", cipher_message_d_status.MPI_SOURCE, st.id, st.client_address, st.validity);
                print_key(st.key);
                printf("TGS: send message e(ST) ciphertext to client %d: ", cipher_message_d_status.MPI_SOURCE);
                print_message(buffer, st_ciphertext_size);
                MPI_Send(buffer, st_ciphertext_size, MPI_UNSIGNED_CHAR, cipher_message_d_status.MPI_SOURCE, 0, MPI_COMM_WORLD);

                // 发送 message f
                printf("TGS: key-client-ss origin text of client %d: ", cipher_message_d_status.MPI_SOURCE);
                print_key(key_client_ss);
                int key_client_ss_size = des_encrypt(key_client_ss, 8, buffer, key_client_tgs);
                printf("TGS: send key-client-ss ciphertext after encrypt to client %d: ", cipher_message_d_status.MPI_SOURCE);
                print_message(buffer, key_client_ss_size);  
                MPI_Send(buffer, key_client_ss_size, MPI_UNSIGNED_CHAR, cipher_message_d_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
            }
        }
        free(client_record);
    }
    // SS 进程
    else if (my_rank == 2) {
        long *client_record = malloc(sizeof(long) * comm_sz);
        for (int i = 0; i < comm_sz; ++i) {
            client_record[i] = 0;
        }
        MPI_Recv(key_ss, 8, MPI_UNSIGNED_CHAR, 1, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        printf("SS: recv key-ss from TGS: ");
        print_message(key_ss, 8);
        
        for (int i = 3; i < comm_sz; ++i) {
            int error_code;
            MPI_Status error_code_status;
            MPI_Recv(&error_code, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &error_code_status);
            if (error_code == 0) {
                // 接收 message e(servive ID)
                int service_ID;
                MPI_Status service_ID_status;
                MPI_Recv(&service_ID, 1, MPI_INT, error_code_status.MPI_SOURCE, 0, MPI_COMM_WORLD, &service_ID_status);
                printf("SS: recv service ID: %d from client %d\n", service_ID, service_ID_status.MPI_SOURCE);
                // 接受 message e(ST)
                MPI_Status st_ciphertext_status;
                MPI_Recv(buffer, BUF_SIZE, MPI_UNSIGNED_CHAR, error_code_status.MPI_SOURCE, 0, MPI_COMM_WORLD, &st_ciphertext_status);
                int st_ciphertext_size;
                MPI_Get_count(&st_ciphertext_status, MPI_UNSIGNED_CHAR, &st_ciphertext_size);
                printf("SS: recv ST ciphertext from client %d: ", st_ciphertext_status.MPI_SOURCE);
                print_message(buffer, st_ciphertext_size);
                Ticket st;
                des_decrypt(buffer, st_ciphertext_size, (uint8_t*)&st, key_ss);
                printf("SS: message e(ST) origin text from client %d: client id: %d, address: %d, validity: %d, key_client_ss: ", st_ciphertext_status.MPI_SOURCE, st.id, st.client_address, st.validity);
                print_key(st.key);
                memcpy(key_client_ss, st.key, 8);
                // 接收 message g
                MPI_Status message_g_ciphertext_status;
                MPI_Recv(buffer, BUF_SIZE, MPI_UNSIGNED_CHAR, error_code_status.MPI_SOURCE, 0, MPI_COMM_WORLD, &message_g_ciphertext_status);
                int message_g_ciphertext_size;
                MPI_Get_count(&message_g_ciphertext_status, MPI_UNSIGNED_CHAR, &message_g_ciphertext_size);
                printf("SS: recv message g ciphertext from client %d: ", message_g_ciphertext_status.MPI_SOURCE);
                print_message(buffer, message_g_ciphertext_size);
                Auth message_g;
                des_decrypt(buffer, message_g_ciphertext_size, (uint8_t*)&message_g, st.key);
                printf("SS: message g origin text from client %d: client id: %d, timestamp: %ld\n", message_g_ciphertext_status.MPI_SOURCE, message_g.id, message_g.timestamp);
            
                // 进行验证
                int error_code;
                if (time(NULL) - message_g.timestamp > st.validity) {
                    error_code = 1;
                    printf("SS: timeout error!\n");
                    MPI_Send(&error_code, 1, MPI_INT, message_g_ciphertext_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                }
                else if (message_g.id != st.id) {
                    error_code = 2;
                    printf("SS: id error!\n");
                    MPI_Send(&error_code, 1, MPI_INT, message_g_ciphertext_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                }
                else if (client_record[message_g_ciphertext_status.MPI_SOURCE] >= message_g.timestamp) {
                    error_code = 3;
                    printf("SS: timestamp error!\n");
                    MPI_Send(&error_code, 1, MPI_INT, message_g_ciphertext_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                }
                else {
                    error_code = 0;
                    printf("SS: agree to service\n");
                    MPI_Send(&error_code, 1, MPI_INT, message_g_ciphertext_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                    // 发送 message h
                    Auth message_h = message_g;
                    message_h.timestamp++;
                    printf("SS: message h origin text to client %d: client id: %d, timestamp: %ld\n", message_g_ciphertext_status.MPI_SOURCE, message_h.id, message_h.timestamp);
                    int message_h_ciphertext_size = des_encrypt((uint8_t*)&message_h, sizeof(Auth), buffer, key_client_ss);
                    printf("SS: send message h ciphertext to client %d: ", message_g_ciphertext_status.MPI_SOURCE);
                    print_message(buffer, message_h_ciphertext_size);
                    MPI_Send(buffer, message_h_ciphertext_size, MPI_UNSIGNED_CHAR, message_g_ciphertext_status.MPI_SOURCE, 0, MPI_COMM_WORLD);
                    printf("SS: start to service to client\n");
                }
            }
        }
    }
    // Client 进程
    else {
        MPI_Send(&my_rank, 1, MPI_INT, 0, 0, MPI_COMM_WORLD);
        printf("Client %d: send id to AS for request\n", my_rank);
        // 根据 password(rank) 的 MD5 生成 key client (密码就是rank_id)
        printf("Client %d: ", my_rank);
        kerberos_generate_key_client(my_rank, key_client);
        
        // 接收加密的 key client-tgs (收到消息A)
        MPI_Status recv_status_a;
        MPI_Recv(buffer, BUF_SIZE, MPI_UNSIGNED_CHAR, 0, 0, MPI_COMM_WORLD, &recv_status_a);
        // 使用 key client 对 key client-tgs 解密
        // 被加密后 key client-tgs 的长度
        int key_client_tgs_cipher_size;
        MPI_Get_count(&recv_status_a, MPI_UNSIGNED_CHAR, &key_client_tgs_cipher_size);
        printf("Client %d: recv key-client-tgs ciphertext from AS: ", my_rank);
        print_message(buffer, key_client_tgs_cipher_size);
        // 解密后 key client-tgs 的长度
        int key_client_tgs_origin_size = des_decrypt(buffer, key_client_tgs_cipher_size, key_client_tgs, key_client);
        printf("Client %d: key-client-tgs origin text after decrypt: ", my_rank);
        print_message(key_client_tgs, key_client_tgs_origin_size);

        // 接受TGT(收到消息B)
        MPI_Status recv_status_b;
        MPI_Recv(buffer, BUF_SIZE, MPI_UNSIGNED_CHAR, 0, 0, MPI_COMM_WORLD, &recv_status_b);
        // 被加密后 message b 的长度
        int message_b_cipher_size;
        MPI_Get_count(&recv_status_b, MPI_UNSIGNED_CHAR, &message_b_cipher_size);
        printf("Client %d: recv message b(TGT) ciphertext from AS: ", my_rank);
        print_message(buffer, message_b_cipher_size);
        // 存储这个加密后的 message b，稍后发送给 tgs
        uint8_t *temp_b = malloc(message_b_cipher_size);
        memcpy(temp_b, buffer, message_b_cipher_size);

        // 发送 message c
        // 发送 service ID
        int service_ID = my_rank;
        printf("Client %d: send service ID: %d to TGS\n", my_rank, service_ID);
        MPI_Send(&service_ID, 1, MPI_INT, 1, 0, MPI_COMM_WORLD);
        // 发送 message b
        printf("Client %d: send message b(TGT) ciphertext to TGS: ", my_rank);
        print_message(buffer, message_b_cipher_size);
        MPI_Send(temp_b, message_b_cipher_size, MPI_UNSIGNED_CHAR, 1, 0, MPI_COMM_WORLD);
        free(temp_b);

        // 发送 message d
        Auth message_d = {my_rank, time(NULL)};
        printf("Client %d: message d origin text: id: %d, timestamp: %d\n", my_rank, message_d.id, message_d.timestamp);
        int message_d_cipher_size = des_encrypt((uint8_t*)&message_d, sizeof(Auth), buffer, key_client_tgs);
        printf("Client %d: send message d ciphertext to TGS: ", my_rank);
        print_message(buffer, message_d_cipher_size);
        MPI_Send(buffer, message_d_cipher_size, MPI_UNSIGNED_CHAR, 1, 0, MPI_COMM_WORLD);


        MPI_Status judge_flag;
        int error_code;
        MPI_Recv(&error_code, 1, MPI_INT, 1, 0, MPI_COMM_WORLD, &judge_flag);
        if (error_code == 1) {
            printf("Client %d: timeout error!\n", my_rank);
            MPI_Send(&error_code, 1, MPI_INT, 2, 0, MPI_COMM_WORLD);
        }
        else if (error_code == 2) {
            printf("Client %d: id error!\n", my_rank);
            MPI_Send(&error_code, 1, MPI_INT, 2, 0, MPI_COMM_WORLD);
        }
        else if (error_code == 3) {
            printf("Client %d: timestamp error!\n", my_rank);
            MPI_Send(&error_code, 1, MPI_INT, 2, 0, MPI_COMM_WORLD);
        }
        else {
            MPI_Send(&error_code, 1, MPI_INT, 2, 0, MPI_COMM_WORLD);
            // 接收 message e
            // 接受 service ID
            MPI_Recv(&service_ID, 1, MPI_INT, 1, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            printf("Client %d: recv service ID: %d from TGS\n", my_rank, service_ID);
            // 接受 ST 
            MPI_Status st_status;
            MPI_Recv(buffer, BUF_SIZE, MPI_UNSIGNED_CHAR, 1, 0, MPI_COMM_WORLD, &st_status);
            int st_ciphertext_size;
            MPI_Get_count(&st_status, MPI_UNSIGNED_CHAR, &st_ciphertext_size);
            printf("Client %d: recv ST ciphertext from TGS: ", my_rank);
            uint8_t *st_tem = malloc(st_ciphertext_size);
            memcpy(st_tem, buffer, st_ciphertext_size);
            print_message(st_tem, st_ciphertext_size);
            // 接受 message f
            MPI_Status ciphertext_message_f_status;
            MPI_Recv(buffer, BUF_SIZE, MPI_UNSIGNED_CHAR, 1, 0, MPI_COMM_WORLD, &ciphertext_message_f_status);
            int ciphertext_message_f_size;
            MPI_Get_count(&ciphertext_message_f_status, MPI_UNSIGNED_CHAR, &ciphertext_message_f_size);
            printf("Client %d: recv key-client-ss ciphertext from TGS: ", my_rank);
            print_message(buffer, ciphertext_message_f_size);
            des_decrypt(buffer, ciphertext_message_f_size, key_client_ss, key_client_tgs);
            printf("Client %d: key-client-ss origin text from TGS: ", my_rank);
            print_key(key_client_ss);

            // 发送 message e
            // 发送 service ID
            printf("Client %d: send service ID: %d to SS\n", my_rank, service_ID);
            MPI_Send(&service_ID, 1, MPI_INT, 2, 0, MPI_COMM_WORLD);
            // 发送 ST 的密文
            printf("Client %d: send ST ciphertext to SS: ", my_rank);
            print_message(st_tem, st_ciphertext_size);
            MPI_Send(st_tem, st_ciphertext_size, MPI_UNSIGNED_CHAR, 2, 0, MPI_COMM_WORLD);
            free(st_tem);
            // 发送 message g
            Auth message_g = {my_rank, time(NULL)};
            printf("Client %d: message g origin text: id: %d, timestamp: %d\n", my_rank, message_g.id, message_g.timestamp);
            int message_g_ciphertext_size = des_encrypt((uint8_t*)&message_g, sizeof(Auth), buffer, key_client_ss);
            printf("Client %d: send message g ciphertext to TGS: ", my_rank);
            print_message(buffer, message_g_ciphertext_size);
            MPI_Send(buffer, message_g_ciphertext_size, MPI_UNSIGNED_CHAR, 2, 0, MPI_COMM_WORLD);

                
            // 判断认证情况
            int error_code;
            MPI_Recv(&error_code, 1, MPI_INT, 2, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            if (error_code == 1) {
                printf("Client %d: timeout error!\n", my_rank);
            }
            else if (error_code == 2) {
                printf("Client %d: id error!\n", my_rank);
            }
            else if (error_code == 3) {
                printf("Client %d: timestamp error!\n", my_rank);
            }
            else {
                // 接受 message h
                MPI_Status message_h_ciphertext_status;
                MPI_Recv(buffer, BUF_SIZE, MPI_UNSIGNED_CHAR, 2, 0, MPI_COMM_WORLD, &message_h_ciphertext_status);
                int message_h_ciphertext_size;
                MPI_Get_count(&message_h_ciphertext_status, MPI_UNSIGNED_CHAR, &message_h_ciphertext_size);
                printf("Client %d: recv message h ciphertext from SS: ", my_rank);
                print_message(buffer, message_h_ciphertext_size);

                // 解密 message h
                Auth message_h;
                des_decrypt(buffer, message_h_ciphertext_size, (uint8_t*)&message_h, key_client_ss);
                printf("Client %d: message h origin text from SS: client id: %d, timestamp: %ld\n", my_rank, message_h.id, message_h.timestamp);

                if (message_h.timestamp == message_g.timestamp + 1) {
                    printf("Client %d: I will trust SS\n", my_rank);
                }
                else {
                    printf("Client %d: I can't trust SS\n", my_rank);
                }
            }
        }

    }
    MPI_Finalize();
    return 0;
}