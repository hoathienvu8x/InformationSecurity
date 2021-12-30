# C语言实现DES对称算法
## 算法原理
算法大致分为以下步骤
1. 将字符流拆解为64位的块
2. 对64位的块进行IP置换
3. IP置换后的块进行16轮迭代
4. 迭代后的结果LR置换为RL
5. 进行IP逆置换  

算法的详细过程在PPT中有详细介绍，有效性证明也在其中，此处不再赘述。

## 使用方法
```sh
cd hw1_DES && make
cd bin
./des
```

## 文件结构
```
hw1_DES
    |
    --- README.md
    |
    --- include
    |   |
    |   --- bits_operation.h
    |   |
    |   --- des.h
    |
    --- src
    |   |
    |   --- bits_operation.c
    |   |
    |   --- des.c
    |   |
    |   --- main.c
    |
    --- bin
        |
        ---des
```

## 主要函数的调用关系
```c
main()
    |
    --- generate_key()
    |
    --- des_encrypt()
    |   |
    |   --- _des_process(DES_ENCRYPT)
    |       |
    |       --- do_permutation(&PERM_IP)
    |       |
    |       --- do_iter_and_switch()
    |       |   |
    |       |   --- gernerate_subkey()
    |       |   |
    |       |   --- feistel()
    |       |
    |       --- do_permutation(&PERM_IPINV)
    |       
    --- des_decrypt()
        |
        --- _des_process(DES_DECRYPT)

```

## 文件内容
**各个函数的使用方法都在头文件有清楚的注释，此处不再重复放代码**  
-  bit_operation.h/c 本项目使用的是 **uint64_t** 来储存一个64位的块（值得注意的是，该库的实现是将64位无符号整数的最右边的位置当作第一位，符合我们对2进制整数的认识）。该文件实现了直接对一个 uint64_t 进行 get_bit()，set_bit()，循环移位，uint64_t 和 char[8]之间转换的函数。
- des.h/c 该文件实现了所有DES算法所用到的操作。
- main.c 该文件使用了DES算法

## 测试
### 使用自己写的函数，使用随机生成的密钥进行加密解密，主函数如下所示：
```c
#include <stdio.h>
#include "des.h"
 
int main(int argc,char **argv) {
    char key[9], buffer[1000];;
    key[8] = 0;
    generate_key(key);
    char * text = "Hello, world!";
    des_encrypt(text, buffer, key);
    des_decrypt(buffer, buffer, key);
    fprintf(stdout, "%s\n", buffer);
} 
```
结果如下所示：
```sh
[luowle@VM_0_4_centos hw1_DES]$ ./bin/des 
Hello, world!
```

### 使用 openssl 验证。方法：使用 openssl 进行加密，再用自己写的版本进行解密。
由于加密解密是对应的，上一步已经验证了自己写的库可以解密自己加密的密文。如果自己写的解密函数可以解密 openssl 加密的密文，就可以说明自己写的加密函数也是正确的。主函数如下所示：
```c
int main(int argc,char **argv) {
    char key[9], buffer[1000];;
    key[8] = 0;
    for (int i = 0; i < 4; ++i) {
        key[i] = 0xe0;
    }
    for (int i = 4; i < 8; ++i) {
        key[i] = 0xf1;
    }

    FILE *fp_c = NULL;
    fp_c = fopen("/home/luowle/homework/InformationSecurity/hw1_DES/test/ciphertext", "r"); 
    fscanf(fp_c, "%s", buffer);

    des_decrypt(buffer, buffer, key);
    fprintf(stdout, "%s", buffer);
    fclose(fp_c);
} 
```
结果如下所示，**可以看见自己写的解密函数可以解密密文。因此该库的正确性是可以保证的**。

```sh
# 需要加密的密文内容
[luowle@VM_0_4_centos test]$ cat input 
Hello, world!
# 使用 openssl加密
[luowle@VM_0_4_centos test]$ openssl enc -des-ecb -K e0e0e0e0f1f1f1f1 -in input -out ciphertext
# 使用自己写的程序解密
[luowle@VM_0_4_centos test]$ ./../bin/des 
Hello, world!
```

## 修改主函数使其可以对文件加密解密
操作如下所示  
没有密钥，先随机产生一个密钥：key，加密解密是正常的
```sh
[luowle@VM_0_4_centos final]$ ls -l
total 8
-rw-rw-r-- 1 luowle luowle 24 Sep 30 01:42 final_test
-rw-rw-r-- 1 luowle luowle 14 Sep 30 01:42 hello_test
# 查看明文内容
[luowle@VM_0_4_centos final]$ cat hello_test 
Hello, world!
# 随机生成一个密钥：key 进行加密
[luowle@VM_0_4_centos final]$ ./../bin/des e hello_test - encrypt_hello
# cat查看密文内容
[luowle@VM_0_4_centos final]$ cat encrypt_hello 
<AvQ[luowle@VM_0_4_centos fina
# 使用刚刚生成的密钥解密
[luowle@VM_0_4_centos final]$ ./../bin/des d encrypt_hello key decrypt_hello
# 查看解密后的明文
[luowle@VM_0_4_centos final]$ cat decrypt_hello 
Hello, world!
[luowle@VM_0_4_centos final]$ ls -l
total 20
-rw-rw-r-- 1 luowle luowle 14 Sep 30 01:54 decrypt_hello
-rw-rw-r-- 1 luowle luowle 16 Sep 30 01:53 encrypt_hello
-rw-rw-r-- 1 luowle luowle 24 Sep 30 01:42 final_test
-rw-rw-r-- 1 luowle luowle 14 Sep 30 01:42 hello_test
-rw-rw-r-- 1 luowle luowle  8 Sep 30 01:53 key
```
使用刚刚生成的密钥进行加密解密
```sh
[luowle@VM_0_4_centos final]$ ls -l
total 20
-rw-rw-r-- 1 luowle luowle 14 Sep 30 01:54 decrypt_hello
-rw-rw-r-- 1 luowle luowle 16 Sep 30 01:53 encrypt_hello
-rw-rw-r-- 1 luowle luowle 24 Sep 30 01:42 final_test
-rw-rw-r-- 1 luowle luowle 14 Sep 30 01:42 hello_test
-rw-rw-r-- 1 luowle luowle  8 Sep 30 01:53 key
# 查看明文内容
[luowle@VM_0_4_centos final]$ cat final_test 
This is the final test!
# 使用刚刚产生的key加密
[luowle@VM_0_4_centos final]$ ./../bin/des e final_test key encrypt_test
# cat 查看密文
[luowle@VM_0_4_centos final]$ cat encrypt_test 
y-
  P(+P,͉[luowle@VM_0_4_centos final]$ 
# 使用同一个key解密
[luowle@VM_0_4_centos final]$ ./../bin/des d encrypt_test key decrypt_test
# 查看解密后的密文
[luowle@VM_0_4_centos final]$ cat decrypt_test 
This is the final test!
# key，密文等文件大小均符合DES标准
[luowle@VM_0_4_centos final]$ ls -l
total 28
-rw-rw-r-- 1 luowle luowle 14 Sep 30 01:54 decrypt_hello
-rw-rw-r-- 1 luowle luowle 24 Sep 30 01:59 decrypt_test
-rw-rw-r-- 1 luowle luowle 16 Sep 30 01:53 encrypt_hello
-rw-rw-r-- 1 luowle luowle 32 Sep 30 01:58 encrypt_test
-rw-rw-r-- 1 luowle luowle 24 Sep 30 01:42 final_test
-rw-rw-r-- 1 luowle luowle 14 Sep 30 01:42 hello_test
-rw-rw-r-- 1 luowle luowle  8 Sep 30 01:53 key
```

主函数代码如下所示
```c
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
```


