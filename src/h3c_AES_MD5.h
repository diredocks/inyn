#ifndef h3c_AES_MD5_
#define h3c_AES_MD5_
int h3c_AES_MD5_decryption(unsigned char *decrypt_data, unsigned char *encrypt_data);
int test();
char* get_sig(unsigned long index, int offset, int length, unsigned char* dst);
#endif