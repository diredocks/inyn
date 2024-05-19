/* File:
 * ---------------
 * 调用openssl提供的MD5函数
 */

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

void CalculateMD5(const uint8_t *input, size_t length, uint8_t output[16]) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        // 处理错误
        fprintf(stderr, "Failed to create MD context\n");
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
        // 处理错误
        fprintf(stderr, "Failed to initialize MD context\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestUpdate(mdctx, input, length) != 1) {
        // 处理错误
        fprintf(stderr, "Failed to update MD context\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    unsigned int digest_len;
    if (EVP_DigestFinal_ex(mdctx, output, &digest_len) != 1) {
        // 处理错误
        fprintf(stderr, "Failed to finalize MD context\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);
    assert(digest_len == 16); // MD5 产生一个16字节（128位）的哈希值
}


void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[])
{
    uint8_t msgbuf[128]; // msgbuf = 'id' + 'passwd' + 'srcMD5'
    size_t msglen;
    size_t passlen;
    EVP_MD_CTX *mdctx;
    
    passlen = strlen(passwd);
    msglen = 1 + passlen + 16;
    assert(sizeof(msgbuf) >= msglen);

    msgbuf[0] = id;
    memcpy(msgbuf + 1, passwd, passlen);
    memcpy(msgbuf + 1 + passlen, srcMD5, 16);

	CalculateMD5(msgbuf, msglen, digest);
}