#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

#include "aes.h"
#include "h3c_dict.h"
#include "h3c_AES_MD5.h"

/* 大小端问题 */
//大小端检测，如果 ENDIANNESS=='l' 则为小端
static union { char c[4]; unsigned long mylong; } endian_test = {{ 'l', '?', '?', 'b' } }; 
#define ENDIANNESS ((char)endian_test.mylong)
//大小端转换
#define BigLittleSwap32(A) ((((uint32_t)(A)&0xff000000)>>24)|\
	(((uint32_t)(A)&0x00ff0000)>>8)|\
	(((uint32_t)(A)&0x0000ff00)<<8)|\
	(((uint32_t)(A)&0x000000ff)<<24))
//void main()
//{
//	test();
//}

int test() {
	unsigned char encrypt_data[32] = { 0xcf, 0xfe, 0x64, 0x73, 0xd5, 0x73, 0x3b, 0x1f, 0x9e, 0x9a, 0xee, 0x1a, 0x6b, 0x76, 0x47, 0xc8, 0x9e, 0x27, 0xc8, 0x92, 0x25, 0x78, 0xc4, 0xc8, 0x27, 0x03, 0x34, 0x50, 0xb6, 0x10, 0xb8, 0x35 };
	unsigned char decrypt_data[32];
	unsigned char i;

	// decrypt
	h3c_AES_MD5_decryption(decrypt_data, encrypt_data);

	// print
	printf("encrypted string = ");
	for (i = 0; i<32; ++i) {
		printf("%x%x", ((int)encrypt_data[i] >> 4) & 0xf,
			(int)encrypt_data[i] & 0xf);
	}
	printf("\n");
	printf("decrypted string = ");
	for (i = 0; i<32; ++i) {
		printf("%x%x", ((int)decrypt_data[i] >> 4) & 0xf,
			(int)decrypt_data[i] & 0xf);
	}
	// the decrypt_data should be 8719362833108a6e16b08e33943601542511372d8d1fb1ab31aa17059118a6ba
	getchar();
	return 0;
}

void CalculateMD5(const uint8_t *input, size_t length, uint8_t output[16]);

//参考 h3c_AES_MD5.md 文档中对算法的说明
int h3c_AES_MD5_decryption(unsigned char *decrypt_data, unsigned char *encrypt_data)
{
	const unsigned char key[16] = { 0xEC, 0xD4, 0x4F, 0x7B, 0xC6, 0xDD, 0x7D, 0xDE, 0x2B, 0x7B, 0x51, 0xAB, 0x4A, 0x6F, 0x5A, 0x22 };        // AES_BLOCK_SIZE = 16
	unsigned char iv1[16] = { 'a', '@', '4', 'd', 'e', '%', '#', '1', 'a', 's', 'd', 'f', 's', 'd', '2', '4' };        // init vector
	unsigned char iv2[16] = { 'a', '@', '4', 'd', 'e', '%', '#', '1', 'a', 's', 'd', 'f', 's', 'd', '2', '4' }; //每次加密、解密后，IV会被改变！因此需要两组IV完成两次“独立的”解密
	unsigned int length_1;
	unsigned int length_2;
	unsigned char tmp0[32];
	unsigned char sig[255];
	unsigned char tmp2[16];
	unsigned char tmp3[16];
	// decrypt
	AES128_CBC_decrypt_buffer(tmp0, encrypt_data, 32, key, iv1);
	memcpy(decrypt_data, tmp0, 16);
	length_1 = *(tmp0 + 5);
	get_sig(*(uint32_t *)tmp0, *(tmp0 + 4), length_1, sig);
	CalculateMD5(sig, length_1, tmp2);

	AES128_CBC_decrypt_buffer(tmp3, tmp0+16, 16, tmp2, iv2);

	memcpy(decrypt_data + 16, tmp3, 16);

	length_2 = *(tmp3 + 15);
	get_sig(*(uint32_t *)(tmp3 + 10), *(tmp3 + 14), length_2, sig + length_1);
	if (length_1 + length_2>32)
	{
		memcpy(decrypt_data, sig, 32);
	}
	else
	{
		memcpy(decrypt_data, sig, length_1 + length_2);
	}
	CalculateMD5(decrypt_data, 32, decrypt_data);//获取MD5摘要数据，将结果存到前16位中
	CalculateMD5(decrypt_data, 16, decrypt_data + 16);//将前一MD5的结果再做一次MD5，存到后16位
	return 0;
}


// 查找表函数，根据索引值、偏移量以及长度查找序列
char* get_sig(uint32_t index, int offset, int length, unsigned char* dst)
{
	uint32_t index_tmp;
	const unsigned char *base_address;
	// printf("index = %x\n" ,index);
	
	if (ENDIANNESS == 'l')
	{
		index_tmp = BigLittleSwap32(index); // 小端情况，如PC架构
	}
	else
	{
		index_tmp = index; // 大端序，如MIPS架构
	}
	switch (index_tmp) // this line works in mips.
	{
	case 0x0BE169DA:base_address = x0BE169DA; break;
	case 0x077AED1F:base_address = x077AED1F; break;
	case 0x1A5776C9:base_address = x1A5776C9; break;
	case 0x22E05E21:base_address = x22E05E21; break;
	case 0x22D5BBE5:base_address = x22D5BBE5; break;
	case 0x2C58D42D:base_address = x2C58D42D; break;
	case 0x36F158CE:base_address = x36F158CE; break;
	case 0x3367942B:base_address = x3367942B; break;
	case 0x31A46D27:base_address = x31A46D27; break;
	case 0x354E4205:base_address = x354E4205; break;
	case 0x3F131A4E:base_address = x3F131A4E; break;
	case 0x65C64E05:base_address = x65C64E05; break;
	case 0x63355D54:base_address = x63355D54; break;
	case 0x5BC95547:base_address = x5BC95547; break;
	case 0x6555D892:base_address = x6555D892; break;
	case 0x55AB5F34:base_address = x55AB5F34; break;
	case 0x44F73BB5:base_address = x44F73BB5; break;
	case 0x414E793A:base_address = x414E793A; break;
	case 0x4C37ADF3:base_address = x4C37ADF3; break;
	case 0x58DD8873:base_address = x58DD8873; break;
	case 0x6FB7795F:base_address = x6FB7795F; break;
	case 0x7EABA88E:base_address = x7EABA88E; break;
	case 0x76F63D02:base_address = x76F63D02; break;
	case 0x72B2F727:base_address = x72B2F727; break;
	case 0x7243D3A3:base_address = x7243D3A3; break;
	case 0x72D78AB9:base_address = x72D78AB9; break;
	case 0x7EF5ADA7:base_address = x7EF5ADA7; break;
	case 0xAC40ED9D:base_address = xAC40ED9D; break;
	case 0xAC2DCCD3:base_address = xAC2DCCD3; break;
	case 0x8F52F955:base_address = x8F52F955; break;
	case 0x7F9773C0:base_address = x7F9773C0; break;
	case 0xA97617A6:base_address = xA97617A6; break;
	case 0xF435CA94:base_address = xF435CA94; break;
	case 0xAC12139E:base_address = xAC12139E; break;
	case 0xB7A23044:base_address = xB7A23044; break;
	case 0xF94BD0C3:base_address = xF94BD0C3; break;
	case 0xDBDB6398:base_address = xDBDB6398; break;
	case 0xC6AD7541:base_address = xC6AD7541; break;
	case 0xC0F90B5C:base_address = xC0F90B5C; break;
	case 0xE813C036:base_address = xE813C036; break;
	default:
		printf("lookup dict failed.\n"); // 查表失败
		base_address = xE813C036;
		break;
	}
	memcpy(dst, base_address + offset, length);
	return dst;
}
