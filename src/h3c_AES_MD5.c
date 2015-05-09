#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes.h"
#include "h3c_dict.h"
#include "md5.h"
#include "h3c_AES_MD5.h"

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
	get_sig(*(unsigned long *)tmp0, *(tmp0 + 4), length_1, sig);
	MD5Calc(sig, length_1, tmp2);

	AES128_CBC_decrypt_buffer(tmp3, tmp0+16, 16, tmp2, iv2);

	memcpy(decrypt_data + 16, tmp3, 16);

	length_2 = *(tmp3 + 15);
	get_sig(*(unsigned long *)(tmp3 + 10), *(tmp3 + 14), length_2, sig + length_1);
	if (length_1 + length_2>32)
	{
		memcpy(decrypt_data, sig, 32);
	}
	else
	{
		memcpy(decrypt_data, sig, length_1 + length_2);
	}
	MD5Calc(decrypt_data, 32, decrypt_data);//获取MD5摘要数据，将结果存到前16位中
	MD5Calc(decrypt_data, 16, decrypt_data + 16);//将前一MD5的结果再做一次MD5，存到后16位
	return 0;
}


// 查找表函数，根据索引值、偏移量以及长度查找序列
char* get_sig(unsigned long index, int offset, int length, unsigned char* dst)
{
	const unsigned char *base_address;
	switch (index)
	{
	case 0xa31acc57:base_address = x57cc1aa3; break;
	case 0xa9c5ca51:base_address = x51cac5a9; break;
	case 0x1b9ded4e:base_address = x4eed9d1b; break;
	case 0xeac0d553:base_address = x53d5c0ea; break;
	case 0xde27624b:base_address = x4b6227de; break;
	case 0x0d339d44:base_address = x449d330d; break;
	case 0x5ee76142:base_address = x4261e75e; break;
	case 0x4c5c6847:base_address = x47685c4c; break;
	case 0xd568394d:base_address = x4d3968d5; break;
	case 0xe74da312:base_address = x12a34de7; break;
	case 0x1bb3380b:base_address = x0b38b31b; break;
	case 0x2e101d17:base_address = x171d102e; break;
	case 0xc331f521:base_address = x21f531c3; break;
	case 0x3480121d:base_address = x1d128034; break;
	case 0x6ff7212d:base_address = x2d21f76f; break;
	case 0x245e532b:base_address = x2b535e24; break;
	case 0x3d8f6927:base_address = x27698f3d; break;
	case 0xd3472c2c:base_address = x2c2c47d3; break;
	case 0xe08ef131:base_address = x31f18ee0; break;
	case 0x0be96260:base_address = x6062e90b; break;
	case 0x164017ec:base_address = xec174016; break;
	case 0x422356e9:base_address = xe9562342; break;
	case 0xb9b151e0:base_address = xe051b1b9; break;
	case 0x63f534f6:base_address = xf634f563; break;
	case 0x7c23d097:base_address = x97d0237c; break;
	case 0xae7c5e72:base_address = x725e7cae; break;
	case 0x71a17c99:base_address = x997ca171; break;
	case 0x91e463a7:base_address = xa763e491; break;
	case 0x079255a3:base_address = xa3559207; break;
	case 0xc7c4f69c:base_address = x9cf6c4c7; break;
	case 0x830d87dd:base_address = xdd870d83; break;
	case 0x908b026c:base_address = x6c028b90; break;
	case 0x93180268:base_address = x68021893; break;
	case 0x5511cb67:base_address = x67cb1155; break;
	case 0x5d90086b:base_address = x6b08905d; break;
	case 0xf4a21c72:base_address = x721ca2f4; break;
	default:
		return 0; break;
	}
	memcpy(dst, base_address + offset, length);
	return dst;
}