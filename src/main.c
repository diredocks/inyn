/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

/* 子函数声明 */
int Authentication(const char *UserName, const char *Password, const char *DeviceName, const char *Version, const char *Key);
void convert(char *dest, char const *src);

/**
 * 函数：main()
 *
 * 检查程序的执行权限，检查命令行参数格式。
 * 允许的调用格式包括：
 * 	njit-client  username  password
 * 	njit-client  username  password  eth0
 * 	njit-client  username  password  eth1
 * 若没有从命令行指定网卡，则默认将使用eth0
 */
int main(int argc, char *argv[])
{
	char *UserName;
	char *Password;
	char *DeviceName;
	char *Version;
	char *Key;


	/* 检查命令行参数格式 */
	if (argc<3 || argc>6 || getuid() != 0) {
		fprintf(stderr, "Usage: %s [USERNAME] [PASSWORD]... [DEVICE] [CLIENT-VERSION] [KEY]\n", argv[0]);
    fprintf(stderr, "\nRoot privilege is needed to capture network frames\n");
		fprintf(stderr, "If no device given, 'enp1s0' would be the default\n");
    fprintf(stderr, "When typing client veriosn with hex character, please do it with \"[CLIENT-VERSION]\"\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "%s 123404@cucc 123456 eth0 \"CH\\x11V7.10-0213\" Oly5D62FaE94W7\n", argv[0]);
    fprintf(stderr, "\nVisit https://github.com/diredocks/inyn for help or contribution\n");
		exit(-1);
	} else {
		if (argc > 3) {
			DeviceName = argv[3]; // 允许从命令行指定设备名
		} else {
			DeviceName = "enp1s0"; // 缺省情况下使用的设备
		}
		if (argc > 5) {
			Version = (char *)malloc(32 * sizeof(char));
			convert(Version, argv[4]);
      printf("%s\n", Version);
      printf("%d\n", strcmp(Version, "CH\x11V7.30-0601"));
      exit(1);
			Key = argv[5];
		} else {
			Version = "CH\x11V7.30-0601";
			Key = "Oly5D62FaE94W7";
		}
	}
	UserName = argv[1];
	Password = argv[2];

	/* 调用子函数完成802.1X认证 */
	Authentication(UserName, Password, DeviceName, Version, Key);

	return (0);
}

// 处理并转换输入字符串中的十六进制转义序列
void convert(char *dest, const char *src) {
    int srcIndex = 0, destIndex = 0;
    int srcLength = strlen(src);

    while (srcIndex < srcLength) {
        // 检查是否有十六进制转义序列
        if (src[srcIndex] == '\\' && srcIndex + 3 < srcLength && src[srcIndex + 1] == 'x') {
            // 提取十六进制转义序列
            char hexSequence[3];
            hexSequence[0] = src[srcIndex + 2];
            hexSequence[1] = src[srcIndex + 3];
            hexSequence[2] = '\0';

            // 将十六进制转义序列转换为字符并复制到dest中
            unsigned char convertedChar;
            sscanf(hexSequence, "%hhx", &convertedChar);
            dest[destIndex++] = convertedChar;
            srcIndex += 4; // 跳过转义序列
        } else {
            // 普通字符直接复制到dest中
            dest[destIndex++] = src[srcIndex++];
        }
    }
    dest[destIndex] = '\0'; // 添加字符串结束符
}
