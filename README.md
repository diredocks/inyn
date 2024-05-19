# Inyn - I am not your node

现代新华三 802.1x 认证客户端

---
## 编译

安装 `cmake`、`libpcap`、`openssl`

```bash
mkdir build && cd build
cmake ../src
cmake --build .
```

产物为 `build/client`

## 待办

- 使用 C++ 重构
- 提供 openwrt 打包
- 完善文档

## 致谢
感谢所有研究认证协议的大侠们。