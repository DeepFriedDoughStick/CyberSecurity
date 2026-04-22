#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

// g++ -std=c++11 vpn_client.cpp -o vpn_client -lssl -lcrypto -lpthread
// sudo ./vpn_client <服务器IP> (127.0.0.1)
// ping 10.8.0.1 测试

using namespace std;

#define VPN_PORT    8443
#define BUFFER_SIZE 4096
#define AES_KEY_LEN 32
#define AES_IV_LEN  16

// ==================== TUN 接口（与服务端相同）====================

int CreateTun(char* dev_name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (dev_name && dev_name[0])
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF"); close(fd); return -1;
    }
    strcpy(dev_name, ifr.ifr_name);
    return fd;
}

void ConfigureTun(const char* dev, const char* client_ip, const char* server_ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s peer %s dev %s", client_ip, server_ip, dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", dev);
    system(cmd);
    // 把所有流量路由到 VPN 隧道
    // 在单机测试时，必须把下面这两行注释掉！否则会路由环路，导致连接断开
    // snprintf(cmd, sizeof(cmd), "ip route add default via %s dev %s", server_ip, dev);
    // system(cmd);
    cout << "[TUN] " << dev << " 已配置: " << client_ip << " <-> " << server_ip << endl;
}

// ==================== AES-256-CBC ====================

int AesEncrypt(const unsigned char* in, int in_len,
               const unsigned char* key, const unsigned char* iv,
               unsigned char* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) ||
        !EVP_EncryptUpdate(ctx, out, &len, in, in_len)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    total = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;
}

int AesDecrypt(const unsigned char* in, int in_len,
               const unsigned char* key, const unsigned char* iv,
               unsigned char* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) ||
        !EVP_DecryptUpdate(ctx, out, &len, in, in_len)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    total = len;
    if (!EVP_DecryptFinal_ex(ctx, out + len, &len)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;
}

// ==================== 主程序 ====================

int main(int argc, char* argv[]) {
    const char* server_ip = (argc > 1) ? argv[1] : "127.0.0.1";
    cout << "====== VPN 客户端 ======" << endl;
    cout << "连接服务器: " << server_ip << ":" << VPN_PORT << endl;

    // —— 1. 初始化 SSL ——
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    // 测试环境跳过证书验证；生产环境应改为 SSL_VERIFY_PEER 并加载 CA 证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    // —— 2. TCP 连接 ——
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(VPN_PORT);
    inet_pton(AF_INET, server_ip, &sa.sin_addr);

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect"); return 1;
    }

    // —— 3. TLS 握手 ——
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        cerr << "[TLS] 握手失败" << endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }
    cout << "[TLS] 握手成功，加密算法: " << SSL_get_cipher(ssl) << endl;

    // —— 4. 身份认证 ——
    string auth = "vpnuser:secure_password_123";
    SSL_write(ssl, auth.c_str(), auth.length());

    char resp[16] = {0};
    SSL_read(ssl, resp, 12);
    resp[12] = '\0';
    if (string(resp) != "AUTH_SUCCESS") {
        cerr << "[Auth] 认证失败: " << resp << endl;
        SSL_free(ssl); close(sock); return 1;
    }
    cout << "[Auth] 认证成功" << endl;

    // —— 5. 接收服务端发来的会话密钥和 IV（密钥协商）——
    unsigned char session_key[AES_KEY_LEN];
    unsigned char session_iv[AES_IV_LEN];

    if (SSL_read(ssl, session_key, AES_KEY_LEN) <= 0 ||
        SSL_read(ssl, session_iv,  AES_IV_LEN)  <= 0) {
        cerr << "[密钥协商] 接收密钥失败" << endl;
        return 1;
    }
    cout << "[密钥协商] 会话密钥接收成功" << endl;

    // —— 6. 创建 TUN 接口 ——
    char tun_name[IFNAMSIZ] = "vpntun1";
    int tun_fd = CreateTun(tun_name);
    if (tun_fd < 0) return 1;
    ConfigureTun(tun_name, "10.8.0.2", "10.8.0.1");

    // —— 7. 双向加密转发 ——
    cout << "[VPN] 隧道已建立，开始转发流量..." << endl;

    unsigned char plain[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char cipher[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    while (true) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(tun_fd, &fds);
        FD_SET(sock,   &fds);
        int max_fd = max(tun_fd, sock) + 1;

        if (select(max_fd, &fds, nullptr, nullptr, nullptr) < 0) break;

        // ── TUN → 加密 → SSL ──
        if (FD_ISSET(tun_fd, &fds)) {
            int pkt_len = read(tun_fd, plain, BUFFER_SIZE);
            if (pkt_len <= 0) break;

            int enc_len = AesEncrypt(plain, pkt_len, session_key, session_iv, cipher);
            if (enc_len < 0) continue;

            uint32_t net_len = htonl((uint32_t)enc_len);
            SSL_write(ssl, &net_len, 4);
            SSL_write(ssl, cipher,  enc_len);
        }

        // ── SSL → 解密 → TUN ──
        if (FD_ISSET(sock, &fds)) {
            uint32_t net_len = 0;
            if (SSL_read(ssl, &net_len, 4) <= 0) break;
            int enc_len = (int)ntohl(net_len);
            if (enc_len <= 0 || enc_len > (int)sizeof(cipher)) break;

            if (SSL_read(ssl, cipher, enc_len) <= 0) break;

            int pkt_len = AesDecrypt(cipher, enc_len, session_key, session_iv, plain);
            if (pkt_len > 0)
                write(tun_fd, plain, pkt_len);
        }
    }

    cout << "[VPN] 连接断开" << endl;
    close(tun_fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}
