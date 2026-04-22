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
#include <thread>
#include <mutex>
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// g++ -std=c++11 vpn_server.cpp -o vpn_server -lssl -lcrypto -lpthread  
// sudo ./vpn_server

using namespace std;

#define VPN_PORT     8443
#define BUFFER_SIZE  4096
#define AES_KEY_LEN  32   // AES-256
#define AES_IV_LEN   16

SSL_CTX* ssl_ctx = nullptr;
mutex    clients_mutex;

// ==================== TUN 接口 ====================

/**
 * 创建 TUN 虚拟网卡，返回文件描述符
 */
int CreateTun(char* dev_name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;          // TUN 模式，不带协议头
    if (dev_name && dev_name[0])
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF"); close(fd); return -1;
    }
    strcpy(dev_name, ifr.ifr_name);
    return fd;
}

/**
 * 用 ip 命令配置 TUN 接口地址并启用
 * server_ip: 服务端 TUN 地址
 * client_ip: 客户端 TUN 地址（peer）
 */
void ConfigureTun(const char* dev, const char* server_ip, const char* client_ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s peer %s dev %s", server_ip, client_ip, dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", dev);
    system(cmd);
    cout << "[TUN] " << dev << " 已配置: " << server_ip << " <-> " << client_ip << endl;
}

// ==================== SSL/TLS ====================

bool InitSSL() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) return false;

    // 仅允许 TLS 1.2 及以上
    SSL_CTX_set_options(ssl_ctx,
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx,  "server.key", SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ssl_ctx)) {
        ERR_print_errors_fp(stderr);
        cerr << "证书加载失败，先生成:\n"
             << "  openssl genrsa -out server.key 2048\n"
             << "  openssl req -new -x509 -key server.key -out server.crt -days 365\n";
        return false;
    }
    cout << "[SSL] 初始化成功" << endl;
    return true;
}

// ==================== AES-256-CBC 加解密 ====================

/**
 * 加密：明文 → 密文，返回密文长度（-1 失败）
 * 注意：out_buf 至少要有 in_len + AES_BLOCK_SIZE 字节
 */
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
    if (!EVP_EncryptFinal_ex(ctx, out + len, &len)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;
}

/**
 * 解密：密文 → 明文，返回明文长度（-1 失败）
 */
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

// ==================== 客户端处理线程 ====================

void HandleClient(int sock, struct sockaddr_in addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

    // —— 1. TLS 握手 ——
    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_accept(ssl) <= 0) {
        cerr << "[TLS] 握手失败 (" << client_ip << ")" << endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl); close(sock); return;
    }
    cout << "[TLS] 握手成功: " << client_ip << endl;

    // —— 2. 身份认证 ——
    char buf[BUFFER_SIZE];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n <= 0) { SSL_free(ssl); close(sock); return; }
    buf[n] = '\0';

    string auth(buf);
    // 去除尾部换行
    while (!auth.empty() && (auth.back() == '\n' || auth.back() == '\r'))
        auth.pop_back();

    size_t sep = auth.find(':');
    if (sep == string::npos) {
        SSL_write(ssl, "AUTH_FAILED", 11);
        SSL_free(ssl); close(sock); return;
    }
    string user = auth.substr(0, sep);
    string pass = auth.substr(sep + 1);

    if (user != "vpnuser" || pass != "secure_password_123") {
        cerr << "[Auth] 认证失败: " << user << endl;
        SSL_write(ssl, "AUTH_FAILED", 11);
        SSL_free(ssl); close(sock); return;
    }
    cout << "[Auth] 认证成功: " << user << endl;
    SSL_write(ssl, "AUTH_SUCCESS", 12);

    // —— 3. 密钥协商：生成 AES 会话密钥和 IV，通过 TLS 信道发送给客户端 ——
    unsigned char session_key[AES_KEY_LEN];
    unsigned char session_iv[AES_IV_LEN];
    RAND_bytes(session_key, AES_KEY_LEN);
    RAND_bytes(session_iv,  AES_IV_LEN);

    // 先发密钥，再发 IV
    if (SSL_write(ssl, session_key, AES_KEY_LEN) <= 0 ||
        SSL_write(ssl, session_iv,  AES_IV_LEN)  <= 0) {
        cerr << "[密钥协商] 密钥发送失败" << endl;
        SSL_free(ssl); close(sock); return;
    }
    cout << "[密钥协商] 会话密钥已安全发送给客户端" << endl;

    // —— 4. 创建 TUN 接口 ——
    char tun_name[IFNAMSIZ] = "vpntun0";
    int tun_fd = CreateTun(tun_name);
    if (tun_fd < 0) { SSL_free(ssl); close(sock); return; }
    ConfigureTun(tun_name, "10.8.0.1", "10.8.0.2");

    // —— 5. 双向加密转发：TUN ↔ AES ↔ TLS ↔ 网络 ——
    cout << "[VPN] 开始加密转发 (" << client_ip << ")" << endl;

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

            // 帧格式: [4字节长度][加密数据]
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

    cout << "[VPN] 客户端断开: " << client_ip << endl;
    close(tun_fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
}

// ==================== 主程序 ====================

int main() {
    cout << "====== VPN 服务器 (TLS + AES-256) ======\n" << endl;

    if (!InitSSL()) return 1;

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(VPN_PORT);
    sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("bind"); return 1;
    }
    listen(server_sock, 10);
    cout << "[服务器] 监听端口 " << VPN_PORT << " ..." << endl;

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) { perror("accept"); continue; }

        thread(HandleClient, client_sock, client_addr).detach();
    }

    close(server_sock);
    SSL_CTX_free(ssl_ctx);
    return 0;
}
