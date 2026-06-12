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
#include <openssl/x509.h>

// g++ -std=c++17 vpn_client.cpp -o vpn_client -lssl -lcrypto -lpthread
// sudo ./vpn_client <服务器IP> (127.0.0.1)
// ping 10.8.0.1 测试

using namespace std;

#define VPN_PORT    8443
#define BUFFER_SIZE 4096

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
    // 用 /24 子网地址配置（而非点对点 peer），这样会自动生成 10.8.0.0/24 dev 路由，
    // 客户端不仅能到达服务端，还能到达同子网内的其他客户端（依赖服务端 ip_forward）。
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", client_ip, dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", dev);
    system(cmd);
    // 把所有流量路由到 VPN 隧道
    // 在单机测试时，必须把下面这两行注释掉！否则会路由环路，导致连接断开
    // snprintf(cmd, sizeof(cmd), "ip route add default via %s dev %s", server_ip, dev);
    // system(cmd);
    cout << "[TUN] " << dev << " 已配置: " << client_ip << "/24 (网关 " << server_ip << ")" << endl;
}

// ==================== 工具函数 ====================
// 不再使用应用层 AES：TLS（SSL_read/SSL_write）已负责机密性与完整性，
// 隧道内直接传输原始 IP 包，外层 TLS 即为唯一加密层。

/**
 * 从 SSL 连接中读取「恰好」len 字节，避免 TLS 分段导致的帧错位
 * 返回 true 表示读满，false 表示连接断开或出错
 */
bool SSL_read_full(SSL* ssl, void* bufp, int len) {
    int got = 0;
    unsigned char* p = static_cast<unsigned char*>(bufp);
    while (got < len) {
        int n = SSL_read(ssl, p + got, len - got);
        if (n <= 0) return false;
        got += n;
    }
    return true;
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
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    // 校验服务器身份：把服务端自签证书 server.crt 作为受信任的 CA 加载，
    // 并开启 SSL_VERIFY_PEER，防止中间人攻击（替代原先不安全的 VERIFY_NONE）
    if (SSL_CTX_load_verify_locations(ctx, "server.crt", nullptr) != 1) {
        cerr << "[SSL] 加载受信任证书 server.crt 失败" << endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

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
    // 复核证书校验结果（SSL_VERIFY_PEER 下握手失败一般已返回，这里再确认一次）
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        cerr << "[TLS] 服务器证书校验失败" << endl;
        SSL_free(ssl); close(sock); return 1;
    }
    cout << "[TLS] 握手成功，加密算法: " << SSL_get_cipher(ssl) << endl;

    // —— 4. 身份认证 ——
    string auth = "vpnuser:secure_password_123";
    SSL_write(ssl, auth.c_str(), auth.length());

    // 接收认证结果与服务端分配的虚拟 IP，格式："OK <ip>\n" 或 "FAIL\n"
    char resp[64] = {0};
    int rn = SSL_read(ssl, resp, sizeof(resp) - 1);
    if (rn <= 0) {
        cerr << "[Auth] 未收到服务器响应" << endl;
        SSL_free(ssl); close(sock); return 1;
    }
    resp[rn] = '\0';
    string r(resp);
    while (!r.empty() && (r.back() == '\n' || r.back() == '\r')) r.pop_back();
    if (r.rfind("OK ", 0) != 0) {
        cerr << "[Auth] 认证失败: " << r << endl;
        SSL_free(ssl); close(sock); return 1;
    }
    string vip = r.substr(3);   // 服务端分配的虚拟 IP（密钥协商已由 TLS 握手完成）
    cout << "[Auth] 认证成功，分配虚拟IP: " << vip << endl;

    // —— 5. 创建并配置 TUN 接口（使用服务端分配的虚拟 IP）——
    char tun_name[IFNAMSIZ] = "vpntun1";
    int tun_fd = CreateTun(tun_name);
    if (tun_fd < 0) return 1;
    ConfigureTun(tun_name, vip.c_str(), "10.8.0.1");

    // —— 6. 双向转发（数据通道直接走 TLS，机密性与完整性由 TLS 保证）——
    cout << "[VPN] 隧道已建立，开始转发流量..." << endl;

    unsigned char pkt[BUFFER_SIZE];

    while (true) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(tun_fd, &fds);
        FD_SET(sock,   &fds);
        int max_fd = max(tun_fd, sock) + 1;

        if (select(max_fd, &fds, nullptr, nullptr, nullptr) < 0) break;

        // ── TUN → TLS：读取本机 IP 包，按 [4字节长度][数据] 发送 ──
        if (FD_ISSET(tun_fd, &fds)) {
            int len = read(tun_fd, pkt, sizeof(pkt));
            if (len <= 0) break;

            uint32_t net_len = htonl((uint32_t)len);
            if (SSL_write(ssl, &net_len, 4) <= 0) break;
            if (SSL_write(ssl, pkt, len) <= 0) break;
        }

        // ── TLS → TUN：读满长度头与数据，写回 TUN ──
        if (FD_ISSET(sock, &fds)) {
            uint32_t net_len = 0;
            if (!SSL_read_full(ssl, &net_len, 4)) break;
            int len = (int)ntohl(net_len);
            if (len <= 0 || len > (int)sizeof(pkt)) break;
            if (!SSL_read_full(ssl, pkt, len)) break;

            if (write(tun_fd, pkt, len) < 0) break;
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
