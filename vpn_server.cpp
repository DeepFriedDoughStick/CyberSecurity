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
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "ClientSession.h"
#include "ClientManager.h"
#include <shared_mutex>
#include <random>
#include <iomanip>

// g++ -std=c++11 vpn_server.cpp -o vpn_server -lssl -lcrypto -lpthread
// sudo ./vpn_server
ClientSession::ClientSession(int fd, const std::string &client_ip, int client_port)
    : m_socket_fd(fd), m_state(ClientState::HANDSHAKING)
{

    m_info.real_ip = client_ip;
    m_info.real_port = client_port;
    m_info.connect_time = std::chrono::system_clock::now();
    m_info.last_activity = m_info.connect_time;
    m_info.bytes_sent = 0;
    m_info.bytes_received = 0;
    m_info.session_id = "";
    m_info.username = "";
    m_info.virtual_ip = "";
}
ClientSession::~ClientSession()
{
    close();
}
void ClientSession::setState(ClientState state)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state = state;
}
ClientState ClientSession::getState() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state;
}
bool ClientSession::isAlive() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state != ClientState::DISCONNECTED && m_socket_fd != -1;
}
void ClientSession::updateActivity()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_info.last_activity = std::chrono::system_clock::now();
}
bool ClientSession::isTimeout(int timeout_seconds) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_info.last_activity);
    return elapsed.count() > timeout_seconds;
}
void ClientSession::close()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_socket_fd != -1)
    {
        ::close(m_socket_fd);
        m_socket_fd = -1;
    }
    m_state = ClientState::DISCONNECTED;
}

ClientManager::ClientManager()
    : m_ip_network("10.8.0"), m_ip_start(2), m_ip_end(254)
{

    m_stats.total_connections = 0;
    m_stats.active_connections = 0;
    m_stats.total_bytes_sent = 0;
    m_stats.total_bytes_received = 0;
    m_stats.start_time = std::chrono::system_clock::now();
}
ClientManager::~ClientManager()
{
    // 断开所有客户端
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    for (auto &pair : m_clients)
    {
        pair.second->close();
    }
    m_clients.clear();
    m_ip_map.clear();
    m_username_map.clear();
}
bool ClientManager::addClient(int fd, const std::string &ip, int port)
{
    auto session = std::make_shared<ClientSession>(fd, ip, port);

    std::unique_lock<std::shared_mutex> lock(m_mutex);

    // 检查是否已存在
    if (m_clients.find(fd) != m_clients.end())
    {
        return false;
    }

    // 生成会话ID
    session->setSessionId(generateSessionId());

    // 添加到映射表
    m_clients[fd] = session;

    lock.unlock();

    updateStatsOnConnect();

    // 触发回调
    if (m_on_connect_cb)
    {
        m_on_connect_cb(session);
    }

    return true;
}
bool ClientManager::removeClient(int fd)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    auto it = m_clients.find(fd);
    if (it == m_clients.end())
    {
        return false;
    }

    auto session = it->second;

    // 从所有映射表中移除
    if (!session->getInfo().virtual_ip.empty())
    {
        m_ip_map.erase(session->getInfo().virtual_ip);
        releaseVirtualIP(session->getInfo().virtual_ip);
    }

    if (!session->getInfo().username.empty())
    {
        m_username_map.erase(session->getInfo().username);
    }

    m_clients.erase(it);

    lock.unlock();

    updateStatsOnDisconnect(session);

    // 触发回调
    if (m_on_disconnect_cb)
    {
        m_on_disconnect_cb(session);
    }

    // 关闭连接
    session->close();

    return true;
}
bool ClientManager::removeClientByIP(const std::string &virtual_ip)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    auto it = m_ip_map.find(virtual_ip);
    if (it == m_ip_map.end())
    {
        return false;
    }

    int fd = it->second->getSocketFd();
    lock.unlock();

    return removeClient(fd);
}
ClientManager::SessionPtr ClientManager::getClient(int fd)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    auto it = m_clients.find(fd);
    if (it != m_clients.end())
    {
        return it->second;
    }
    return nullptr;
}
ClientManager::SessionPtr ClientManager::getClientByIP(const std::string &virtual_ip)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    auto it = m_ip_map.find(virtual_ip);
    if (it != m_ip_map.end())
    {
        return it->second;
    }
    return nullptr;
}
ClientManager::SessionPtr ClientManager::getClientByUsername(const std::string &username)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    auto it = m_username_map.find(username);
    if (it != m_username_map.end())
    {
        return it->second;
    }
    return nullptr;
}
std::vector<ClientManager::SessionPtr> ClientManager::getAllClients()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    std::vector<SessionPtr> clients;
    clients.reserve(m_clients.size());

    for (auto &pair : m_clients)
    {
        clients.push_back(pair.second);
    }

    return clients;
}
std::vector<std::string> ClientManager::getAllVirtualIPs()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    std::vector<std::string> ips;
    ips.reserve(m_ip_map.size());

    for (auto &pair : m_ip_map)
    {
        ips.push_back(pair.first);
    }

    return ips;
}
bool ClientManager::canAcceptNewClient(int max_clients)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_clients.size() < static_cast<size_t>(max_clients);
}
int ClientManager::getClientCount() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_clients.size();
}
void ClientManager::cleanupTimeoutClients(int timeout_seconds)
{
    std::vector<int> timeout_fds;

    // 收集超时的客户端
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        for (auto &pair : m_clients)
        {
            if (pair.second->isTimeout(timeout_seconds))
            {
                timeout_fds.push_back(pair.first);
            }
        }
    }

    // 断开超时客户端
    for (int fd : timeout_fds)
    {
        auto session = getClient(fd);
        if (session && m_on_timeout_cb)
        {
            m_on_timeout_cb(session);
        }
        removeClient(fd);
    }
}
std::string ClientManager::allocateVirtualIP(const std::string &preferred_ip)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    // 如果指定了IP且未被分配，使用指定IP
    if (!preferred_ip.empty())
    {
        if (m_allocated_ips.find(preferred_ip) == m_allocated_ips.end())
        {
            m_allocated_ips.insert(preferred_ip);
            return preferred_ip;
        }
    }

    // 自动分配IP
    for (int i = m_ip_start; i <= m_ip_end; i++)
    {
        std::string ip = m_ip_network + "." + std::to_string(i);
        if (m_allocated_ips.find(ip) == m_allocated_ips.end())
        {
            m_allocated_ips.insert(ip);
            return ip;
        }
    }

    return ""; // IP池已满
}
void ClientManager::releaseVirtualIP(const std::string &ip)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_allocated_ips.erase(ip);
}
void ClientManager::broadcastToAll(const uint8_t *data, int len, int exclude_fd)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    for (auto &pair : m_clients)
    {
        if (pair.first != exclude_fd)
        {
            // 这里需要实际的发送逻辑
            // send(pair.first, data, len, 0);
        }
    }
}
ClientManager::Stats ClientManager::getStats() const
{
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    Stats stats = m_stats;
    stats.active_connections = getClientCount();
    return stats;
}
void ClientManager::setOnClientConnect(std::function<void(SessionPtr)> callback)
{
    m_on_connect_cb = callback;
}
void ClientManager::setOnClientDisconnect(std::function<void(SessionPtr)> callback)
{
    m_on_disconnect_cb = callback;
}
void ClientManager::setOnClientTimeout(std::function<void(SessionPtr)> callback)
{
    m_on_timeout_cb = callback;
}
void ClientManager::updateStatsOnConnect()
{
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    m_stats.total_connections++;
    m_stats.active_connections++;
}
void ClientManager::updateStatsOnDisconnect(const SessionPtr &session)
{
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    m_stats.active_connections--;

    if (session)
    {
        m_stats.total_bytes_sent += session->getInfo().bytes_sent;
        m_stats.total_bytes_received += session->getInfo().bytes_received;
    }
}
std::string ClientManager::generateSessionId()
{
    // 生成简单的UUID v4
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (int i = 0; i < 36; i++)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            ss << '-';
        }
        else if (i == 14)
        {
            ss << dis2(gen);
        }
        else
        {
            ss << dis(gen);
        }
    }

    return ss.str();
}
using namespace std;

#define VPN_PORT 8443
#define BUFFER_SIZE 4096
#define AES_KEY_LEN 32 // AES-256
#define AES_IV_LEN 16

SSL_CTX *ssl_ctx = nullptr;
ClientManager client_manager;

// ==================== TUN 接口 ====================

/**
 * 创建 TUN 虚拟网卡，返回文件描述符
 */
int CreateTun(char *dev_name)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        perror("open /dev/net/tun");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN 模式，不带协议头
    if (dev_name && dev_name[0])
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
    {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }
    strcpy(dev_name, ifr.ifr_name);
    return fd;
}

/**
 * 用 ip 命令配置 TUN 接口地址并启用
 * server_ip: 服务端 TUN 地址
 * client_ip: 客户端 TUN 地址（peer）
 */
void ConfigureTun(const char *dev, const char *server_ip, const char *client_ip)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s peer %s dev %s", server_ip, client_ip, dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", dev);
    system(cmd);
    cout << "[TUN] " << dev << " 已配置: " << server_ip << " <-> " << client_ip << endl;
}

// ==================== SSL/TLS ====================

bool InitSSL()
{
    OPENSSL_init_ssl(0, NULL);
    // SSL_library_init();
    // OpenSSL_add_all_algorithms();
    // SSL_load_error_strings();

    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx)
        return false;

    // 仅允许 TLS 1.2 及以上
    SSL_CTX_set_options(ssl_ctx,
                        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ssl_ctx))
    {
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
// 与客户端 vpn_client.cpp 中的实现保持一致，保证两端可以互相加解密

/**
 * AES-256-CBC 加密
 * in/in_len: 明文及其长度  key/iv: 32 字节密钥与 16 字节初始向量
 * out: 输出密文缓冲区（调用方需保证至少 in_len + EVP_MAX_BLOCK_LENGTH 大小）
 * 返回: 密文长度，失败返回 -1
 */
int AesEncrypt(const unsigned char *in, int in_len,
               const unsigned char *key, const unsigned char *iv,
               unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) ||
        !EVP_EncryptUpdate(ctx, out, &len, in, in_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len); // 处理 PKCS#7 填充
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;
}

/**
 * AES-256-CBC 解密，参数含义与 AesEncrypt 对称
 * 返回: 明文长度，失败返回 -1
 */
int AesDecrypt(const unsigned char *in, int in_len,
               const unsigned char *key, const unsigned char *iv,
               unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) ||
        !EVP_DecryptUpdate(ctx, out, &len, in, in_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total = len;
    if (!EVP_DecryptFinal_ex(ctx, out + len, &len))
    { // 校验并去除填充
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;
}

/**
 * 从 SSL 连接中读取「恰好」len 字节
 * SSL_read 单次调用可能只返回部分数据，这里循环读满，避免帧错位
 * 返回: true 表示读满，false 表示连接断开或出错
 */
bool SSL_read_full(SSL *ssl, void *buf, int len)
{
    int got = 0;
    unsigned char *p = static_cast<unsigned char *>(buf);
    while (got < len)
    {
        int n = SSL_read(ssl, p + got, len - got);
        if (n <= 0)
            return false;
        got += n;
    }
    return true;
}

// ==================== 客户端处理线程 ====================

void HandleClient(int sock, struct sockaddr_in addr)
{
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

    client_manager.addClient(sock, client_ip, ntohs(addr.sin_port));
    auto session = client_manager.getClient(sock);

    // —— 1. TLS 握手 ——
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_accept(ssl) <= 0)
    {
        cerr << "[TLS] 握手失败 (" << client_ip << ")" << endl;
        ERR_print_errors_fp(stderr);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        SSL_free(ssl);
        return;
    }
    cout << "[TLS] 握手成功: " << client_ip << endl;
    session->setState(ClientState::AUTHENTICATING);

    // —— 2. 身份认证 ——
    char buf[BUFFER_SIZE];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n <= 0)
    {
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        return;
    }
    buf[n] = '\0';

    string auth(buf);
    // 去除尾部换行
    while (!auth.empty() && (auth.back() == '\n' || auth.back() == '\r'))
        auth.pop_back();

    size_t sep = auth.find(':');
    if (sep == string::npos)
    {
        SSL_write(ssl, "AUTH_FAILED", 11);
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        return;
    }
    string user = auth.substr(0, sep);
    string pass = auth.substr(sep + 1);

    if (user != "vpnuser" || pass != "secure_password_123")
    {
        cerr << "[Auth] 认证失败: " << user << endl;
        SSL_write(ssl, "AUTH_FAILED", 11);
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        return;
    }
    cout << "[Auth] 认证成功: " << user << endl;
    SSL_write(ssl, "AUTH_SUCCESS", 12);
    session->setUsername(user);
    session->setState(ClientState::CONNECTED);

    // —— 3. 密钥协商 ——
    // 由服务端生成随机的 AES-256 会话密钥与 IV，并通过已加密的 TLS 通道下发给客户端。
    // 客户端会按「先密钥后 IV」的顺序接收（见 vpn_client.cpp 第 146~155 行）。
    unsigned char session_key[AES_KEY_LEN]; // AES-256 会话密钥（32 字节）
    unsigned char session_iv[AES_IV_LEN];   // CBC 模式初始向量（16 字节）

    if (RAND_bytes(session_key, AES_KEY_LEN) != 1 ||
        RAND_bytes(session_iv, AES_IV_LEN) != 1)
    {
        cerr << "[密钥协商] 随机密钥生成失败" << endl;
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        return;
    }
    // 顺序必须与客户端接收顺序一致：先发送密钥，再发送 IV
    if (SSL_write(ssl, session_key, AES_KEY_LEN) <= 0 ||
        SSL_write(ssl, session_iv, AES_IV_LEN) <= 0)
    {
        cerr << "[密钥协商] 密钥下发失败" << endl;
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        return;
    }
    cout << "[密钥协商] 会话密钥已下发: " << client_ip << endl;

    // —— 4. 创建并配置服务端 TUN 虚拟网卡 ——
    char tun_name[IFNAMSIZ] = "vpntun0";
    int tun_fd = CreateTun(tun_name);
    if (tun_fd < 0)
    {
        cerr << "[TUN] 创建失败" << endl;
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        return;
    }
    // 服务端虚拟 IP = 10.8.0.1，对端（客户端）= 10.8.0.2
    ConfigureTun(tun_name, "10.8.0.1", "10.8.0.2");

    // —— 5. 双向加密转发 ——
    cout << "[VPN] 开始加密转发 (" << client_ip << ")" << endl;
    unsigned char plain[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];  // 明文 IP 包缓冲
    unsigned char cipher[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH]; // 密文缓冲

    while (true)
    {
        // 用 select 同时监听 TUN 网卡与 TLS socket，任一可读即处理
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(tun_fd, &fds);
        FD_SET(sock, &fds);
        int max_fd = max(tun_fd, sock) + 1;

        if (select(max_fd, &fds, nullptr, nullptr, nullptr) < 0)
            break;

        // ── 方向一：TUN → 加密 → TLS（把本机要发给客户端的 IP 包送出去）──
        if (FD_ISSET(tun_fd, &fds))
        {
            int pkt_len = read(tun_fd, plain, BUFFER_SIZE);
            if (pkt_len <= 0)
                break;

            // 先 AES-256-CBC 加密明文 IP 包
            int enc_len = AesEncrypt(plain, pkt_len, session_key, session_iv, cipher);
            if (enc_len < 0)
                continue;

            // 帧格式: [4字节网络序长度][密文]，解决 TCP 字节流的粘包/拆包问题
            uint32_t net_len = htonl((uint32_t)enc_len);
            if (SSL_write(ssl, &net_len, 4) <= 0)
                break;
            if (SSL_write(ssl, cipher, enc_len) <= 0)
                break;

            // 更新流量统计与活动时间（用于超时检测）
            session->addBytesSent(enc_len);
            session->updateActivity();
        }

        // ── 方向二：TLS → 解密 → TUN（接收客户端发来的 IP 包）──
        if (FD_ISSET(sock, &fds))
        {
            // 先读 4 字节长度头（读满，避免 TLS 分段导致的错位）
            uint32_t net_len = 0;
            if (!SSL_read_full(ssl, &net_len, 4))
                break;
            int enc_len = (int)ntohl(net_len);
            if (enc_len <= 0 || enc_len > (int)sizeof(cipher))
                break;

            // 再读对应长度的密文
            if (!SSL_read_full(ssl, cipher, enc_len))
                break;

            // AES-256-CBC 解密还原明文 IP 包
            int pkt_len = AesDecrypt(cipher, enc_len, session_key, session_iv, plain);
            if (pkt_len > 0)
            {
                write(tun_fd, plain, pkt_len); // 写回 TUN，交给内核协议栈处理
                session->addBytesReceived(enc_len);
                session->updateActivity();
            }
        }
    }

    cout << "[VPN] 客户端断开: " << client_ip << endl;
    close(tun_fd);
    client_manager.removeClient(sock);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
}

// ==================== 主程序 ====================

int main()
{
    cout << "====== VPN 服务器 (TLS + AES-256) ======\n"
         << endl;

    if (!InitSSL())
        return 1;

    client_manager.setOnClientConnect([](ClientManager::SessionPtr session)
                                      {
        std::cout << "客户端连接: " 
                  << session->getInfo().real_ip << ":"
                  << session->getInfo().real_port << std::endl;
        std::cout << "会话ID: " << session->getInfo().session_id << std::endl; });

    client_manager.setOnClientDisconnect([](ClientManager::SessionPtr session)
                                         {
        std::cout << "客户端断开: " 
                  << session->getInfo().username << " ("
                  << session->getInfo().virtual_ip << ")" << std::endl;
        
        // 统计信息
        std::cout << "  发送: " << session->getInfo().bytes_sent << " bytes" << std::endl;
        std::cout << "  接收: " << session->getInfo().bytes_received << " bytes" << std::endl; });

    client_manager.setOnClientTimeout([](ClientManager::SessionPtr session)
                                      { std::cout << "客户端超时: " << session->getInfo().username << std::endl; });

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    const short ServerPort = VPN_PORT; // Default using VPN Port(8443). Can be replaced.
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(ServerPort);
    sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("bind");
        return 1;
    }
    listen(server_sock, 10);
    cout << "[服务器] 监听端口 " << ServerPort << " ..." << endl;

    while (true)
    {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0)
        {
            perror("accept");
            continue;
        }

        thread(HandleClient, client_sock, client_addr).detach();
    }

    close(server_sock);
    SSL_CTX_free(ssl_ctx);
    return 0;
}
