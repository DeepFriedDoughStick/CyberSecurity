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
#include "ClientSession.h"
#include "ClientManager.h"
#include <shared_mutex>
#include <random>
#include <iomanip>

// g++ -std=c++17 vpn_server.cpp -o vpn_server -lssl -lcrypto -lpthread
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
void ClientSession::setSSL(SSL *ssl)
{
    std::lock_guard<std::mutex> lock(m_ssl_mutex);
    m_ssl = ssl;
}
int ClientSession::sslWritePacket(const void *data, int len)
{
    // 在同一把锁内写出 [4字节长度][数据]，保证一个数据帧的原子性，
    // 并通过判空避免向已被释放的 SSL 写入（use-after-free）
    std::lock_guard<std::mutex> lock(m_ssl_mutex);
    if (!m_ssl)
        return -1;
    uint32_t net_len = htonl((uint32_t)len);
    if (SSL_write(m_ssl, &net_len, 4) <= 0)
        return -1;
    if (SSL_write(m_ssl, data, len) <= 0)
        return -1;
    return len;
}
void ClientSession::detachAndFreeSSL()
{
    SSL *s = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_ssl_mutex);
        s = m_ssl;
        m_ssl = nullptr; // 置空后，分发线程不会再使用该连接
    }
    if (s)
    {
        SSL_shutdown(s);
        SSL_free(s);
    }
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
    // 注意：此处已持有 m_mutex，必须直接擦除 m_allocated_ips，
    // 不能调用 releaseVirtualIP（它会再次锁 m_mutex，导致递归死锁 EDEADLK）
    if (!session->getInfo().virtual_ip.empty())
    {
        m_ip_map.erase(session->getInfo().virtual_ip);
        m_allocated_ips.erase(session->getInfo().virtual_ip);
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
bool ClientManager::assignVirtualIP(int fd, const std::string &ip)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_clients.find(fd);
    if (it == m_clients.end())
        return false;
    it->second->setVirtualIP(ip);
    m_ip_map[ip] = it->second; // 登记 virtual_ip -> session，供分发线程按目的IP查找
    return true;
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

SSL_CTX *ssl_ctx = nullptr;
ClientManager client_manager;
int g_tun_fd = -1; // 服务端共享 TUN 虚拟网卡（所有客户端共用一块网卡）

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
 * 用 ip 命令为共享 TUN 配置子网地址并启用
 * cidr: 例如 "10.8.0.1/24"，服务端在该子网内的地址
 * 所有客户端共用这块网卡，服务端按数据包目的 IP 转发给对应客户端
 */
void ConfigureServerTun(const char *dev, const char *cidr)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", cidr, dev);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", dev);
    system(cmd);
    cout << "[TUN] " << dev << " 已配置: " << cidr << endl;
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

// ==================== 数据传输说明 ====================
// 不再在应用层做 AES：SSL_read/SSL_write 已由 TLS 记录层负责机密性与完整性，
// 隧道内传输的就是「原始 IP 包」，外层 TLS 即为唯一且足够的加密层。
// 仍使用 [4字节长度][数据] 的帧格式来解决 TCP 字节流的粘包/拆包问题。

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

// ==================== TUN -> 客户端 分发线程 ====================

/**
 * 单独一个线程从共享 TUN 读取内核发出的 IP 包，
 * 按「目的 IP」找到对应客户端会话，经其 TLS 连接发送出去。
 * 这样多个客户端可以共用一块网卡，并支持客户端之间互通（需开启 ip_forward）。
 */
void TunToClients()
{
    unsigned char pkt[BUFFER_SIZE];
    while (true)
    {
        int len = read(g_tun_fd, pkt, sizeof(pkt));
        if (len <= 0)
        {
            if (len < 0)
                perror("read tun");
            continue;
        }
        if (len < 20 || (pkt[0] >> 4) != 4)
            continue; // 仅处理 IPv4 数据包

        // IPv4 头部第 16~19 字节为目的地址
        char dst[INET_ADDRSTRLEN];
        struct in_addr a;
        memcpy(&a, pkt + 16, 4);
        inet_ntop(AF_INET, &a, dst, sizeof(dst));

        auto session = client_manager.getClientByIP(dst);
        if (!session)
            continue; // 无对应客户端，丢弃

        if (session->sslWritePacket(pkt, len) > 0)
        {
            session->addBytesSent(len);
            session->updateActivity();
        }
    }
}

// ==================== 客户端处理线程 ====================

void HandleClient(int sock, struct sockaddr_in addr)
{
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

    client_manager.addClient(sock, client_ip, ntohs(addr.sin_port));
    auto session = client_manager.getClient(sock);

    // —— 1. TLS 握手 ——（TLS 握手层完成密钥协商 ECDHE、加密协商与服务器身份认证）
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_accept(ssl) <= 0)
    {
        cerr << "[TLS] 握手失败 (" << client_ip << ")" << endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
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
    while (!auth.empty() && (auth.back() == '\n' || auth.back() == '\r'))
        auth.pop_back();

    size_t sep = auth.find(':');
    bool auth_ok = false;
    string user;
    if (sep != string::npos)
    {
        user = auth.substr(0, sep);
        string pass = auth.substr(sep + 1);
        auth_ok = (user == "vpnuser" && pass == "secure_password_123");
    }
    if (!auth_ok)
    {
        cerr << "[Auth] 认证失败: " << user << endl;
        SSL_write(ssl, "FAIL\n", 5);
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        return;
    }
    session->setUsername(user);

    // —— 3. 分配虚拟 IP（从 10.8.0.2~254 地址池中取一个空闲地址）——
    string vip = client_manager.allocateVirtualIP();
    if (vip.empty())
    {
        cerr << "[IP] 地址池已满，拒绝: " << user << endl;
        SSL_write(ssl, "FAIL\n", 5);
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        return;
    }
    client_manager.assignVirtualIP(sock, vip);
    cout << "[Auth] 认证成功: " << user << "，分配虚拟IP " << vip << endl;

    // 下发认证结果与分配到的虚拟 IP，格式："OK <ip>\n"
    string resp = "OK " + vip + "\n";
    if (SSL_write(ssl, resp.c_str(), (int)resp.size()) <= 0)
    {
        SSL_free(ssl);
        session->setState(ClientState::DISCONNECTED);
        client_manager.removeClient(sock);
        return;
    }

    // —— 4. 注册 TLS 连接，进入数据转发 ——
    // 数据通道直接走 TLS（已提供机密性与完整性），不再叠加应用层 AES。
    session->setSSL(ssl);
    session->setState(ClientState::CONNECTED);
    cout << "[VPN] 隧道建立: " << client_ip << " -> " << vip << endl;

    // —— 5. 客户端 -> 服务器：从 TLS 读取数据帧并写入共享 TUN ——
    // （服务器 -> 客户端方向由 TunToClients 分发线程负责）
    unsigned char pkt[BUFFER_SIZE];
    while (true)
    {
        uint32_t net_len = 0;
        if (!SSL_read_full(ssl, &net_len, 4))
            break;
        int len = (int)ntohl(net_len);
        if (len <= 0 || len > (int)sizeof(pkt))
            break;
        if (!SSL_read_full(ssl, pkt, len))
            break;

        if (write(g_tun_fd, pkt, len) < 0)
            break;
        session->addBytesReceived(len);
        session->updateActivity();
    }

    cout << "[VPN] 客户端断开: " << client_ip << " (" << vip << ")" << endl;
    session->detachAndFreeSSL();        // 先优雅关闭并释放 TLS（socket 仍打开）
    client_manager.removeClient(sock);  // 注销会话、释放虚拟IP、关闭 socket
}

// ==================== 主程序 ====================

int main()
{
    cout << "====== VPN 服务器 (TLS) ======\n"
         << endl;

    if (!InitSSL())
        return 1;

    // 创建并配置服务端共享 TUN 虚拟网卡（所有客户端共用）
    char tun_name[IFNAMSIZ] = "vpntun0";
    g_tun_fd = CreateTun(tun_name);
    if (g_tun_fd < 0)
    {
        cerr << "[TUN] 创建失败" << endl;
        return 1;
    }
    ConfigureServerTun(tun_name, "10.8.0.1/24");
    // 开启 IP 转发，使不同客户端之间（10.8.0.0/24）可以互通
    system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1");

    // 启动 TUN -> 客户端 的分发线程
    thread(TunToClients).detach();

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
