#pragma once

#include <string>
#include <chrono>
#include <mutex>
#include <memory>
#include <functional>

// OpenSSL 前向声明，避免在头文件中引入完整的 openssl 头
typedef struct ssl_st SSL;

// 客户端状态
enum class ClientState {
    HANDSHAKING,    // 握手中
    AUTHENTICATING, // 认证中
    CONNECTED,      // 已连接
    DISCONNECTED,   // 已断开
    SUSPENDED       // 挂起（超时）
};

// 客户端信息
struct ClientInfo {
    std::string session_id;      // 会话ID (UUID)
    std::string username;        // 用户名
    std::string virtual_ip;      // 虚拟IP地址
    std::string real_ip;         // 真实IP
    int real_port;               // 真实端口
    std::chrono::system_clock::time_point connect_time;  // 连接时间
    std::chrono::system_clock::time_point last_activity; // 最后活动时间
    uint64_t bytes_sent;         // 发送字节数
    uint64_t bytes_received;     // 接收字节数
};

// 前向声明
class EncryptedSession;

// 客户端会话类
class ClientSession {
public:
    ClientSession(int fd, const std::string& client_ip, int client_port);
    ~ClientSession();
    
    // 禁止拷贝
    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;
    
    // 允许移动
    ClientSession(ClientSession&& other) noexcept;
    ClientSession& operator=(ClientSession&& other) noexcept;
    
    // 连接管理
    void setState(ClientState state);
    ClientState getState() const;
    bool isAlive() const;
    
    // 会话信息
    void setSessionId(const std::string& id) { m_info.session_id = id; }
    void setUsername(const std::string& name) { m_info.username = name; }
    void setVirtualIP(const std::string& ip) { m_info.virtual_ip = ip; }
    void setEncryptionSession(std::shared_ptr<EncryptedSession> enc) { m_encryption = enc; }

    // TLS 连接管理（多线程：处理线程读取、分发线程写入）
    void setSSL(SSL *ssl);
    int sslWritePacket(const void *data, int len); // 线程安全：写入 [4字节长度][数据]
    void detachAndFreeSSL();                        // 线程安全：优雅关闭并释放 TLS
    
    const ClientInfo& getInfo() const { return m_info; }
    int getSocketFd() const { return m_socket_fd; }
    std::shared_ptr<EncryptedSession> getEncryption() const { return m_encryption; }
    
    // 活动更新
    void updateActivity();
    bool isTimeout(int timeout_seconds) const;
    
    // 统计数据更新
    void addBytesSent(uint64_t bytes) { m_info.bytes_sent += bytes; }
    void addBytesReceived(uint64_t bytes) { m_info.bytes_received += bytes; }
    
    // 连接关闭
    void close();
    
private:
    int m_socket_fd;
    ClientState m_state;
    ClientInfo m_info;
    std::shared_ptr<EncryptedSession> m_encryption;
    mutable std::mutex m_mutex;  // 保护本会话的操作

    SSL *m_ssl = nullptr;            // TLS 连接：处理线程读取、分发线程写入
    mutable std::mutex m_ssl_mutex;  // 保护 m_ssl 的写入与释放，避免 use-after-free
};