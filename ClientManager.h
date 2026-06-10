#pragma once

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <functional>
#include <chrono>

class ClientSession;

// 客户端管理器
class ClientManager
{
public:
    using SessionPtr = std::shared_ptr<ClientSession>;
    using SessionMap = std::unordered_map<int, SessionPtr>;          // fd -> session
    using IPMap = std::unordered_map<std::string, SessionPtr>;       // virtual_ip -> session
    using UsernameMap = std::unordered_map<std::string, SessionPtr>; // username -> session
    ClientManager();
    ~ClientManager();

    // 禁止拷贝
    ClientManager(const ClientManager &) = delete;
    ClientManager &operator=(const ClientManager &) = delete;

    // 客户端管理
    bool addClient(int fd, const std::string &ip, int port);
    bool removeClient(int fd);
    bool removeClientByIP(const std::string &virtual_ip);

    SessionPtr getClient(int fd);
    SessionPtr getClientByIP(const std::string &virtual_ip);
    SessionPtr getClientByUsername(const std::string &username);

    std::vector<SessionPtr> getAllClients();
    std::vector<std::string> getAllVirtualIPs();

    // 连接数限制
    bool canAcceptNewClient(int max_clients);
    int getClientCount() const;

    // 超时清理
    void cleanupTimeoutClients(int timeout_seconds);

    // IP分配管理
    std::string allocateVirtualIP(const std::string &preferred_ip = "");
    void releaseVirtualIP(const std::string &ip);
    bool assignVirtualIP(int fd, const std::string &ip); // 绑定虚拟IP到会话并登记到 ip_map

    // 广播消息
    void broadcastToAll(const uint8_t *data, int len, int exclude_fd = -1);

    // 统计信息
    struct Stats
    {
        int total_connections;
        int active_connections;
        uint64_t total_bytes_sent;
        uint64_t total_bytes_received;
        std::chrono::system_clock::time_point start_time;
    };

    Stats getStats() const;

    // 回调函数设置（用于事件通知）
    void setOnClientConnect(std::function<void(SessionPtr)> callback);
    void setOnClientDisconnect(std::function<void(SessionPtr)> callback);
    void setOnClientTimeout(std::function<void(SessionPtr)> callback);

private:
    SessionMap m_clients;                            // fd -> session
    IPMap m_ip_map;                                  // virtual_ip -> session
    UsernameMap m_username_map;                      // username -> session
    std::unordered_set<std::string> m_allocated_ips; // 已分配的IP

    mutable std::shared_mutex m_mutex; // 读写锁：读操作用 shared_lock，写操作用 unique_lock

    // IP池配置
    std::string m_ip_network; // "10.8.0"
    int m_ip_start;           // 2
    int m_ip_end;             // 254

    // 统计信息
    Stats m_stats;
    mutable std::mutex m_stats_mutex;

    // 回调函数
    std::function<void(SessionPtr)> m_on_connect_cb;
    std::function<void(SessionPtr)> m_on_disconnect_cb;
    std::function<void(SessionPtr)> m_on_timeout_cb;

    // 内部方法
    void updateStatsOnConnect();
    void updateStatsOnDisconnect(const SessionPtr &session);
    std::string generateSessionId();
};