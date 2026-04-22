#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

// 服务器编译运行：
// 1. g++ -std=c++11 Initialize.cpp -o vpn_server -lssl -lcrypto -lpthread
// 2. sudo ./vpn_server

// 客户端测试：
// openssl s_client -connect localhost:8443

using namespace std;

// VPN 服务器配置
#define VPN_PORT 8443
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100

// SSL/TLS 上下文
SSL_CTX* ssl_ctx = nullptr;

// 客户端信息结构
struct ClientInfo {
    int socket;
    SSL* ssl;
    string client_ip;
    bool authenticated;
};

// 全局互斥锁和客户端映射
mutex clients_mutex;
map<int, ClientInfo> connected_clients;

// ==================== SSL/TLS 初始化和证书管理 ====================

/**
 * 初始化 SSL/TLS 库和上下文
 */
bool InitializeSSL() {
    OPENSSL_init_ssl(0,NULL);
    // SSL_library_init();
    // OpenSSL_add_all_algorithms();
    // SSL_load_error_strings();
    
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        cerr << "创建 SSL 上下文失败" << endl;
        return false;
    }
    
    cout << "SSL/TLS 初始化成功" << endl;
    return true;
}

/**
 * 加载服务器证书和私钥
 */
bool LoadServerCertificateAndKey(const string& cert_file, const string& key_file) {
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        cerr << "加载证书文件失败: " << cert_file << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        cerr << "加载私钥文件失败: " << key_file << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        cerr << "私钥和证书不匹配" << endl;
        return false;
    }
    
    cout << "服务器证书和私钥加载成功" << endl;
    return true;
}

/**
 * 配置 SSL/TLS 安全参数
 */
void ConfigureSSLSecurity() {
    // 设置 SSL 版本（只允许 TLS 1.2 及以上）
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    
    // 设置密码套件（兼容性更好）
    SSL_CTX_set_cipher_list(ssl_ctx, "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK");//可能仅保留DEFAULT，不指定禁用套件。
}

// ==================== 身份认证模块 ====================

/**
 * 验证客户端身份（基本示例）
 */
bool AuthenticateClient(SSL* ssl, const string& username, const string& password) {
    // 实际应用中应使用更安全的身份验证方法
    // 这里使用简单的用户名密码验证示例
    
    string expected_username = "vpnuser";
    string expected_password = "secure_password_123";
    
    cout << "DEBUG: 接收到用户名: '" << username << "' (长度: " << username.length() << ")" << endl;
    cout << "DEBUG: 接收到密码: '" << password << "' (长度: " << password.length() << ")" << endl;
    cout << "DEBUG: 期望用户名: '" << expected_username << "' (长度: " << expected_username.length() << ")" << endl;
    cout << "DEBUG: 期望密码: '" << expected_password << "' (长度: " << expected_password.length() << ")" << endl;
    
    if (username == expected_username && password == expected_password) {
        cout << "客户端身份验证成功: " << username << endl;
        return true;
    }
    
    cerr << "客户端身份验证失败: " << username << endl;
    return false;
}

// ==================== 密钥协商和加密传输 ====================

/**
 * 生成随机密钥
 */
string GenerateRandomKey(int key_length) {
    unsigned char key[key_length];
    
    if (!RAND_bytes(key, key_length)) {
        cerr << "生成随机密钥失败" << endl;
        return "";
    }
    
    string result;
    for (int i = 0; i < key_length; i++) {
        char hex[3];
        sprintf(hex, "%02x", key[i]);
        result += hex;
    }
    
    return result;
}

/**
 * 加密数据（AES-256-CBC）
 */
string EncryptData(const string& plaintext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char ciphertext[plaintext.length() + EVP_MAX_BLOCK_LENGTH];
    int len = 0;
    int ciphertext_len = 0;
    
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        cerr << "加密初始化失败" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext.c_str(), plaintext.length())) {
        cerr << "数据加密失败" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;
    
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        cerr << "加密完成失败" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    string result;
    for (int i = 0; i < ciphertext_len; i++) {
        char hex[3];
        sprintf(hex, "%02x", ciphertext[i]);
        result += hex;
    }
    
    return result;
}

/**
 * 解密数据（AES-256-CBC）
 */
string DecryptData(const string& ciphertext_hex, const unsigned char* key, const unsigned char* iv) {
    int ciphertext_len = ciphertext_hex.length() / 2;
    unsigned char ciphertext[ciphertext_len];
    
    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(ciphertext_hex.c_str() + i * 2, "%2hhx", &ciphertext[i]);
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char plaintext[ciphertext_len + EVP_MAX_BLOCK_LENGTH];
    int len = 0;
    int plaintext_len = 0;
    
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        cerr << "解密初始化失败" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        cerr << "数据解密失败" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;
    
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        cerr << "解密完成失败" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return string((char*)plaintext, plaintext_len);
}

// ==================== 客户端处理 ====================

/**
 * 处理客户端连接
 */
void HandleClient(int client_socket, struct sockaddr_in client_addr) {
    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        cerr << "创建 SSL 对象失败" << endl;
        close(client_socket);
        return;
    }
    
    //插入SSL层，绑定SOCKET
    SSL_set_fd(ssl, client_socket);
    
    // 执行 SSL/TLS 握手
    if (SSL_accept(ssl) <= 0) {
        cerr << "SSL/TLS 握手失败" << endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        return;
    }
    
    cout << "SSL/TLS 连接建立成功" << endl;
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    cout << "客户端连接: " << client_ip << ":" << ntohs(client_addr.sin_port) << endl;
    
    // 接收客户端身份认证信息
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    
    int bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        cout << "接收到身份认证信息: " << buffer << endl;
        
        // 简单解析（格式: username:password）
        string auth_str(buffer);
        
        // 移除尾部的换行符和空白
        while (!auth_str.empty() && (auth_str.back() == '\n' || auth_str.back() == '\r' || auth_str.back() == ' ')) {
            auth_str.pop_back();
        }
        
        size_t delimiter_pos = auth_str.find(':');
        if (delimiter_pos != string::npos) {
            string username = auth_str.substr(0, delimiter_pos);
            string password = auth_str.substr(delimiter_pos + 1);
            
            // 移除密码中的换行符
            while (!password.empty() && (password.back() == '\n' || password.back() == '\r')) {
                password.pop_back();
            }
            
            if (AuthenticateClient(ssl, username, password)) {
                // 发送认证成功响应
                string response = "AUTH_SUCCESS";
                SSL_write(ssl, response.c_str(), response.length());
                
                // 生成会话密钥
                string session_key = GenerateRandomKey(32); // 256-bit AES key
                cout << "生成的会话密钥: " << session_key.substr(0, 16) << "... (隐藏)" << endl;
                
                // 存储客户端信息
                {
                    lock_guard<mutex> lock(clients_mutex);
                    ClientInfo client_info;
                    client_info.socket = client_socket;
                    client_info.ssl = ssl;
                    client_info.client_ip = client_ip;
                    client_info.authenticated = true;
                    connected_clients[client_socket] = client_info;
                }
                
                // 处理客户端数据通信
                while (true) {
                    memset(buffer, 0, BUFFER_SIZE);
                    bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
                    
                    if (bytes_read > 0) {
                        buffer[bytes_read] = '\0';
                        cout << "接收到数据 (来自 " << client_ip << "): " << buffer << endl;
                        
                        // 回显数据（在实际应用中可进行数据转发）
                        string response = "数据已接收: ";
                        response += string(buffer);
                        SSL_write(ssl, response.c_str(), response.length());
                    } else if (bytes_read == 0) {
                        cout << "客户端断开连接: " << client_ip << endl;
                        break;
                    } else {
                        cerr << "SSL_read 错误" << endl;
                        break;
                    }
                }
            } else {
                string response = "AUTH_FAILED";
                SSL_write(ssl, response.c_str(), response.length());
            }
        }
    }
    
    // 清理资源
    {
        lock_guard<mutex> lock(clients_mutex);
        connected_clients.erase(client_socket);
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
}

// ==================== VPN 服务器主程序 ====================

/**
 * 启动 VPN 服务器
 */
bool StartVPNServer() {
    // 初始化 SSL/TLS
    if (!InitializeSSL()) {
        return false;
    }
    
    // 配置 SSL 安全参数
    ConfigureSSLSecurity();
    
    // 加载自签名证书和私钥
    if (!LoadServerCertificateAndKey("server.crt", "server.key")) {
        cerr << "证书加载失败，可能是证书不存在或损坏，请先生成证书:" << endl;
        cerr << "  openssl genrsa -out server.key 2048" << endl;
        cerr << "  openssl req -new -x509 -key server.key -out server.crt -days 365" << endl;
        return false;
    }
    
    // 创建服务器套接字
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        cerr << "创建服务器套接字失败" << endl;
        return false;
    }
    
    // 允许套接字地址重用
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "设置套接字选项失败" << endl;
        close(server_socket);
        return false;
    }
    
    // 绑定端口
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(VPN_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "绑定端口失败" << endl;
        close(server_socket);
        return false;
    }
    
    // 监听连接
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        cerr << "监听失败" << endl;
        close(server_socket);
        return false;
    }
    
    cout << "VPN 服务器启动成功，监听端口: " << VPN_PORT << endl;
    
    // 接受客户端连接
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            cerr << "接受客户端连接失败" << endl;
            continue;
        }
        
        // 创建线程处理客户端
        thread client_thread(HandleClient, client_socket, client_addr);
        client_thread.detach();
    }
    
    close(server_socket);
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    
    return true;
}

// ==================== 主程序入口 ====================

int main() {
    cout << "====== VPN 程序 - SSL/TLS 实现 ======" << endl;
    cout << "功能: 基于 SSL/TLS 的加密 VPN 服务" << endl;
    cout << "包含: 身份认证、密钥协商、加密传输" << endl;
    cout << "=====================================" << endl << endl;
    
    if (!StartVPNServer()) {
        cerr << "VPN 服务器启动失败" << endl;
        return 1;
    }
    
    return 0;
}
