#pragma once

#include <stun.hpp>

#include <QtNetwork/QUdpSocket>

#include <memory>
#include <utility>

namespace turn {

struct Client {
public:
    Client(std::string, uint16_t, std::string, std::string);
    ~Client();

public:
    std::pair<std::string, uint16_t> allocate_address();
    void create_permission(std::string, uint16_t);
    void refresh(uint32_t);

    stun::Message send_to_server(stun::Message, bool check_error = true);
    void send_data(QByteArray, std::string, uint16_t);
    std::pair<QByteArray, std::pair<std::string, uint16_t>> recv_data();

private:
    constexpr static size_t BUFFER_SIZE = 2048;
    std::string _username;
    std::shared_ptr<QUdpSocket> _socket;
    std::pair<std::string, uint16_t> _server_addr;
    QByteArray _integrity_key;
    QByteArray _nonce;
};

struct ServerError : public std::runtime_error {
public:
    ServerError(const std::string&);
    virtual ~ServerError() noexcept = default;
};

};