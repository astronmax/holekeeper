#include <common.hpp>
#include <turn.hpp>

#include <QtCore/QCryptographicHash>
#include <QtCore/QtLogging>
#include <QtNetwork/QHostAddress>

#include <sstream>

using namespace turn;

QByteArray xor_address(std::string ip_addr, uint16_t port)
{
    QByteArray xor_peer_addr {};
    xor_peer_addr.push_back(int_to_bytes<uint16_t>(stun::IPV4_PROTOCOL));
    xor_peer_addr.push_back(int_to_bytes<uint16_t>(port ^ (stun::COOKIE >> 16)));

    auto cookie_raw = int_to_bytes<uint32_t>(stun::COOKIE);
    std::stringstream ss { ip_addr };
    std::string octet;
    size_t i {};
    while (std::getline(ss, octet, '.')) {
        xor_peer_addr.push_back(std::atoi(octet.c_str()) ^ cookie_raw[i]);
        i++;
    }

    return xor_peer_addr;
}

Client::Client(std::string ip, uint16_t port, std::string username, std::string password)
{
    _username = username;
    _socket = std::make_shared<QUdpSocket>(nullptr);
    _server_addr = std::make_pair(ip, port);

    QCryptographicHash hash { QCryptographicHash::Algorithm::Md5 };
    hash.addData(username + "::" + password); // no realm
    _integrity_key = hash.result();
}

Client::~Client()
{
    this->refresh(0);
    _socket->close();
}

HostAddress Client::allocate_address()
{
    // create request to get NONCE
    stun::Message get_nonce_msg { stun::MsgClass::REQUEST, stun::MsgMethod::ALLOCATE };
    auto transport_udp = int_to_bytes<uint32_t>(0x11000000);
    get_nonce_msg.add_attribute(stun::Attribute::REQUESTED_TRANSPORT, transport_udp);
    get_nonce_msg.add_fingerprint();

    // send request to get NONCE and wait response
    auto nonce_response = this->send_to_server(get_nonce_msg, false);

    // get NONCE from response
    auto nonce_attribute = nonce_response.find_attribute(stun::Attribute::NONCE);
    _nonce = stun::Message::get_attribute_data(nonce_attribute);

    // create allocation request
    stun::Message allocate_msg { stun::MsgClass::REQUEST, stun::MsgMethod::ALLOCATE };
    allocate_msg.add_attribute(stun::Attribute::REQUESTED_TRANSPORT, transport_udp);
    allocate_msg.add_attribute(stun::Attribute::USERNAME, QByteArray(_username.c_str()));
    allocate_msg.add_attribute(stun::Attribute::NONCE, _nonce);
    allocate_msg.add_attribute(stun::Attribute::REALM, QByteArray());
    allocate_msg.add_integrity(_integrity_key);
    allocate_msg.add_fingerprint();

    // send request to get NONCE and wait response
    auto allocate_response = this->send_to_server(allocate_msg);

    // get XOR_RELAYED_ADDRESS from response
    auto relayed_addr_attr = allocate_response.find_attribute(stun::Attribute::XOR_RELAYED_ADDRESS);
    auto xor_relayed_address = stun::Message::get_attribute_data(relayed_addr_attr);
    auto relayed_addr = stun::unpack_xor_address(xor_relayed_address);
    qInfo("[INFO] Get TURN allocation: %s:%d", relayed_addr.first.c_str(), relayed_addr.second);
    return relayed_addr;
}

void Client::create_permission(std::string ip_addr, uint16_t port)
{
    auto xor_peer_addr = xor_address(ip_addr, port);
    stun::Message msg { stun::MsgClass::REQUEST, stun::MsgMethod::CREATE_PERMISSION };
    msg.add_attribute(stun::Attribute::XOR_PEER_ADDRESS, xor_peer_addr);
    msg.add_attribute(stun::Attribute::USERNAME, QByteArray(_username.c_str()));
    msg.add_attribute(stun::Attribute::NONCE, _nonce);
    msg.add_attribute(stun::Attribute::REALM, QByteArray());
    msg.add_integrity(_integrity_key);
    msg.add_fingerprint();
    this->send_to_server(msg);
    qInfo("[INFO] Create permission on TURN for %s:%d", ip_addr.c_str(), port);
}

void Client::refresh(uint32_t lifetime)
{
    stun::Message msg { stun::MsgClass::REQUEST, stun::MsgMethod::REFRESH };
    msg.add_attribute(stun::Attribute::LIFETIME, int_to_bytes(lifetime));
    msg.add_attribute(stun::Attribute::USERNAME, QByteArray(_username.c_str()));
    msg.add_attribute(stun::Attribute::NONCE, _nonce);
    msg.add_attribute(stun::Attribute::REALM, QByteArray());
    msg.add_integrity(_integrity_key);
    msg.add_fingerprint();
    this->send_to_server(msg);
    qInfo("[INFO] Refresh on TURN with lifetime %d", lifetime);
}

stun::Message Client::send_to_server(stun::Message msg, bool check_error)
{
    QByteArray response_raw {};
    response_raw.fill('\x00', BUFFER_SIZE);
    _socket->writeDatagram(msg.to_bytes(), QHostAddress(_server_addr.first.c_str()), _server_addr.second);

    while (!_socket->hasPendingDatagrams()) { }
    _socket->readDatagram(response_raw.data(), BUFFER_SIZE);

    stun::Message response { response_raw };
    if (check_error && response.get_class() == stun::MsgClass::ERROR) {
        // TODO: error message parsing
        qCritical("[CRITICAL] Error in TURN server response");
        throw ServerError { "Error in TURN server response" };
    }

    return response;
}

void Client::send_data(QByteArray data, std::string ip_addr, uint16_t port)
{
    if (data.length() % 4 != 0) {
        data.append(QByteArray().fill('\x00', 4 - (data.length() % 4)));
    }

    stun::Message msg { stun::MsgClass::INDICATION, stun::MsgMethod::SEND };
    msg.add_attribute(stun::Attribute::DATA, data);
    msg.add_attribute(stun::Attribute::XOR_PEER_ADDRESS, xor_address(ip_addr, port));
    msg.add_fingerprint();
    _socket->writeDatagram(msg.to_bytes(), QHostAddress(_server_addr.first.c_str()), _server_addr.second);
}

auto Client::recv_data() -> std::pair<QByteArray, HostAddress>
{
    QByteArray buf {};
    buf.resize(BUFFER_SIZE);

    while (!_socket->hasPendingDatagrams()) { }
    _socket->readDatagram(buf.data(), BUFFER_SIZE);

    stun::Message response { buf };
    auto from_addr_attr = response.find_attribute(stun::Attribute::XOR_PEER_ADDRESS);
    auto from_addr_xor = stun::Message::get_attribute_data(from_addr_attr);
    auto from_addr = stun::unpack_xor_address(from_addr_xor);

    auto data_attr = response.find_attribute(stun::Attribute::DATA);
    auto data = stun::Message::get_attribute_data(data_attr);

    return std::make_pair(data, from_addr);
}

ServerError::ServerError(const std::string& msg)
    : std::runtime_error { msg }
{
}
