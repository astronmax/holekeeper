#include <common.hpp>
#include <turn.hpp>

#include <QtCore/QCryptographicHash>

#include <sstream>

using namespace turn;

std::pair<QHostAddress, uint16_t> unpack_xor_address(QByteArray data)
{
    QByteArray family_raw {};
    family_raw.resize(2);
    std::copy(data.begin(), data.begin() + 2, family_raw.begin());
    if (bytes_to_int<uint16_t>(family_raw) != stun::IPV4_PROTOCOL) {
        throw std::invalid_argument { "IPv6 address not supported" };
    }

    // unpack port
    QByteArray xport_raw {};
    xport_raw.resize(2);
    std::copy(data.begin() + 2, data.begin() + 4, xport_raw.begin());
    auto port = bytes_to_int<uint16_t>(xport_raw) ^ static_cast<uint16_t>(stun::COOKIE >> 16);

    // unpack ip
    QByteArray xaddr_raw {};
    xaddr_raw.resize(4);
    std::copy(data.begin() + 4, data.end(), xaddr_raw.begin());
    auto cookie_raw = int_to_bytes<uint32_t>(stun::COOKIE);
    std::string ip_addr;
    for (size_t i {}; i < 4; i++) {
        auto octet = static_cast<uint8_t>(xaddr_raw[i]) ^ static_cast<uint8_t>(cookie_raw[i]);
        ip_addr += std::to_string(octet);
        if (i != 3) {
            ip_addr += ".";
        }
    }

    return std::make_pair(QHostAddress(ip_addr.c_str()), port);
}

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
    }

    return xor_peer_addr;
}

Client::Client(QHostAddress ip, uint16_t port, std::string username, std::string password)
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

std::pair<QHostAddress, uint16_t> Client::allocate_address()
{
    // create request to get NONCE
    stun::Message get_nonce_msg { stun::MsgClass::REQUEST, stun::MsgMethod::ALLOCATE };
    auto transport_udp = int_to_bytes<uint32_t>(0x11000000);
    get_nonce_msg.add_attribute(stun::Attribute::REQUESTED_TRANSPORT, transport_udp);
    get_nonce_msg.add_fingerprint();

    // send request to get NONCE and wait response
    _socket->writeDatagram(get_nonce_msg.to_bytes(), _server_addr.first, _server_addr.second);
    while (!_socket->hasPendingDatagrams()) { }

    QByteArray response_raw {};
    response_raw.fill('\x00', BUFFER_SIZE);
    _socket->readDatagram(response_raw.data(), BUFFER_SIZE);

    // get NONCE from response
    stun::Message response { response_raw };
    auto nonce_attribute = response.find_attribute(stun::Attribute::NONCE);
    _nonce.resize(16);
    std::copy(nonce_attribute.begin() + 4, nonce_attribute.end(), _nonce.begin());

    // create allocation request
    stun::Message allocate_msg { stun::MsgClass::REQUEST, stun::MsgMethod::ALLOCATE };
    allocate_msg.add_attribute(stun::Attribute::REQUESTED_TRANSPORT, transport_udp);
    allocate_msg.add_attribute(stun::Attribute::USERNAME, QByteArray(_username.c_str()));
    allocate_msg.add_attribute(stun::Attribute::NONCE, _nonce);
    allocate_msg.add_attribute(stun::Attribute::REALM, QByteArray());
    allocate_msg.add_integrity(_integrity_key);
    allocate_msg.add_fingerprint();

    // send request to get NONCE and wait response
    _socket->writeDatagram(allocate_msg.to_bytes(), _server_addr.first, _server_addr.second);
    while (!_socket->hasPendingDatagrams()) { }

    response_raw.clear();
    response_raw.fill('\x00', BUFFER_SIZE);
    _socket->readDatagram(response_raw.data(), BUFFER_SIZE);

    // get XOR_RELAYED_ADDRESS from response
    stun::Message allocate_response { response_raw };
    auto relayed_addr_attr = allocate_response.find_attribute(stun::Attribute::XOR_RELAYED_ADDRESS);

    QByteArray xor_relayed_address {};
    xor_relayed_address.resize(8);
    std::copy(relayed_addr_attr.begin() + 4, relayed_addr_attr.end(), xor_relayed_address.begin());

    return unpack_xor_address(xor_relayed_address);
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

    _socket->writeDatagram(msg.to_bytes(), _server_addr.first, _server_addr.second);
    while (!_socket->hasPendingDatagrams()) { }

    QByteArray response_raw {};
    response_raw.fill('\x00', BUFFER_SIZE);
    _socket->readDatagram(response_raw.data(), BUFFER_SIZE);

    stun::Message create_permissions_response { response_raw };
    if (create_permissions_response.get_class() == stun::MsgClass::ERROR) {
        throw std::runtime_error { "Can't create permission on TURN server" };
    }
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

    _socket->writeDatagram(msg.to_bytes(), _server_addr.first, _server_addr.second);
    while (!_socket->hasPendingDatagrams()) { }

    QByteArray response_raw {};
    response_raw.fill('\x00', BUFFER_SIZE);
    _socket->readDatagram(response_raw.data(), BUFFER_SIZE);
}

void Client::send_data(QByteArray data, std::string ip_addr, uint16_t port)
{
    stun::Message msg { stun::MsgClass::INDICATION, stun::MsgMethod::SEND };
    auto xor_peer_addr = xor_address(ip_addr, port);
    msg.add_attribute(stun::Attribute::DATA, data);
    msg.add_attribute(stun::Attribute::XOR_PEER_ADDRESS, xor_peer_addr);
    msg.add_fingerprint();

    _socket->writeDatagram(msg.to_bytes(), _server_addr.first, _server_addr.second);
}

QByteArray Client::recv_data()
{
    while (!_socket->hasPendingDatagrams()) { }

    QByteArray buf {};
    buf.resize(BUFFER_SIZE);
    _socket->readDatagram(buf.data(), BUFFER_SIZE);

    stun::Message response { buf };
    auto data_attr = response.find_attribute(stun::Attribute::DATA);
    QByteArray data_length_raw {};
    data_length_raw.resize(2);
    std::copy(data_attr.begin() + 2, data_attr.begin() + 4, data_length_raw.begin());
    auto data_len = bytes_to_int<uint16_t>(data_length_raw);

    QByteArray data {};
    data.resize(data_len);
    std::copy(data_attr.begin() + 4, data_attr.end(), data.begin());

    return data;
}
