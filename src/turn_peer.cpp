#include <stun.hpp>
#include <turn_peer.hpp>

TurnPeer::TurnPeer(ConfigManager& config_manager)
{
    _socket = std::make_shared<QUdpSocket>();
    _socket->bind(QHostAddress("0.0.0.0"), config_manager.get_port());

    _peer_info.nickname = config_manager.get_nickname();
    _peer_info.nat_type = NatType::COMMON;
    _server = config_manager.get_turn_server();

    // create integrity key
    QCryptographicHash hash { QCryptographicHash::Algorithm::Md5 };
    hash.addData(_server.username + "::" + _server.password); // no realm
    _integrity_key = hash.result();

    // allocate address on TURN server
    _peer_info.address = this->allocate_address();

    connect(_socket.get(), &QUdpSocket::readyRead, this, &TurnPeer::read_data);
}

TurnPeer::~TurnPeer()
{
    this->refresh(0);
}

void TurnPeer::send_data(QByteArray const& message, HostAddress addr)
{
    auto data = message;
    if (data.length() % 4 != 0) {
        data.append(QByteArray().fill('\x00', 4 - (data.length() % 4)));
    }

    stun::Message msg { stun::MsgClass::INDICATION, stun::MsgMethod::SEND };
    msg.add_attribute(stun::Attribute::DATA, data);
    msg.add_attribute(stun::Attribute::XOR_PEER_ADDRESS, stun::xor_address(addr));
    msg.add_fingerprint();

    const auto [ip, port] = _server.address;
    _socket->writeDatagram(msg.to_bytes(), QHostAddress(ip.c_str()), port);
}

void TurnPeer::register_peer(PeerInfo peer)
{
    auto xor_peer_addr = stun::xor_address(peer.address);
    stun::Message msg { stun::MsgClass::REQUEST, stun::MsgMethod::CREATE_PERMISSION };
    msg.add_attribute(stun::Attribute::XOR_PEER_ADDRESS, xor_peer_addr);
    msg.add_attribute(stun::Attribute::USERNAME, QByteArray(_server.username.c_str()));
    msg.add_attribute(stun::Attribute::NONCE, _nonce);
    msg.add_attribute(stun::Attribute::REALM, QByteArray());
    msg.add_integrity(_integrity_key);
    msg.add_fingerprint();
    this->send_to_server(msg.to_bytes());
    qInfo("[INFO] Create permission on TURN for %s %s:%d",
        peer.nickname.c_str(), peer.address.first.c_str(), peer.address.second);

    _active_peers.insert(peer.nickname, peer.address);
    emit peer_registered(peer.nickname);
}

void TurnPeer::ping_active_peers() { this->refresh(600); }

void TurnPeer::read_data()
{
    QByteArray buf;
    buf.resize(_socket->pendingDatagramSize());
    _socket->readDatagram(buf.data(), buf.size());

    stun::Message response { buf };
    if (response.get_class() == stun::MsgClass::ERROR) {
        // TODO: error message parsing
        qCritical() << "[CRITICAL] Error in TURN server response";
        throw ServerError { "Error in TURN server response" };
    }

    if (response.get_class() == stun::MsgClass::INDICATION
        && response.get_method() == stun::MsgMethod::DATA) {

        auto from_addr_attr = response.find_attribute(stun::Attribute::XOR_PEER_ADDRESS);
        auto from_addr_xor = stun::Message::get_attribute_data(from_addr_attr);
        auto from_addr = stun::unpack_address(from_addr_xor, true);

        auto data_attr = response.find_attribute(stun::Attribute::DATA);
        auto data = stun::Message::get_attribute_data(data_attr);

        emit data_received(data, _active_peers.key(from_addr));
    }
}

void TurnPeer::send_to_server(QByteArray const& data)
{
    const auto [ip, port] = _server.address;
    _socket->writeDatagram(data, QHostAddress(ip.c_str()), port);
}

void TurnPeer::refresh(uint32_t lifetime)
{
    stun::Message msg { stun::MsgClass::REQUEST, stun::MsgMethod::REFRESH };
    msg.add_attribute(stun::Attribute::LIFETIME, int_to_bytes(lifetime));
    msg.add_attribute(stun::Attribute::USERNAME, QByteArray(_server.username.c_str()));
    msg.add_attribute(stun::Attribute::NONCE, _nonce);
    msg.add_attribute(stun::Attribute::REALM, QByteArray());
    msg.add_integrity(_integrity_key);
    msg.add_fingerprint();
    this->send_to_server(msg.to_bytes());
}

HostAddress TurnPeer::allocate_address()
{
    // create request to get NONCE
    stun::Message get_nonce_msg { stun::MsgClass::REQUEST, stun::MsgMethod::ALLOCATE };
    auto transport_udp = int_to_bytes<uint32_t>(0x11000000);
    get_nonce_msg.add_attribute(stun::Attribute::REQUESTED_TRANSPORT, transport_udp);
    get_nonce_msg.add_fingerprint();
    this->send_to_server(get_nonce_msg.to_bytes());
    while (!_socket->hasPendingDatagrams()) { }
    QByteArray nonce_raw {};
    nonce_raw.resize(_socket->pendingDatagramSize());
    _socket->readDatagram(nonce_raw.data(), nonce_raw.size());
    stun::Message nonce_response { nonce_raw };

    // get NONCE from response
    auto nonce_attribute = nonce_response.find_attribute(stun::Attribute::NONCE);
    _nonce = stun::Message::get_attribute_data(nonce_attribute);

    // create allocation request
    stun::Message allocate_msg { stun::MsgClass::REQUEST, stun::MsgMethod::ALLOCATE };
    allocate_msg.add_attribute(stun::Attribute::REQUESTED_TRANSPORT, transport_udp);
    allocate_msg.add_attribute(stun::Attribute::USERNAME, QByteArray(_server.username.c_str()));
    allocate_msg.add_attribute(stun::Attribute::NONCE, _nonce);
    allocate_msg.add_attribute(stun::Attribute::REALM, QByteArray());
    allocate_msg.add_integrity(_integrity_key);
    allocate_msg.add_fingerprint();

    // send request to get NONCE and wait response
    this->send_to_server(allocate_msg.to_bytes());
    while (!_socket->hasPendingDatagrams()) { }
    QByteArray allocate_raw {};
    allocate_raw.resize(_socket->pendingDatagramSize());
    _socket->readDatagram(allocate_raw.data(), allocate_raw.size());
    stun::Message allocate_response { allocate_raw };

    // get XOR_RELAYED_ADDRESS from response
    auto relayed_addr_attr = allocate_response.find_attribute(stun::Attribute::XOR_RELAYED_ADDRESS);
    auto xor_relayed_address = stun::Message::get_attribute_data(relayed_addr_attr);
    auto relayed_addr = stun::unpack_address(xor_relayed_address, true);
    qInfo("[INFO] Get TURN allocation: %s:%d", relayed_addr.first.c_str(), relayed_addr.second);

    return relayed_addr;
}

ServerError::ServerError(const std::string& msg)
    : std::runtime_error { msg }
{
}
