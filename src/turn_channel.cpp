#include "turn_channel.hpp"
#include "abstract_channel.hpp"
#include "stun.hpp"

#include <QtCore/QCryptographicHash>
#include <QtCore/QMessageAuthenticationCode>
#include <QtCore/QtLogging>

using namespace hk;

TurnChannel::TurnChannel(ConfigParser& config_parser) {
    m_turn_settings = config_parser.turn_server();
    m_socket = std::make_shared<QUdpSocket>();
    m_socket->bind(QHostAddress("0.0.0.0"), config_parser.port());

    m_self_info = std::make_shared<ChannelInfo>();
    m_self_info->nickname = config_parser.nickname();
    m_self_info->holepunching = false;

    // create integrity key
    QCryptographicHash hash { QCryptographicHash::Algorithm::Md5 };
    hash.addData(m_turn_settings.username + "::" + m_turn_settings.password); // no realm
    m_integrity_key = hash.result();

    send_allocation_request();

    connect(m_socket.get(), &QUdpSocket::readyRead, this, &TurnChannel::process);
    connect(&m_receive_timer, &QTimer::timeout, this, []() {
        throw std::runtime_error { "TURN response wait timeout" };
    });
    connect(this, &AbstractChannel::channel_ready, this, &TurnChannel::start_refreshing);
}

TurnChannel::~TurnChannel() { send_refresh_request(0); }

auto TurnChannel::send_data(QByteArray& raw_data) -> void {
    stun::Message msg { stun::MsgClass::INDICATION, stun::MsgMethod::SEND };
    msg.add_attribute(stun::Attribute::DATA, raw_data);
    msg.add_attribute(stun::Attribute::XOR_PEER_ADDRESS, stun::xor_address(m_peer_info->address));
    msg.add_fingerprint();

    const auto [ip, port] = m_turn_settings.address;
    m_socket->writeDatagram(msg.to_bytes(), QHostAddress(ip.c_str()), port);
}

auto TurnChannel::connect_peer(std::shared_ptr<ChannelInfo> peer_info) -> void {
    m_peer_info = peer_info;
    auto xor_peer_addr = stun::xor_address(m_peer_info->address);
    stun::Message msg { stun::MsgClass::REQUEST, stun::MsgMethod::CREATE_PERMISSION };
    msg.add_attribute(stun::Attribute::XOR_PEER_ADDRESS, xor_peer_addr);
    msg.add_attribute(stun::Attribute::USERNAME, QByteArray(m_turn_settings.username.c_str()));
    msg.add_attribute(stun::Attribute::NONCE, m_nonce);
    msg.add_attribute(stun::Attribute::REALM, QByteArray());
    msg.add_integrity(m_integrity_key);
    msg.add_fingerprint();

    const auto [server_ip, server_port] = m_turn_settings.address;
    m_socket->writeDatagram(msg.to_bytes(), QHostAddress(server_ip.c_str()), server_port);
}

auto TurnChannel::process() -> void {
    m_receive_timer.stop();

    QByteArray response {};
    response.resize(m_socket->pendingDatagramSize());
    m_socket->readDatagram(response.data(), response.size());
    stun::Message stun_response { response };

    if (m_nonce.isEmpty()) {
        auto nonce_attribute = stun_response.find_attribute(stun::Attribute::NONCE);
        if (nonce_attribute.isEmpty()) {
            throw std::runtime_error { "TURN server sends response with empty NONCE" };
        }
        m_nonce = stun::Message::get_attribute_data(nonce_attribute);

        send_allocation_request();
        return;
    }

    if (stun_response.get_class() == stun::MsgClass::ERROR) {
        throw std::runtime_error { "Error in TURN response" };
    }

    if (stun_response.get_class() == stun::MsgClass::RESPONSE) {
        if (stun_response.get_method() == stun::MsgMethod::ALLOCATE) {
            auto relayed_addr_attr = stun_response.find_attribute(stun::Attribute::XOR_RELAYED_ADDRESS);
            auto xor_relayed_address = stun::Message::get_attribute_data(relayed_addr_attr);
            auto relayed_addr = stun::unpack_address(xor_relayed_address, true);
            m_self_info->address = relayed_addr;
            qInfo() << "[INFO] Get TURN allocation" << relayed_addr.first.c_str()
                    << ":" << relayed_addr.second;
            emit channel_ready();
        } else if (stun_response.get_method() == stun::MsgMethod::REFRESH) {
            qInfo() << "[INFO] Successfully refresh TURN allocation";
        } else if (stun_response.get_method() == stun::MsgMethod::CREATE_PERMISSION) {
            qInfo() << "[INFO] Send ping to peer";
            send_ping();
        }
    }

    if (stun_response.get_class() == stun::MsgClass::INDICATION
        && stun_response.get_method() == stun::MsgMethod::DATA) {

        auto from_addr_attr = stun_response.find_attribute(stun::Attribute::XOR_PEER_ADDRESS);
        auto from_addr_xor = stun::Message::get_attribute_data(from_addr_attr);
        auto from_addr = stun::unpack_address(from_addr_xor, true);

        auto data_attr = stun_response.find_attribute(stun::Attribute::DATA);
        auto data = stun::Message::get_attribute_data(data_attr);
        process_data(data);
    }
}

auto TurnChannel::start_refreshing() -> void {
    m_refresh_timer.start(120'000);
    connect(&m_refresh_timer, &QTimer::timeout, this, [this]() {
        send_refresh_request(600);
        m_refresh_timer.start(120'000);
    });
}

auto TurnChannel::send_allocation_request() -> void {
    auto transport_udp = int_to_bytes<uint32_t>(0x11000000);
    const auto [server_ip, server_port] = m_turn_settings.address;

    if (m_nonce.isEmpty()) {
        stun::Message get_nonce_msg { stun::MsgClass::REQUEST, stun::MsgMethod::ALLOCATE };
        get_nonce_msg.add_attribute(stun::Attribute::REQUESTED_TRANSPORT, transport_udp);
        get_nonce_msg.add_fingerprint();
        m_socket->writeDatagram(get_nonce_msg.to_bytes(), QHostAddress(server_ip.c_str()), server_port);

    } else {
        stun::Message allocate_msg { stun::MsgClass::REQUEST, stun::MsgMethod::ALLOCATE };
        allocate_msg.add_attribute(stun::Attribute::REQUESTED_TRANSPORT, transport_udp);
        allocate_msg.add_attribute(stun::Attribute::USERNAME, QByteArray(m_turn_settings.username.c_str()));
        allocate_msg.add_attribute(stun::Attribute::NONCE, m_nonce);
        allocate_msg.add_attribute(stun::Attribute::REALM, QByteArray());
        allocate_msg.add_integrity(m_integrity_key);
        allocate_msg.add_fingerprint();
        m_socket->writeDatagram(allocate_msg.to_bytes(), QHostAddress(server_ip.c_str()), server_port);
    }

    m_receive_timer.start(3'000);
}

auto TurnChannel::send_refresh_request(std::uint32_t lifetime) -> void {
    stun::Message msg { stun::MsgClass::REQUEST, stun::MsgMethod::REFRESH };
    msg.add_attribute(stun::Attribute::LIFETIME, int_to_bytes(lifetime));
    msg.add_attribute(stun::Attribute::USERNAME, QByteArray(m_turn_settings.username.c_str()));
    msg.add_attribute(stun::Attribute::NONCE, m_nonce);
    msg.add_attribute(stun::Attribute::REALM, QByteArray());
    msg.add_integrity(m_integrity_key);
    msg.add_fingerprint();

    const auto [server_ip, server_port] = m_turn_settings.address;
    m_socket->writeDatagram(msg.to_bytes(), QHostAddress(server_ip.c_str()), server_port);
    m_receive_timer.start(3'000);
}
