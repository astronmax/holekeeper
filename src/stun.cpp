#include <common.hpp>
#include <stun.hpp>

#include <QtCore/QMessageAuthenticationCode>
#include <QtCore/QtLogging>

#include <random>
#include <sstream>

using namespace stun;

uint32_t calc_crc32(const QByteArray data)
{
    std::array<uint32_t, 256> crc_table;
    for (int i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++)
            crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;

        crc_table[i] = crc;
    }

    uint32_t result = 0xFFFFFFFFUL;
    for (auto byte : data) {
        result = crc_table[(result ^ byte) & 0xFF] ^ (result >> 8);
    }

    return result ^ 0xFFFFFFFFUL;
}

QByteArray create_transacrion_id()
{
    auto transaction_id = int_to_bytes<uint32_t>(COOKIE);

    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, 255);
    for (size_t i = 0; i < 12; i++) {
        transaction_id.push_back(dist(rng));
    }

    return transaction_id;
}

HostAddress stun::unpack_address(QByteArray data, bool is_xored)
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
    uint16_t port {};
    if (is_xored) {
        port = bytes_to_int<uint16_t>(xport_raw) ^ static_cast<uint16_t>(stun::COOKIE >> 16);
    } else {
        port = bytes_to_int<uint16_t>(xport_raw);
    }

    // unpack ip
    QByteArray xaddr_raw {};
    xaddr_raw.resize(4);
    std::copy(data.begin() + 4, data.end(), xaddr_raw.begin());
    auto cookie_raw = int_to_bytes<uint32_t>(stun::COOKIE);
    std::string ip_addr;
    for (size_t i {}; i < 4; i++) {
        uint8_t octet {};
        if (is_xored) {
            octet = static_cast<uint8_t>(xaddr_raw[i]) ^ static_cast<uint8_t>(cookie_raw[i]);
        } else {
            octet = static_cast<uint8_t>(xaddr_raw[i]);
        }
        ip_addr += std::to_string(octet);
        if (i != 3) {
            ip_addr += ".";
        }
    }

    return std::make_pair(ip_addr, port);
}

QByteArray stun::xor_address(HostAddress addr)
{
    auto [ip_addr, port] = addr;
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

Message::Message(MsgClass msg_class, MsgMethod msg_method)
{
    _class = msg_class;
    _method = msg_method;
    _length = 0;

    QByteArray header {};
    auto msg_type = static_cast<uint16_t>(msg_class) + static_cast<uint16_t>(msg_method);
    header.push_back(int_to_bytes<uint16_t>(msg_type));
    header.push_back('\x00');
    header.push_back('\x00');
    header.push_back(create_transacrion_id());
    _attributes.push_back(header);
}

Message::Message(QByteArray data)
{
    if (static_cast<size_t>(data.length()) < HEADER_LENGTH) {
        throw std::invalid_argument { "Invalid STUN message" };
    }

    // add header
    QByteArray header {};
    header.resize(HEADER_LENGTH);
    std::copy(data.begin(), data.begin() + HEADER_LENGTH, header.begin());
    _attributes.push_back(header);

    // message type
    QByteArray msg_type_raw {};
    msg_type_raw.resize(2);
    std::copy(data.begin(), data.begin() + 2, msg_type_raw.begin());
    auto msg_type = bytes_to_int<uint16_t>(msg_type_raw);
    _class = MsgClass(msg_type & 0xFFF0);
    _method = MsgMethod(msg_type & 0xF);

    // message length
    QByteArray msg_len_raw {};
    msg_len_raw.resize(2);
    std::copy(data.begin() + 2, data.begin() + 4, msg_len_raw.begin());
    _length = bytes_to_int<uint16_t>(msg_len_raw);
    if (_length % 4 != 0) {
        throw std::invalid_argument { "Bad STUN message value" };
    }

    size_t offset = HEADER_LENGTH, pos {};
    while (pos < _length) {
        QByteArray attr_len_raw {};
        attr_len_raw.resize(4);
        std::copy(data.begin() + offset, data.begin() + offset + 4, attr_len_raw.begin());
        auto attr_len = Message::get_attribute_size(attr_len_raw) + 4;

        // copy attribute
        QByteArray attr {};
        for (size_t i {}; i < attr_len; i++) {
            attr.push_back(data[offset + i]);
        }
        _attributes.push_back(attr);

        offset += attr_len;
        pos += attr_len;
    }
}

MsgClass Message::get_class() const noexcept { return _class; }

MsgMethod Message::get_method() const noexcept { return _method; }

QByteArray Message::get_header() const noexcept { return _attributes.at(0); }

size_t Message::get_length() const noexcept { return _length; }

void Message::add_attribute(Attribute attr_type, QByteArray data)
{
    this->push_attribute(attr_type, data);
    this->set_length(_length + 4 + data.length());
}

QByteArray Message::find_attribute(Attribute needed_attr_type)
{
    auto it = std::find_if(_attributes.begin(), _attributes.end(), [&](QByteArray raw_data) {
        QByteArray attr_type_bytes {};
        attr_type_bytes.push_back(raw_data[0]);
        attr_type_bytes.push_back(raw_data[1]);
        auto attr_type = bytes_to_int<uint16_t>(attr_type_bytes);
        return attr_type == static_cast<uint16_t>(needed_attr_type);
    });

    if (it == _attributes.end()) {
        return QByteArray();
    } else {
        return *it;
    }
}

QByteArray Message::get_attribute_data(QByteArray attribute)
{
    auto attr_length = Message::get_attribute_size(attribute);
    QByteArray data {};
    data.resize(attr_length);
    std::copy(attribute.begin() + 4, attribute.end(), data.begin());

    return data;
}

QByteArray Message::to_bytes() const noexcept
{
    QByteArray bytes {};
    std::for_each(_attributes.begin(), _attributes.end(), [&](QByteArray data) { bytes.push_back(data); });
    return bytes;
}

void Message::add_integrity(QByteArray integrity_key)
{
    this->set_length(_length + INTEGRITY_LENGTH);
    QMessageAuthenticationCode mac { QCryptographicHash::Algorithm::Sha1 };
    mac.setKey(integrity_key);
    mac.addData(this->to_bytes());

    this->push_attribute(Attribute::MESSAGE_INTEGRITY, mac.result());
}

void Message::add_fingerprint()
{
    this->set_length(_length + FINGERPRINT_LENGTH);
    auto fingerprint = int_to_bytes<uint32_t>(calc_crc32(this->to_bytes()) ^ FINGERPRINT_XOR);
    this->push_attribute(Attribute::FINGERPRINT, fingerprint);
}

size_t Message::get_attribute_size(QByteArray attribute)
{
    if (attribute.length() < 4) {
        throw std::invalid_argument { "Bad STUN attribute value" };
    }

    // attribute len
    QByteArray attr_len_raw {};
    attr_len_raw.push_back(attribute[2]);
    attr_len_raw.push_back(attribute[3]);
    size_t attr_len = bytes_to_int<uint16_t>(attr_len_raw);

    // check padding
    if (attr_len % 4 != 0) {
        attr_len += 4 - (attr_len % 4);
    }

    return attr_len;
}

void Message::push_attribute(Attribute attr_type, QByteArray data)
{
    auto attr = int_to_bytes(static_cast<uint16_t>(attr_type));
    attr.push_back(int_to_bytes<uint16_t>(data.length()));
    _attributes.push_back(attr.append(data));
}

void Message::set_length(size_t length) noexcept
{
    _length = length;
    auto length_bytes = int_to_bytes<uint16_t>(_length);
    _attributes.at(0)[2] = length_bytes[0];
    _attributes.at(0)[3] = length_bytes[1];
}

Client::Client(HostAddress server_addr) { _servers_list.push_back(server_addr); }

Client::Client(std::initializer_list<HostAddress> servers_list) { _servers_list = servers_list; }

void Client::add_server(HostAddress server) { _servers_list.push_back(server); }

HostAddress Client::get_addr_from_server(std::shared_ptr<QUdpSocket> socket, size_t server_index)
{
    Message msg { MsgClass::REQUEST, MsgMethod::BINDING };
    auto [ip, port] = _servers_list.at(server_index);
    socket->writeDatagram(msg.to_bytes(), QHostAddress(ip.c_str()), port);

    while (!socket->hasPendingDatagrams()) { }
    QByteArray response_raw {};
    response_raw.resize(BUFFER_SIZE);
    socket->readDatagram(response_raw.data(), BUFFER_SIZE);
    Message response { response_raw };

    if (auto addr_attr = response.find_attribute(stun::Attribute::MAPPED_ADDRESS); !addr_attr.isEmpty()) {
        return unpack_address(stun::Message::get_attribute_data(addr_attr));
    } else if (auto xor_addr_attr = response.find_attribute(stun::Attribute::XOR_MAPPED_ADDRESS); !xor_addr_attr.isEmpty()) {
        return unpack_address(stun::Message::get_attribute_data(xor_addr_attr), true);
    } else {
        throw std::runtime_error { "Can't find mapped address attribute in response" };
    }
}

NatType Client::get_nat_type(std::shared_ptr<QUdpSocket> socket)
{
    if (_servers_list.size() < 2) {
        throw std::logic_error { "STUN client should have more than 1 server to get NAT type" };
    }

    auto [ip, port] = this->get_addr_from_server(socket);
    for (size_t i = 1; i < _servers_list.size(); i++) {
        auto [another_ip, another_port] = this->get_addr_from_server(socket, i);
        if (ip != another_ip || port != another_port) {
            qInfo("[INFO] NAT type is symmetrict");
            return NatType::SYMMETRIC;
        }
    }

    qInfo("[INFO] NAT type is common");
    return NatType::COMMON;
}
