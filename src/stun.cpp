#include "stun.hpp"
#include "common.hpp"

#include <cstddef>
#include <random>
#include <sstream>

#include <QtCore/QCryptographicHash>
#include <QtCore/QMessageAuthenticationCode>

using namespace hk;

constexpr size_t COOKIE = 0x2112A442;
constexpr size_t FINGERPRINT_LENGTH = 8;
constexpr size_t FINGERPRINT_XOR = 0x5354554E;
constexpr size_t HEADER_LENGTH = 20;
constexpr size_t INTEGRITY_LENGTH = 24;
constexpr size_t IPV4_PROTOCOL = 1;
// constexpr size_t IPV6_PROTOCOL = 2;

auto calc_crc32(QByteArray const& data) -> std::uint32_t {
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

auto create_transaction_id() -> QByteArray {
    auto transaction_id = int_to_bytes<uint32_t>(COOKIE);

    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, 255);
    for (size_t i = 0; i < 12; i++) {
        transaction_id.push_back(dist(rng));
    }

    return transaction_id;
}

auto hk::stun::unpack_address(QByteArray const& data, bool is_xored) -> HostAddress {
    QByteArray family_raw {};
    family_raw.resize(2);
    std::copy(data.begin(), data.begin() + 2, family_raw.begin());
    if (bytes_to_int<uint16_t>(family_raw) != IPV4_PROTOCOL) {
        throw std::invalid_argument { "IPv6 address not supported" };
    }

    // unpack port
    QByteArray xport_raw {};
    xport_raw.resize(2);
    std::copy(data.begin() + 2, data.begin() + 4, xport_raw.begin());
    uint16_t port {};
    if (is_xored) {
        port = bytes_to_int<uint16_t>(xport_raw) ^ static_cast<uint16_t>(COOKIE >> 16);
    } else {
        port = bytes_to_int<uint16_t>(xport_raw);
    }

    // unpack ip
    QByteArray xaddr_raw {};
    xaddr_raw.resize(4);
    std::copy(data.begin() + 4, data.end(), xaddr_raw.begin());
    const auto cookie_raw = int_to_bytes<uint32_t>(COOKIE);
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

auto hk::stun::xor_address(HostAddress addr) -> QByteArray {
    const auto [ip_addr, port] = addr;
    QByteArray xor_peer_addr {};
    xor_peer_addr.push_back(int_to_bytes<uint16_t>(IPV4_PROTOCOL));
    xor_peer_addr.push_back(int_to_bytes<uint16_t>(port ^ (COOKIE >> 16)));

    auto cookie_raw = int_to_bytes<uint32_t>(COOKIE);
    std::stringstream ss { ip_addr };
    std::string octet;
    size_t i {};
    while (std::getline(ss, octet, '.')) {
        xor_peer_addr.push_back(std::atoi(octet.c_str()) ^ cookie_raw[i]);
        i++;
    }

    return xor_peer_addr;
}

stun::Message::Message(MsgClass msg_class, MsgMethod msg_method) {
    m_class = msg_class;
    m_method = msg_method;
    m_length = 0;

    QByteArray header {};
    const auto msg_type = static_cast<uint16_t>(msg_class) + static_cast<uint16_t>(msg_method);
    header.push_back(int_to_bytes<uint16_t>(msg_type));
    header.push_back('\x00');
    header.push_back('\x00');
    header.push_back(create_transaction_id());
    m_attributes.push_back(header);
}

stun::Message::Message(QByteArray const& data) {
    if (static_cast<size_t>(data.length()) < HEADER_LENGTH) {
        throw std::invalid_argument { "Invalid STUN message" };
    }

    // add header
    QByteArray header {};
    header.resize(HEADER_LENGTH);
    std::copy(data.begin(), data.begin() + HEADER_LENGTH, header.begin());
    m_attributes.push_back(header);

    // message type
    QByteArray msg_type_raw {};
    msg_type_raw.resize(2);
    std::copy(data.begin(), data.begin() + 2, msg_type_raw.begin());
    const auto msg_type = bytes_to_int<uint16_t>(msg_type_raw);
    m_class = MsgClass(msg_type & 0xFFF0);
    m_method = MsgMethod(msg_type & 0xF);

    // message length
    QByteArray msg_len_raw {};
    msg_len_raw.resize(2);
    std::copy(data.begin() + 2, data.begin() + 4, msg_len_raw.begin());
    m_length = bytes_to_int<uint16_t>(msg_len_raw);
    if (m_length % 4 != 0) {
        throw std::invalid_argument { "Bad STUN message value" };
    }

    size_t offset = HEADER_LENGTH, pos {};
    while (pos < m_length) {
        QByteArray attr_len_raw {};
        attr_len_raw.resize(4);
        std::copy(data.begin() + offset, data.begin() + offset + 4, attr_len_raw.begin());
        const auto attr_len = Message::get_attribute_size(attr_len_raw) + 4;

        // copy attribute
        QByteArray attr {};
        for (size_t i {}; i < attr_len; i++) {
            attr.push_back(data[offset + i]);
        }
        m_attributes.push_back(attr);

        offset += attr_len;
        pos += attr_len;
    }
}

auto stun::Message::get_class() const noexcept -> stun::MsgClass { return m_class; }
auto stun::Message::get_method() const noexcept -> stun::MsgMethod { return m_method; }
auto stun::Message::get_header() const noexcept -> QByteArray { return m_attributes.at(0); }
auto stun::Message::get_length() const noexcept -> std::size_t { return m_length; }

auto stun::Message::add_attribute(stun::Attribute attr_type, QByteArray data) -> void {
    this->push_attribute(attr_type, data);
    this->set_length(m_length + 4 + data.length());
}

auto stun::Message::find_attribute(Attribute needed_attr_type) -> QByteArray {
    auto it = std::find_if(m_attributes.begin(), m_attributes.end(), [&](QByteArray raw_data) {
        QByteArray attr_type_bytes {};
        attr_type_bytes.push_back(raw_data[0]);
        attr_type_bytes.push_back(raw_data[1]);
        auto attr_type = bytes_to_int<uint16_t>(attr_type_bytes);
        return attr_type == static_cast<uint16_t>(needed_attr_type);
    });

    if (it == m_attributes.end()) {
        return QByteArray();
    } else {
        return *it;
    }
}

auto stun::Message::get_attribute_data(QByteArray const& attribute) -> QByteArray {
    const auto attr_length = Message::get_attribute_size(attribute);
    QByteArray data {};
    data.resize(attr_length);
    std::copy(attribute.begin() + 4, attribute.end(), data.begin());

    return data;
}

auto stun::Message::to_bytes() const noexcept -> QByteArray {
    QByteArray bytes {};
    std::for_each(m_attributes.begin(), m_attributes.end(), [&](QByteArray data) { bytes.push_back(data); });
    return bytes;
}

auto stun::Message::add_integrity(QByteArray const& integrity_key) -> void {
    this->set_length(m_length + INTEGRITY_LENGTH);
    QMessageAuthenticationCode mac { QCryptographicHash::Algorithm::Sha1 };
    mac.setKey(integrity_key);
    mac.addData(this->to_bytes());

    this->push_attribute(Attribute::MESSAGE_INTEGRITY, mac.result());
}

auto stun::Message::add_fingerprint() -> void {
    this->set_length(m_length + FINGERPRINT_LENGTH);
    const auto fingerprint = int_to_bytes<uint32_t>(calc_crc32(this->to_bytes()) ^ FINGERPRINT_XOR);
    this->push_attribute(Attribute::FINGERPRINT, fingerprint);
}

auto stun::Message::get_attribute_size(QByteArray const& attribute) -> std::size_t {
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

auto stun::Message::push_attribute(Attribute attr_type, QByteArray data) -> void {
    auto attr = int_to_bytes(static_cast<uint16_t>(attr_type));
    attr.push_back(int_to_bytes<uint16_t>(data.length()));
    m_attributes.push_back(attr.append(data));
}

auto stun::Message::set_length(size_t length) noexcept -> void {
    m_length = length;
    const auto length_bytes = int_to_bytes<uint16_t>(m_length);
    m_attributes.at(0)[2] = length_bytes[0];
    m_attributes.at(0)[3] = length_bytes[1];
}
