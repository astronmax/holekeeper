#include <common.hpp>
#include <stun.hpp>

#include <QtCore/QMessageAuthenticationCode>

#include <random>

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
        throw std::invalid_argument { "Invalid message" };
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
        throw std::invalid_argument { "Bad attribute value" };
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
