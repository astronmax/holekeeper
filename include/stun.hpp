#pragma once

#include <common.hpp>

#include <QtCore/QByteArray>
#include <QtNetwork/QUdpSocket>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace stun {

constexpr size_t COOKIE = 0x2112A442;
constexpr size_t FINGERPRINT_LENGTH = 8;
constexpr size_t FINGERPRINT_XOR = 0x5354554E;
constexpr size_t HEADER_LENGTH = 20;
constexpr size_t INTEGRITY_LENGTH = 24;
constexpr size_t IPV4_PROTOCOL = 1;
constexpr size_t IPV6_PROTOCOL = 2;

enum class MsgClass {
    REQUEST = 0x000,
    INDICATION = 0x010,
    RESPONSE = 0x100,
    ERROR = 0x110,
};

enum class MsgMethod {
    BINDING = 0x1,
    ALLOCATE = 0x3,
    REFRESH = 0x4,
    SEND = 0x6,
    DATA = 0x7,
    CREATE_PERMISSION = 0x8,
    CHANNEL_BIND = 0x9,
};

enum class Attribute {
    MAPPED_ADDRESS = 0x0001,
    CHANGE_REQUEST = 0x0003,
    SOURCE_ADDRESS = 0x0004,
    CHANGED_ADDRESS = 0x0005,
    USERNAME = 0x0006,
    MESSAGE_INTEGRITY = 0x0008,
    ERROR_CODE = 0x0009,
    CHANNEL_NUMBER = 0x000C,
    LIFETIME = 0x000D,
    XOR_PEER_ADDRESS = 0x0012,
    DATA = 0x0013,
    REALM = 0x0014,
    NONCE = 0x0015,
    XOR_RELAYED_ADDRESS = 0x0016,
    REQUESTED_TRANSPORT = 0x0019,
    XOR_MAPPED_ADDRESS = 0x0020,
    PRIORITY = 0x0024,
    USE_CANDIDATE = 0x0025,
    SOFTWARE = 0x8022,
    FINGERPRINT = 0x8028,
    ICE_CONTROLLED = 0x8029,
    ICE_CONTROLLING = 0x802A,
    RESPONSE_ORIGIN = 0x802B,
    OTHER_ADDRESS = 0x802C,
};

HostAddress unpack_address(QByteArray, bool is_xored = false);
QByteArray xor_address(HostAddress);

class Message final {
public:
    explicit Message(MsgClass, MsgMethod);
    explicit Message(QByteArray);
    ~Message() = default;

public:
    MsgClass get_class() const noexcept;
    MsgMethod get_method() const noexcept;
    QByteArray get_header() const noexcept;
    size_t get_length() const noexcept;
    void add_attribute(Attribute, QByteArray);
    QByteArray find_attribute(Attribute);
    static QByteArray get_attribute_data(QByteArray);
    QByteArray to_bytes() const noexcept;
    void add_integrity(QByteArray integrity_key);
    void add_fingerprint();

private:
    static size_t get_attribute_size(QByteArray);
    void push_attribute(Attribute, QByteArray);
    void set_length(size_t length) noexcept;

private:
    MsgClass _class;
    MsgMethod _method;
    size_t _length;
    std::vector<QByteArray> _attributes;
};

HostAddress get_address(std::shared_ptr<QUdpSocket>, HostAddress);
NatType get_nat_type(std::initializer_list<HostAddress>);

};
