#pragma once

#include "common.hpp"

namespace hk {
namespace stun {

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

    auto unpack_address(QByteArray const&, bool is_xored = false) -> HostAddress;
    auto xor_address(HostAddress) -> QByteArray;

    class Message final {
    public:
        explicit Message(MsgClass, MsgMethod);
        explicit Message(QByteArray const&);
        ~Message() = default;

        auto get_class() const noexcept -> MsgClass;
        auto get_method() const noexcept -> MsgMethod;
        auto get_header() const noexcept -> QByteArray;
        auto get_length() const noexcept -> std::size_t;
        auto add_attribute(Attribute, QByteArray) -> void;
        auto find_attribute(Attribute) -> QByteArray;
        static QByteArray get_attribute_data(QByteArray const&);
        auto to_bytes() const noexcept -> QByteArray;
        auto add_integrity(QByteArray const& integrity_key) -> void;
        auto add_fingerprint() -> void;

    private:
        static auto get_attribute_size(QByteArray const&) -> std::size_t;
        auto push_attribute(Attribute, QByteArray) -> void;
        auto set_length(size_t length) noexcept -> void;

        MsgClass m_class;
        MsgMethod m_method;
        size_t m_length;
        std::vector<QByteArray> m_attributes;
    };

};
};
