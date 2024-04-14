#include <peer.hpp>

QByteArray pack_peer_info(PeerInfo p_info)
{
    QByteArray packed_info {};
    packed_info.append(p_info->nickname);
    packed_info.push_back('\x00');

    packed_info.append(stun::xor_address(p_info->address));
    return packed_info;
}

PeerInfo unpack_peer_info(QByteArray packed_info)
{
    std::string nickname {};
    for (auto b : packed_info) {
        nickname.push_back(b);
        if (b == '\x00') {
            break;
        }
    }

    QByteArray addr_raw {};
    addr_raw.resize(8);
    std::copy(packed_info.begin() + nickname.size(),
        packed_info.begin() + nickname.size() + 8, addr_raw.begin());

    auto addr = stun::unpack_address(addr_raw, true);
    return std::make_shared<PeerInfoType>(PeerInfoType { nickname, addr });
}
