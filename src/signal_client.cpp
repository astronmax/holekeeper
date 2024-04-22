#include <signal_client.hpp>
#include <stun.hpp>

QByteArray pack_peer_info(std::shared_ptr<PeerInfo> p_info)
{
    QByteArray packed_info {};
    packed_info.append(p_info->nickname);
    packed_info.push_back('\x00');
    packed_info.append(stun::xor_address(p_info->address));
    packed_info.push_back(static_cast<uint8_t>(p_info->nat_type));

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
    auto nat_type = NatType(static_cast<uint8_t>(packed_info[nickname.size() + 8]));

    return PeerInfo { nickname, addr, nat_type };
}

SignalClient::SignalClient(HostAddress signal_server)
{
    _socket = std::make_shared<QUdpSocket>();
    _signal_server = signal_server;
}

void SignalClient::add_peer_info(std::shared_ptr<PeerInfo> p_info)
{
    QByteArray request {};
    request.push_back('\x01');
    auto data = pack_peer_info(p_info);
    auto data_length = int_to_bytes<uint16_t>(data.length());
    request.append(data_length);
    request.append(data);

    const auto [ip, port] = _signal_server;
    _socket->writeDatagram(request, QHostAddress(ip.c_str()), port);
}

void SignalClient::find_online_peers()
{
    _peers_online.clear();
    const auto [ip, port] = _signal_server;
    _socket->writeDatagram(QByteArray("\x02"), QHostAddress(ip.c_str()), port);

    while (true) {
        QByteArray buf {};
        buf.resize(1024);

        while (!_socket->hasPendingDatagrams()) { }
        _socket->readDatagram(buf.data(), 1024);

        if (buf[0] == '\xFF' && buf[1] == '\xFF' && buf[2] == '\xFF' && buf[3] == '\xFF') {
            break;
        }

        qsizetype offset {};
        while (offset < buf.length()) {
            QByteArray length_raw {};
            length_raw.resize(2);
            std::copy(buf.begin() + offset, buf.begin() + offset + 2, length_raw.begin());
            auto length = bytes_to_int<uint16_t>(length_raw);
            if (length == 0) {
                break;
            }
            offset += 2;
            QByteArray packed_info {};
            packed_info.resize(length);
            std::copy(buf.begin() + offset, buf.begin() + offset + length, packed_info.begin());
            _peers_online.push_back(std::make_shared<PeerInfo>(unpack_peer_info(packed_info)));
            offset += length;
        }
    }
}

std::vector<std::shared_ptr<PeerInfo>>& SignalClient::get_online_peers() { return _peers_online; }

HostAddress SignalClient::get_server_addr() const { return _signal_server; }
