#include "abstract_channel.hpp"

using namespace hk;

auto ChannelInfo::to_base64() -> QByteArray {
    auto info_str = QString("%1;%2;%3;%4")
                        .arg(nickname.c_str(), address.first.c_str(),
                            QString::number(address.second),
                            QString::number(static_cast<std::uint8_t>(holepunching)));

    return info_str.toUtf8().toBase64();
}

auto ChannelInfo::from_base64(QByteArray const& base64) -> ChannelInfo {
    auto info_str = QByteArray::fromBase64(base64).toStdString();
    std::size_t pos {};
    std::vector<std::string> tokens;
    while ((pos = info_str.find(';')) != std::string::npos) {
        tokens.push_back(info_str.substr(0, pos));
        info_str.erase(0, pos + 1);
    }
    tokens.push_back(info_str);

    if (tokens.size() != 4) {
        throw std::runtime_error { "Invalid channel info format" };
    }

    ChannelInfo info {};
    info.nickname = tokens.at(0);
    info.address.first = tokens.at(1);
    info.address.second = std::stoi(tokens.at(2));
    info.holepunching = tokens.at(3) == "0" ? false : true;
    return info;
}

auto AbstractChannel::send(QByteArray const& data) -> void {
    QByteArray raw_data {};
    raw_data.append(get_self_info()->nickname.c_str());
    raw_data.push_back('\x00');
    raw_data.append(data);

    if (raw_data.length() % 4 != 0) {
        raw_data.append(QByteArray().fill('\x00', 4 - (raw_data.length() % 4)));
    }

    send_data(raw_data);
}

auto AbstractChannel::send_ping() -> void {
    m_peer_connected = false;
    send(QByteArray("\xAA\xAA\xAA\xAA"));
    start_ping_timer();
}

auto AbstractChannel::send_pong() -> void {
    send(QByteArray("\xAA\xAA\xAA\xAA"));
    stop_ping_timer();
}

auto AbstractChannel::get_self_info() -> std::shared_ptr<ChannelInfo> { return m_self_info; }
auto AbstractChannel::get_peer_info() -> std::shared_ptr<ChannelInfo> { return m_peer_info; }

auto AbstractChannel::process_data(QByteArray const& data) -> void {
    std::string nickname {};
    qsizetype i {};
    for (; i < data.size(); i++) {
        if (data[i] == '\0') {
            i++;
            break;
        }
        nickname += data[i];
    }

    QByteArray raw_msg {};
    raw_msg.resize(data.size() - i);
    std::copy(data.begin() + i, data.end(), raw_msg.begin());

    if (nickname == m_peer_info->nickname) {
        if (m_peer_connected == false) {
            if (raw_msg[0] == '\xAA' && raw_msg[1] == '\xAA'
                && raw_msg[2] == '\xAA' && raw_msg[3] == '\xAA') {

                qInfo() << "[INFO] Get ping from" << nickname;
                send_pong();

                emit peer_connected();
                m_peer_connected = true;
                return;
            }
        } else {
            if (raw_msg[0] != '\xAA' || raw_msg[1] != '\xAA'
                || raw_msg[2] != '\xAA' || raw_msg[3] != '\xAA') {

                emit data_received(nickname, raw_msg);
            }
        }
    }
}

auto AbstractChannel::start_ping_timer() -> void {
    m_ping_timer = std::make_unique<QTimer>();
    connect(m_ping_timer.get(), &QTimer::timeout, this, [this]() {
        send(QByteArray("\xAA\xAA\xAA\xAA"));
        m_ping_attempts--;
        qInfo() << "[INFO] Ping peer, attempts:" << m_ping_attempts;
        if (m_ping_attempts == 0) {
            throw std::runtime_error { "Can't establish connection with peer" };
        } else {
            m_ping_timer->start(5'000);
        }
    });
    m_ping_timer->start(5'000);
}

auto AbstractChannel::stop_ping_timer() -> void {
    m_ping_attempts = 5;
    m_ping_timer.reset();
}
