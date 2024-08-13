#pragma once

#include "connect_window.hpp"

#include <QtCore/QTimer>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>

namespace hk {

class MessageBlock final : public QWidget {
    Q_OBJECT

public:
    explicit MessageBlock(std::string, std::string);

private:
    QLabel m_nickname;
    QLabel m_msg_body;
};

class ChatWindow final : public QWidget {
    Q_OBJECT

public:
    explicit ChatWindow(std::shared_ptr<hk::AbstractChannel>);

private:
    auto display_message(MessageBlock*) -> void;

private:
    std::shared_ptr<AbstractChannel> m_channel;
    std::shared_ptr<hk::ConnectWindow> m_connect_window;

    QListWidget m_chat_field;
    QTextEdit m_message_field;
    QPushButton m_send_button;
    QTimer m_ping_timer;
};

};
