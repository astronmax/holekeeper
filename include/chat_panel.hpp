#pragma once

#include <common.hpp>

#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>

class MessageBlock final : public QWidget {
    Q_OBJECT

public:
    explicit MessageBlock(std::string, std::string);
    ~MessageBlock() = default;

private:
    QLabel _author;
    QLabel _msg_body;
};

class ChatPanel final : public QWidget {
    Q_OBJECT

public:
    explicit ChatPanel(std::shared_ptr<Peer>, std::string);
    ~ChatPanel() = default;

    void add_message(std::string, std::string);
    void load(std::string);

signals:
    void send_button_clicked(QString);

public slots:
    void emit_send_signal();

private:
    std::shared_ptr<Peer> _peer;
    QLabel _chat_nickname;
    QListWidget _chat_field;
    QTextEdit _message_to_send;
    QPushButton _send_button;
};
