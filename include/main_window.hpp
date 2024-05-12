#pragma once

#include <chat_panel.hpp>
#include <users_panel.hpp>

#include <QtWidgets/QMainWindow>

class MainWindow final : public QWidget {
    Q_OBJECT

public:
    explicit MainWindow(ConfigManager&, std::shared_ptr<Peer>);
    ~MainWindow() = default;

public slots:
    void load_chat(QString);
    void append_received_msg(QByteArray, std::string);
    void send_message(QString);

private:
    std::shared_ptr<Peer> _peer;
    std::string _chat_nickname;
    UsersPanel _users_panel;
    ChatPanel _chat_panel;
};
