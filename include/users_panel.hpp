#pragma once

#include <common.hpp>
#include <signal_client.hpp>

#include <QtCore/QTimer>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTableWidgetItem>

class UsersPanel final : public QTabWidget {
    Q_OBJECT

public:
    explicit UsersPanel(ConfigManager&, std::shared_ptr<Peer>);
    ~UsersPanel() = default;

public slots:
    void refresh_online_users(int);
    void start_registering(QListWidgetItem*);
    void add_user(std::string);

private:
    std::shared_ptr<Peer> _peer;
    SignalClient _signal_client;
    QListWidget _online_users_tab;
    QListWidget _chats_tab;
    QTimer _info_send_timer;
    QTimer _ping_users_timer;
};
