#include <users_panel.hpp>

UsersPanel::UsersPanel(ConfigManager& config_manager, std::shared_ptr<Peer> peer)
    : _signal_client { config_manager.get_signal_server() }
{
    _peer = peer;
    _signal_client.add_peer_info(_peer->get_info());
    addTab(&_chats_tab, "Chats");
    addTab(&_online_users_tab, "Online");

    connect(&_info_send_timer, &QTimer::timeout, this, [this]() {
        _signal_client.add_peer_info(_peer->get_info());
        _info_send_timer.start(25'000);
    });
    _info_send_timer.start(25'000);

    connect(&_ping_users_timer, &QTimer::timeout, this, [this]() {
        _peer->ping_active_peers();
        _ping_users_timer.start(10'000);
    });
    _ping_users_timer.start(10'000);

    connect(this, &QTabWidget::tabBarClicked, this, &UsersPanel::refresh_online_users);
    connect(&_online_users_tab, &QListWidget::itemDoubleClicked, this, &UsersPanel::start_registering);
    connect(_peer.get(), &Peer::peer_registered, this, &UsersPanel::add_user);
    connect(&_chats_tab, &QListWidget::itemClicked, this, &UsersPanel::emit_chat_switched);
}

void UsersPanel::refresh_online_users(int index)
{
    if (index == 1) {
        _online_users_tab.clear();
        _signal_client.find_online_peers();
        for (auto user : _signal_client.get_online_peers()) {
            user.nickname.erase(std::remove(user.nickname.begin(), user.nickname.end(), '\x00'), user.nickname.end());
            if (user.nickname != _peer->get_info().nickname) {
                _online_users_tab.addItem(user.nickname.c_str());
            }
        }
    }
}

void UsersPanel::start_registering(QListWidgetItem* clicked_item)
{
    for (auto user : _signal_client.get_online_peers()) {
        user.nickname.erase(std::remove(user.nickname.begin(), user.nickname.end(), '\x00'), user.nickname.end());
        if (user.nickname == clicked_item->text().toStdString()) {
            _peer->register_peer(user);
        }
    }
}

void UsersPanel::add_user(std::string nickname)
{
    for (size_t i {}; i < static_cast<size_t>(_chats_tab.count()); i++) {
        auto user = _chats_tab.takeItem(i);
        _chats_tab.insertItem(i, user);
        if (user->text().toStdString() == nickname) {
            return;
        }
    }

    _chats_tab.addItem(nickname.c_str());
}

void UsersPanel::emit_chat_switched(QListWidgetItem* clicked_item)
{
    emit chat_switched(clicked_item->text());
}
