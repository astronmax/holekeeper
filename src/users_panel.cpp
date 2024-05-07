#include <users_panel.hpp>

UsersPanel::UsersPanel(ConfigManager& config_manager, std::shared_ptr<Peer> peer)
    : _signal_client { config_manager.get_signal_server() }
{
    _peer = peer;
    _signal_client.add_peer_info(_peer->get_info());
    addTab(&_chats_tab, "Chats");
    addTab(&_online_users_tab, "Online");

    connect(this, &QTabWidget::tabBarClicked, this, &UsersPanel::refresh_online_users);
    connect(_peer.get(), &Peer::peer_registered, this, &UsersPanel::add_user);
}

void UsersPanel::refresh_online_users(int index)
{
    // if tab "Online" was clicked
    if (index == 1) {
        _online_users_tab.clear();
        _signal_client.find_online_peers();
        for (const auto& user : _signal_client.get_online_peers()) {
            _online_users_tab.addItem(user.nickname.c_str());
        }
    }
}

void UsersPanel::start_registering(QListWidgetItem* clicked_item)
{
    for (const auto& user : _signal_client.get_online_peers()) {
        if (user.nickname == clicked_item->text().toStdString()) {
            _peer->register_peer(user);
        }
    }
}

void UsersPanel::add_user(std::string nickname)
{
}
