#include <main_window.hpp>

#include <QtWidgets/QHBoxLayout>

MainWindow::MainWindow(ConfigManager& config_manage, std::shared_ptr<Peer> peer)
    : _users_panel { config_manage, peer }
    , _chat_panel { peer, "" }
{
    _peer = peer;

    auto layout = new QHBoxLayout();
    layout->addWidget(&_users_panel);
    layout->addWidget(&_chat_panel);

    layout->setStretch(0, 1);
    layout->setStretch(1, 3);

    setLayout(layout);

    connect(&_users_panel, &UsersPanel::chat_switched, this, &MainWindow::load_chat);
    connect(_peer.get(), &Peer::data_received, this, &MainWindow::append_received_msg);
    connect(&_chat_panel, &ChatPanel::send_button_clicked, this, &MainWindow::send_message);
}

void MainWindow::load_chat(QString peer_nickname)
{
    _chat_nickname = peer_nickname.toStdString();
    _chat_panel.load(_chat_nickname);
}

void MainWindow::append_received_msg(QByteArray data, std::string nickname)
{
    _chat_panel.add_message(nickname, data.toStdString());
}

void MainWindow::send_message(QString msg_to_send)
{
    auto address = _peer->get_active_peers().value(_chat_nickname);
    _peer->send_data(msg_to_send.toUtf8(), address);
    _chat_panel.add_message(_peer->get_info().nickname, msg_to_send.toStdString());
}
