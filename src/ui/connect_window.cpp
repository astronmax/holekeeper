#include "connect_window.hpp"

#include <QtGui/QClipboard>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>

using namespace hk;

ConnectWindow::ConnectWindow(std::shared_ptr<AbstractChannel> channel) {
    m_channel = channel;
    connect(m_channel.get(), &AbstractChannel::channel_ready, this, &ConnectWindow::show_ui);
    connect(&m_copy_info_btn, &QPushButton::clicked, this, [this]() {
        auto channel_info = m_channel->get_self_info()->to_base64().toStdString();
        auto clipboard = QApplication::clipboard();
        clipboard->setText(channel_info.c_str());
    });
    connect(&m_connect_btn, &QPushButton::clicked, this, [this]() {
        auto peer_info_str = m_peer_info_form.text();
        auto peer_info = std::make_shared<ChannelInfo>(ChannelInfo::from_base64(peer_info_str.toUtf8()));
        m_channel->connect_peer(peer_info);
    });
}

auto ConnectWindow::show_ui() -> void {
    auto layout = new QHBoxLayout();

    auto left_layout = new QVBoxLayout();
    auto channel_info = m_channel->get_self_info()->to_base64().toHex().toStdString();
    left_layout->addWidget(new QLineEdit(channel_info.c_str()));
    left_layout->addWidget(&m_peer_info_form);
    layout->addLayout(left_layout);

    auto right_layout = new QVBoxLayout();
    m_copy_info_btn.setText("Copy");
    right_layout->addWidget(&m_copy_info_btn);
    m_connect_btn.setText("Connect");
    right_layout->addWidget(&m_connect_btn);
    layout->addLayout(right_layout);

    setLayout(layout);
    show();
}
