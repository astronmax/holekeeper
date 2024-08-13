#include "chat_window.hpp"

#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QVBoxLayout>

using namespace hk;

ChatWindow::ChatWindow(std::shared_ptr<hk::AbstractChannel> channel)
    : m_channel { channel } {

    // setup UI
    m_send_button.setText("Send");

    auto bottom_layout = new QHBoxLayout();
    bottom_layout->addWidget(&m_message_field);
    bottom_layout->addWidget(&m_send_button);

    auto main_layout = new QVBoxLayout();
    main_layout->addWidget(&m_chat_field);
    main_layout->addLayout(bottom_layout);
    main_layout->setStretch(0, 5);
    main_layout->setStretch(1, 1);
    setLayout(main_layout);

    // connect window show on peer_connected event
    m_connect_window = std::make_shared<ConnectWindow>(m_channel);
    connect(m_channel.get(), &AbstractChannel::peer_connected, this, [this]() {
        m_connect_window->close();
        m_ping_timer.start(5'000);
        show();
    });

    // connect displaying of received messages
    connect(m_channel.get(), &AbstractChannel::data_received, this,
        [this](std::string nickname, QByteArray const& raw_data) {
            display_message(new MessageBlock(nickname, raw_data.toStdString()));
        });

    // connect messages sending
    connect(&m_send_button, &QPushButton::clicked, this, [this]() {
        auto msg_body = m_message_field.toPlainText().toUtf8();
        m_channel->send(msg_body);
        m_message_field.clear();
        display_message(new MessageBlock(m_channel->get_peer_info()->nickname, msg_body.toStdString()));
    });

    // connect ping timer
    connect(&m_ping_timer, &QTimer::timeout, this, [this]() {
        m_channel->send_ping();
        m_ping_timer.start(5'000);
    });
}

auto ChatWindow::display_message(MessageBlock* msg_block) -> void {
    auto item = new QListWidgetItem();
    item->setSizeHint(msg_block->sizeHint());
    m_chat_field.addItem(item);
    m_chat_field.setItemWidget(item, msg_block);
}

MessageBlock::MessageBlock(std::string nickname, std::string msg_body) {
    m_nickname.setStyleSheet("font-weight: bold; font-size: 10pt");
    m_nickname.setText(nickname.c_str());
    m_msg_body.setText(msg_body.c_str());

    auto layout = new QVBoxLayout();
    layout->addWidget(&m_nickname);
    layout->addWidget(&m_msg_body);
    layout->setSizeConstraint(QLayout::SizeConstraint::SetFixedSize);

    setLayout(layout);
}
