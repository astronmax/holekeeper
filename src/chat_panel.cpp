#include <chat_panel.hpp>

#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QVBoxLayout>

MessageBlock::MessageBlock(std::string author, std::string msg_body)
{
    _author.setStyleSheet("font-weight: bold; font-size: 10pt");
    _author.setText(author.c_str());
    _msg_body.setText(msg_body.c_str());

    auto layout = new QVBoxLayout();
    layout->addWidget(&_author);
    layout->addWidget(&_msg_body);
    layout->setSizeConstraint(QLayout::SizeConstraint::SetFixedSize);

    setLayout(layout);
}

ChatPanel::ChatPanel(std::shared_ptr<Peer> peer, std::string chat_nickname)
{
    _peer = peer;

    _chat_nickname.setText(("Chat with: " + chat_nickname).c_str());
    _chat_nickname.setStyleSheet("font-weight: bold; font-size: 12pt");
    _chat_nickname.setAlignment(Qt::AlignCenter);

    _send_button.setText("Send");

    auto main_layout = new QVBoxLayout();
    main_layout->addWidget(&_chat_nickname);
    main_layout->addWidget(&_chat_field);

    auto bottom_layout = new QHBoxLayout();
    bottom_layout->addWidget(&_message_to_send);
    bottom_layout->addWidget(&_send_button);

    main_layout->addLayout(bottom_layout);
    main_layout->setStretch(1, 5);
    main_layout->setStretch(2, 1);
    setLayout(main_layout);
}

void ChatPanel::add_message(TextMessage const& msg)
{
    auto msg_block = new MessageBlock(msg.author, msg.body);

    auto item = new QListWidgetItem();
    item->setSizeHint(msg_block->sizeHint());

    _chat_field.addItem(item);
    _chat_field.setItemWidget(item, msg_block);
}

void ChatPanel::load(std::string chat_nickname)
{
    _chat_nickname.setText(("Chat with: " + chat_nickname).c_str());
    for (const auto& msg : _peer->get_message_storage().get_chat(chat_nickname)) {
        this->add_message(msg);
    }
}
