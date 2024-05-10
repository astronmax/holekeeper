#include <msg_storage.hpp>

void MessageStorage::add_message(std::string chat_name, std::string dst, std::string body)
{
    auto datetime = QDateTime::currentDateTime();
    _chats[chat_name].push_back(TextMessage { dst, datetime, body });
}

MessagesList& MessageStorage::get_chat(std::string chat_name) { return _chats[chat_name]; }
