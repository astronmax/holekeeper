#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <QtCore/QDateTime>

struct TextMessage {
    std::string author;
    QDateTime datetime;
    std::string body;
};

using MessagesList = std::vector<TextMessage>;

class MessageStorage final {
public:
    explicit MessageStorage() = default;
    ~MessageStorage() = default;

    void add_message(std::string, std::string, std::string);
    MessagesList& get_chat(std::string);

private:
    std::unordered_map<std::string, MessagesList> _chats;
};
