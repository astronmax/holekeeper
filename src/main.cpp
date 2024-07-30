#include "config_parser.hpp"
#include "turn_channel.hpp"
#include "ui/chat_window.hpp"

#include <QtWidgets/QApplication>

auto main(int argc, char* argv[]) -> int {
    QApplication app { argc, argv };

    hk::ConfigParser config_parser { "settings.json" };
    auto channel = std::make_shared<hk::TurnChannel>(config_parser);

    hk::ChatWindow chat_window { channel };

    return app.exec();
}
