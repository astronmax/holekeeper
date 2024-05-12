#include <basic_peer.hpp>
#include <turn_peer.hpp>

#include <main_window.hpp>

#include <QtWidgets/QApplication>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);

    ConfigManager config_manager { "settings.json" };
    std::shared_ptr<Peer> peer;
    if (config_manager.turn_using()) {
        qInfo() << "[INFO] Using TURN server";
        peer = std::make_shared<TurnPeer>(config_manager);
    } else {
        qInfo() << "[INFO] Making p2p connection";
        peer = std::make_shared<BasicPeer>(config_manager);
    }

    MainWindow main_window { config_manager, peer };
    main_window.show();

    return app.exec();
}
