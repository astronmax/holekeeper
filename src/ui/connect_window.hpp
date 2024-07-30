#pragma once

#include "../abstract_channel.hpp"
#include "../common.hpp"

#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

#include <memory>

namespace hk {

class ConnectWindow final : public QWidget {
    Q_OBJECT

public:
    explicit ConnectWindow(std::shared_ptr<AbstractChannel>);

private:
    auto show_ui() -> void;

private:
    std::shared_ptr<AbstractChannel> m_channel;
    QLineEdit m_peer_info_form;
    QPushButton m_copy_info_btn;
    QPushButton m_connect_btn;
};

};
