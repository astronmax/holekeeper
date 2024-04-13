#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace boost::asio::ip;
using namespace std::chrono_literals;

using BinStruct = std::vector<uint8_t>;
using ClientData = std::pair<BinStruct, std::chrono::system_clock::time_point>;
using ClientsList = std::unordered_map<udp::endpoint, ClientData>;

struct SignalServer final {
public:
    explicit SignalServer(std::string, uint16_t, size_t n_threads = 4);
    ~SignalServer() = default;
    void start();

private:
    void process_add(BinStruct, udp::endpoint);
    void process_get(udp::endpoint);
    void check_activity();

private:
    constexpr static size_t BUFFER_SIZE = 1024;
    boost::asio::io_context _io_ctx;
    udp::socket _socket;
    boost::asio::thread_pool _thread_pool;
    ClientsList _clients;
    std::mutex _clients_mtx;
};

SignalServer::SignalServer(std::string ip, uint16_t port, size_t n_threads)
    : _io_ctx {}
    , _socket { _io_ctx, udp::endpoint(address::from_string(ip.c_str()), port) }
    , _thread_pool { n_threads }
{
}

void SignalServer::start()
{
    std::thread checking_thread([this]() {
        while (true) {
            std::this_thread::sleep_for(30s);
            this->check_activity();
        }
    });

    while (true) {
        BinStruct buf(BUFFER_SIZE);
        udp::endpoint remote_ep;
        _socket.receive_from(boost::asio::buffer(buf), remote_ep);
        switch (buf.at(0)) {
        case 0x01:
            boost::asio::post(_thread_pool, [this, buf, remote_ep]() {
                this->process_add(buf, remote_ep);
            });
            break;

        case 0x02:
            boost::asio::post(_thread_pool, [this, remote_ep]() {
                this->process_get(remote_ep);
            });
            break;

        default:
            continue;
        }
    }
}

void SignalServer::process_add(BinStruct buf, udp::endpoint remote_ep)
{
    if (buf.size() < 3) {
        return;
    }

    size_t length = (buf.at(1) << 8) | buf.at(2);
    if (length > 0 && length < BUFFER_SIZE - 3) {
        BinStruct binary_struct(length);
        std::copy(buf.begin() + 3, buf.begin() + 3 + length, binary_struct.begin());

        _clients_mtx.lock();
        auto time_now = std::chrono::high_resolution_clock::now();
        _clients[remote_ep] = std::make_pair(binary_struct, time_now);
        _clients_mtx.unlock();
    }

    spdlog::info("Add data from {}:{}", remote_ep.address().to_string(), remote_ep.port());
}

void SignalServer::process_get(udp::endpoint remote_ep)
{
    spdlog::info("Send data to {}:{}", remote_ep.address().to_string(), remote_ep.port());
    BinStruct response {};
    size_t offset {};
    _clients_mtx.lock();
    for (auto [client_addr, client_data] : _clients) {
        auto frame = client_data.first;
        if ((offset + frame.size() + 2) > BUFFER_SIZE) {
            _socket.send_to(boost::asio::buffer(response, response.size()), remote_ep);
            response.clear();
            offset = 0;
        }

        response.push_back(frame.size() >> 8);
        response.push_back(frame.size() & 0xFF);

        response.reserve(frame.size());
        response.insert(response.end(), frame.begin(), frame.end());

        offset += 2 + frame.size();
    }
    _clients_mtx.unlock();

    if (!response.empty()) {
        _socket.send_to(boost::asio::buffer(response, response.size()), remote_ep);
    }
    _socket.send_to(boost::asio::buffer("\xFF\xFF\xFF\xFF", 4), remote_ep);
}

void SignalServer::check_activity()
{
    std::vector<udp::endpoint> clients_to_remove;
    _clients_mtx.lock();
    auto time_now = std::chrono::high_resolution_clock::now();
    for (auto [client_addr, client_data] : _clients) {
        auto last_request_time = client_data.second;
        if (time_now - last_request_time > 30s) {
            clients_to_remove.push_back(client_addr);
        }
    }

    for (auto c : clients_to_remove) {
        _clients.erase(c);
    }
    _clients_mtx.unlock();

    std::for_each(clients_to_remove.begin(), clients_to_remove.end(), [](auto c) {
        spdlog::info("Remove client {}:{}", c.address().to_string(), c.port());
    });
    spdlog::info("Clients online: {}", _clients.size());
}

int main()
{
    auto signal_server = SignalServer("0.0.0.0", 5000);
    signal_server.start();
    return 0;
}
