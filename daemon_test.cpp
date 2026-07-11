#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("pong", "text/plain");
    });

    std::cout << "Daemon listening on http://127.0.0.1:8080\n";
    svr.listen("127.0.0.1", 8080);

    return 0;
}