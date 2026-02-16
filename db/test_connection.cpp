#include <iostream>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

int main() {
    try {
        // Required once per process
        mongocxx::instance instance{};

        // Connect to MongoDB
        mongocxx::client client{
            mongocxx::uri{"mongodb://localhost:27017"}
        };

        auto db = client["zkp_service"];

        // Ping command
        auto result = db.run_command(
            bsoncxx::builder::stream::document{}
                << "ping" << 1
                << bsoncxx::builder::stream::finalize
        );

        std::cout << "MongoDB ping successful: "
                  << bsoncxx::to_json(result.view())
                  << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "MongoDB connection failed: "
                  << e.what() << std::endl;
        return 1;
    }
}
