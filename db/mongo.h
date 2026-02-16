#pragma once

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>

class Mongo {
public:
    static Mongo& instance() {
        static Mongo mongo;
        return mongo;
    }

    mongocxx::database db() {
        return client_["zkp_service"];
    }

private:
    Mongo()
        : instance_{},
          client_{mongocxx::uri{"mongodb://localhost:27017"}} {}

    mongocxx::instance instance_;
    mongocxx::client client_;
};
