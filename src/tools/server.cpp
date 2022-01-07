#include <App.h>
#include <string>
#include <mutex>
#include <thread>
#include <string_view>
#include <atomic>
#include <experimental/filesystem>
#include "../core/logger.hpp"
#include "../core/crypto.hpp"
#include "../core/host_manager.hpp"
#include "../core/helpers.hpp"
#include "../core/bloomfilter.hpp"
#include "../core/api.hpp"
#include "../core/crypto.hpp"
#include "../server/request_manager.hpp"
#include "../core/config.hpp"
using namespace std;



int main(int argc, char **argv) {  

    json config = getConfig(argc, argv);

    srand(time(0));
    string myName = randomString(25);
    int port = 3000;
    HostManager hosts(config, myName);
    RequestManager manager(hosts);
    
    auto logsHandler = [&manager](auto *res, auto *req) {
        try {
            string s = "";
            for(auto str : Logger::buffer) {
                s += str + "<br/>";
            }
            res->writeHeader("Content-Type", "text/html; charset=utf-8")->end(s);
        } catch(const std::exception &e) {
            Logger::logError("/logs", e.what());
        } catch(...) {
            Logger::logError("/logs", "unknown");
        }
    };

    auto statsHandler = [&manager](auto *res, auto *req) {
        try {
            json stats = manager.getStats();
            res->writeHeader("Content-Type", "application/json; charset=utf-8")->end(stats.dump());
        } catch(const std::exception &e) {
            Logger::logError("/stats", e.what());
        } catch(...) {
            Logger::logError("/stats", "unknown");
        }
    };

    auto totalWorkHandler = [&manager](auto *res, auto *req) {
        try {
            std::string count = manager.getTotalWork();
            res->writeHeader("Content-Type", "text/html; charset=utf-8")->end(count);
        } catch(const std::exception &e) {
            Logger::logError("/total_work", e.what());
        } catch(...) {
            Logger::logError("/total_work", "unknown");
        }
    };

    auto nameHandler = [&myName](auto *res, auto *req) {
        res->writeHeader("Content-Type", "text/html; charset=utf-8")->end(myName);
    };

    auto peerHandler = [&manager](auto *res, auto *req) {
        json response = manager.getPeers();
        res->end(response.dump());
    };

    auto blockCountHandler = [&manager](auto *res, auto *req) {
        try {
            std::string count = manager.getBlockCount();
            res->writeHeader("Content-Type", "text/html; charset=utf-8")->end(count);
        } catch(const std::exception &e) {
            Logger::logError("/block_count", e.what());
        } catch(...) {
            Logger::logError("/block_count", "unknown");
        }
    };

    auto blockHandler = [&manager](auto *res, auto *req) {
        json result;
        try {
            int idx = std::stoi(string(req->getParameter(0)));
            int count = std::stoi(manager.getBlockCount());
            if (idx < 0 || idx > count) {
                result["error"] = "Invalid Block";
            } else {
                result = manager.getBlock(idx);
            }
            res->writeHeader("Content-Type", "application/json; charset=utf-8")->end(result.dump());
        } catch(const std::exception &e) {
            result["error"] = "Unknown error";
            Logger::logError("/block", e.what());
        } catch(...) {
            Logger::logError("/block", "unknown");
        }
    };

    auto ledgerHandler = [&manager](auto *res, auto *req) {
        try {
            PublicWalletAddress w = stringToWalletAddress(string(req->getParameter(0)));
            json ledger = manager.getLedger(w);
            res->writeHeader("Content-Type", "application/json; charset=utf-8")->end(ledger.dump());
        } catch(const std::exception &e) {
            Logger::logError("/ledger", e.what());
        } catch(...) {
            Logger::logError("/ledger", "unknown");
        }
    };


    auto addPeerHandler = [&manager](auto *res, auto *req) {
        res->onAborted([res]() {
            res->end("ABORTED");
        });
        std::string buffer;
        res->onData([res, buffer = std::move(buffer), &manager](std::string_view data, bool last) mutable {
            buffer.append(data.data(), data.length());
            if (last) {
                try {
                    string url = string(buffer);
                    Logger::logStatus("Adding peer : " + url);
                    json result = manager.addPeer(url);
                    res->writeHeader("Content-Type", "application/json; charset=utf-8")->end(result.dump());
                }  catch(const std::exception &e) {
                    Logger::logError("/add_peer", e.what());
                } catch(...) {
                    Logger::logError("/add_peer", "unknown");
                }
            }
        });
    };


    auto submitHandler = [&manager](auto *res, auto *req) {
        res->onAborted([res]() {
            res->end("ABORTED");
        });
        std::string buffer;
        res->onData([res, buffer = std::move(buffer), &manager](std::string_view data, bool last) mutable {
            buffer.append(data.data(), data.length());
            if (last) {
                try {
                    if (buffer.length() < sizeof(BlockHeader) + sizeof(TransactionInfo)) {
                        json response;
                        response["error"] = "Malformed block";
                        Logger::logError("/submit","Malformed block");
                        res->end(response.dump());
                    } else {
                        char * ptr = (char*)buffer.c_str();
                        BlockHeader blockH = *((BlockHeader*)ptr);
                        ptr += sizeof(BlockHeader);
                        vector<Transaction> transactions;
                        if (blockH.numTransactions > MAX_TRANSACTIONS_PER_BLOCK) {
                            json response;
                            response["error"] = "Too many transactions";
                            res->end(response.dump());
                            Logger::logError("/submit","Too many transactions");
                        } else {
                            for(int j = 0; j < blockH.numTransactions; j++) {
                                TransactionInfo t = *((TransactionInfo*)ptr);
                                ptr += sizeof(TransactionInfo);
                                transactions.push_back(Transaction(t));
                            }
                            Block block(blockH, transactions);
                            json response = manager.submitProofOfWork(block);
                            res->end(response.dump());
                        }
                    }
                } catch(const std::exception &e) {
                    json response;
                    response["error"] = string(e.what());
                    res->end(response.dump());
                    Logger::logError("/submit", e.what());
                } catch(...) {
                    json response;
                    response["error"] = "unknown";
                    res->end(response.dump());
                    Logger::logError("/submit", "unknown");
                }
                
            }
        });
    };

    auto getTxHandler = [&manager](auto *res, auto *req) {
        try {
            res->writeHeader("Content-Type", "application/octet-stream");
            std::pair<char*, size_t> buffer = manager.getRawTransactionData();
            std::string_view str(buffer.first, buffer.second);
            res->write(str);
            delete buffer.first;
            res->end("");
        } catch(const std::exception &e) {
            Logger::logError("/gettx", e.what());
        } catch(...) {
            Logger::logError("/gettx", "unknown");
        }
        res->onAborted([res]() {
            res->end("ABORTED");
        });
    };

    auto mineHandler = [&manager](auto *res, auto *req) {
        try {
            json response = manager.getProofOfWork();
            res->end(response.dump());
        } catch(const std::exception &e) {
            Logger::logError("/mine", e.what());
        } catch(...) {
            Logger::logError("/mine", "unknown");
        }
    };

    auto syncHandler = [&manager](auto *res, auto *req) {
        try {
            int start = std::stoi(string(req->getParameter(0)));
            int end = std::stoi(string(req->getParameter(1)));
            if ((end-start) > BLOCKS_PER_FETCH) {
                Logger::logError("/sync", "invalid range requested");
                res->end("");
            }
            res->writeHeader("Content-Type", "application/octet-stream");
            for (int i = start; i <=end; i++) {
                std::pair<uint8_t*, size_t> buffer = manager.getRawBlockData(i);
                std::string_view str((char*)buffer.first, buffer.second);
                res->write(str);
                delete buffer.first;
            }
            res->end("");
        } catch(const std::exception &e) {
            Logger::logError("/sync", e.what());
        } catch(...) {
            Logger::logError("/sync", "unknown");
        }
        res->onAborted([res]() {
            res->end("ABORTED");
        });
    };

    auto blockHeaderHandler = [&manager](auto *res, auto *req) {
        try {
            int start = std::stoi(string(req->getParameter(0)));
            int end = std::stoi(string(req->getParameter(1)));
            if ((end-start) > BLOCK_HEADERS_PER_FETCH) {
                Logger::logError("/block_headers", "invalid range requested");
                res->end("");
            }
            res->writeHeader("Content-Type", "application/octet-stream");
            for (int i = start; i <=end; i++) {
                BlockHeader b = manager.getBlockHeader(i);
                std::string_view str((char*)&b, sizeof(BlockHeader));
                res->write(str);
            }
            res->end("");
        } catch(const std::exception &e) {
            Logger::logError("/block_headers", e.what());
        } catch(...) {
            Logger::logError("/block_headers", "unknown");
        }
        res->onAborted([res]() {
            res->end("ABORTED");
        });
    };

    auto addTransactionHandler = [&manager](auto *res, auto *req) {
        res->onAborted([res]() {
            res->end("ABORTED");
        });
        std::string buffer;
        res->onData([res, buffer = std::move(buffer), &manager](std::string_view data, bool last) mutable {
            buffer.append(data.data(), data.length());
            if (last) {
                try {
                    if (buffer.length() < sizeof(TransactionInfo)) {
                        json response;
                        response["error"] = "Malformed transaction";
                        Logger::logError("/add_transaction","Malformed transaction");
                        res->end(response.dump());
                    } else {
                        TransactionInfo t = *((TransactionInfo*)buffer.c_str());
                        Transaction tx(t);
                        json response = manager.addTransaction(tx);
                        res->end(response.dump());
                    }
                }  catch(const std::exception &e) {
                    Logger::logError("/add_transaction", e.what());
                } catch(...) {
                    Logger::logError("/add_transaction", "unknown");
                }
            }
        });
    };

    auto verifyTransactionHandler = [&manager](auto *res, auto *req) {
        /* Allocate automatic, stack, variable as usual */
        std::string buffer;
        /* Move it to storage of lambda */
        res->onData([res, buffer = std::move(buffer), &manager](std::string_view data, bool last) mutable {
            buffer.append(data.data(), data.length());
            if (last) {
                if (buffer.length() < sizeof(TransactionInfo)) {
                    json response;
                    response["error"] = "Malformed transaction";
                    res->end(response.dump());
                    Logger::logError("/verify_transaction","Malformed transaction");
                    return;
                }
                TransactionInfo t = *((TransactionInfo*)buffer.c_str());
                Transaction tx(t);
                json response = manager.verifyTransaction(tx);
                res->end(response.dump());
            }
        });
        res->onAborted([res]() {
            res->end("ABORTED");
        });
    };

 
    uWS::App()
        .get("/name", nameHandler)
        .get("/total_work", totalWorkHandler)
        .get("/peers", peerHandler)
        .get("/block_count", blockCountHandler)
        .get("/logs", logsHandler)
        .get("/stats", statsHandler)
        .get("/block/:b", blockHandler)
        .get("/ledger/:user", ledgerHandler)
        .get("/mine", mineHandler)
        .post("/add_peer", addPeerHandler)
        .post("/submit", submitHandler)
        .get("/gettx/:blockId", getTxHandler)
        .get("/sync/:start/:end", syncHandler)
        .get("/block_headers/:start/:end", blockHeaderHandler)
        .get("/synctx", getTxHandler)
        .post("/add_transaction", addTransactionHandler)
        .post("/verify_transaction", verifyTransactionHandler)
        .listen(port, [port](auto *token) {
            Logger::logStatus("Started server");
        }).run();

}

