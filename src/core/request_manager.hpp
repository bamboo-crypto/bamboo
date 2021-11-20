#pragma once
#include "blockchain.hpp"
#include "transaction.hpp"
#include "host_manager.hpp"
#include "mempool.hpp"
#include "common.hpp"
#include <mutex>
#include <vector>
#include <map>
#include <list>
using namespace std;


class RequestManager {
    public:
        RequestManager(HostManager& hosts);
        json addTransaction(json data);
        json getProofOfWork();
        json submitProofOfWork(json data);
        json getBlock(int index);
        json getLedger(PublicWalletAddress w);
        json getStats();
        json verifyTransaction(json data);
        std::pair<char*, size_t> getRawBlockData(int index);
        string getBlockCount();
    protected:
        HostManager& hosts;
        BlockChain* blockchain;
        MemPool* mempool;
        std::mutex transactionsLock;
        size_t getPendingTransactionSize(int block);
        map<int,list<Transaction>> transactionQueue;
};