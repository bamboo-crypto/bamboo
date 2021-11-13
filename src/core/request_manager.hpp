#pragma once
#include "blockchain.hpp"
#include "transaction.hpp"
#include "common.hpp"
#include <vector>
#include <map>
#include <list>
using namespace std;


class RequestManager {
    public:
        RequestManager(string hostUrl="");
        json addTransaction(json data);
        json getProofOfWork();
        json submitProofOfWork(json data);
        json getBlock(int index);
        json getLedger(PublicWalletAddress w);
        string getBlockCount();
        BlockChain* blockchain;
    protected:
        map<int,list<Transaction>> transactionQueue;
};