#pragma once
#include "common.hpp"
#include "header_chain.hpp"
#include <set>
#include <mutex>
 #include <thread>
using namespace std;

class HostManager {
    public:
        HostManager(json config);
        HostManager(); // only used for  mocks
        ~HostManager();
        size_t size();
        string computeAddress();
        void refreshHostList();
        void startPingingPeers();

        string getGoodHost();
        uint64_t getBlockCount();
        Bigint getTotalWork();
        SHA256Hash getBlockHash(string host, uint64_t blockId);
        map<string,uint64_t> getHeaderChainStats();
        std::pair<string,uint64_t> getRandomHost();
        vector<string> getHosts(bool includeSelf=true);
        set<string> sampleFreshHosts(int count);
        set<string> sampleAllHosts(int count);
        string getAddress();
        uint64_t getNetworkTimestamp();
        
        void addPeer(string addr, uint64_t time, string version, string network);
        bool isDisabled();
        
        void acquire();
        void release();
    protected:
        void syncHeadersWithPeers();
        vector<HeaderChain*> currPeers;

        std::mutex lock;
        bool disabled;
        string ip;
        int port;
        string name;
        string address;
        string version;
        string minHostVersion;
        string networkName;
        
        map<string,uint64_t> hostPingTimes;
        map<string,int32_t> peerClockDeltas;
        map<uint64_t, SHA256Hash> checkpoints;
        map<uint64_t, SHA256Hash> bannedHashes;
        vector<string> hostSources;
        vector<string> hosts;
        set<string> blacklist;
        set<string> whitelist;

        vector<std::thread> syncThread;
        vector<std::thread> headerStatsThread;
        friend void peer_sync(HostManager& hm);
};

