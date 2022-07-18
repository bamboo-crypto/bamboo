#include "host_manager.hpp"
#include "helpers.hpp"
#include "api.hpp"
#include "constants.hpp"
#include "logger.hpp"
#include "header_chain.hpp"
#include "../external/http.hpp"
#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <future>
#include <cstdio>
using namespace std;

#define ADD_PEER_BRANCH_FACTOR 10
#define HEADER_VALIDATION_HOST_COUNT 8
#define RANDOM_GOOD_HOST_COUNT 9
#define HOST_MIN_FRESHNESS 180 * 60 // 3 hours

/*
    Fetches the public IP of the node
*/

bool isValidIPv4(string& ip) {
   unsigned int a,b,c,d;
   return sscanf(ip.c_str(),"%d.%d.%d.%d", &a, &b, &c, &d) == 4;
}

bool isJsHost(const string& addr) {
    return addr.find("peer://") != std::string::npos;
}

string HostManager::computeAddress() {
    if (this->ip == "") {
        bool found = false;
        vector<string> lookupServices = { "checkip.amazonaws.com", "icanhazip.com", "ifconfig.co", "wtfismyip.com/text", "ifconfig.io" };

        for(auto& lookupService : lookupServices) {
            string cmd = "curl -s4 " + lookupService;
            string rawUrl = exec(cmd.c_str());
            string ip = rawUrl.substr(0, rawUrl.size() - 1);
            if (isValidIPv4(ip)) {
                this->address = "http://" + ip  + ":" + to_string(this->port);
                found = true;
                break;
            }
        }

        if (!found) {
            Logger::logError("IP discovery", "Could not determine current IP address");
        }
    } else {
        this->address = this->ip + ":" + to_string(this->port);
    }
    return this->address;
}

/*
    This thread periodically updates all neighboring hosts with the 
    nodes current IP 
*/  
void peer_sync(HostManager& hm) {
    while(true) {
        for(auto host : hm.hosts) {
            try {
                pingPeer(host, hm.computeAddress(), std::time(0), hm.version, hm.networkName);
            } catch (...) { }
        }
        std::this_thread::sleep_for(std::chrono::minutes(5));
    }
}

/*
    This thread updates the current display of sync'd headers
*/

void header_stats(HostManager& hm) {
    while(true) {
        Logger::logStatus("================ Header Sync Status ==============");
        map<string, uint64_t> stats = hm.getHeaderChainStats();
        for(auto item : stats) {
            stringstream ss;
            ss<<"Host: " <<item.first<<", blocks: "<<item.second;
            Logger::logStatus(ss.str());
        }
        Logger::logStatus("===================================================");
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

HostManager::HostManager(json config) {
    this->name = config["name"];
    this->port = config["port"];
    this->ip = config["ip"];
    this->version = BUILD_VERSION;
    this->networkName = config["networkName"];
    this->computeAddress();

    // parse checkpoints
    for(auto checkpoint : config["checkpoints"]) {
        this->checkpoints.insert(std::pair<uint64_t, SHA256Hash>(checkpoint[0], stringToSHA256(checkpoint[1])));
    }

    // parse banned hashes
    for(auto bannedHash : config["bannedHashes"]) {
        this->bannedHashes.insert(std::pair<uint64_t, SHA256Hash>(bannedHash[0], stringToSHA256(bannedHash[1])));
    }

    // parse supported host versions
    this->minHostVersion = config["minHostVersion"];

    // check if a blacklist file exists
    std::ifstream blacklist("blacklist.txt");
    if (blacklist.good()) {
        std::string line;
        while (std::getline(blacklist, line)) {
            if (line[0] != '#') {
                string blocked = line;
                if (blocked[blocked.size() - 1] == '/') {
                    blocked = blocked.substr(0, blocked.size() - 1);
                }
                this->blacklist.insert(blocked);
                Logger::logStatus("Ignoring host " + blocked);
            }
        }
    }

    // check if a whitelist file exists
    std::ifstream whitelist("whitelist.txt");
    if (whitelist.good()) {
        std::string line;
        while (std::getline(whitelist, line)) {
            if (line[0] != '#') {
                string enabled = line;
                if (enabled[enabled.size() - 1] == '/') {
                    enabled = enabled.substr(0, enabled.size() - 1);
                }
                this->whitelist.insert(enabled);
                Logger::logStatus("Enabling host " + enabled);
            }
        }
    }

    this->disabled = false;
    for(auto h : config["hostSources"]) {
        this->hostSources.push_back(h);
    }
    if (this->hostSources.size() == 0) {
        string localhost = "http://localhost:3000";
        this->hosts.push_back(localhost);
        this->hostPingTimes[localhost] = std::time(0);
        this->peerClockDeltas[localhost] = 0;
        this->syncHeadersWithPeers();
    } else {
        this->refreshHostList();
    }

    // start thread to print header chain stats
    this->headerStatsThread.push_back(std::thread(header_stats, ref(*this)));
    
}

HostManager::~HostManager() {
    // free existing peers
    this->lock.lock();
    for(auto peer : this->currPeers) {
        delete peer;
    }
    this->currPeers.empty();
}

void HostManager::startPingingPeers() {
    if (this->syncThread.size() > 0) throw std::runtime_error("Peer ping thread exists.");
    this->syncThread.push_back(std::thread(peer_sync, ref(*this)));
}

string HostManager::getAddress() {
    return this->address;
}

// Only used for tests
HostManager::HostManager() {
    this->disabled = true;
}

uint64_t HostManager::getNetworkTimestamp() {
    // find deltas of all hosts that pinged recently
    vector<int32_t> deltas;
    for (auto pair : this->hostPingTimes) {
        uint64_t lastPingAge = std::time(0) - pair.second;
        // only use peers that have pinged recently
        if (lastPingAge < HOST_MIN_FRESHNESS) { 
            deltas.push_back(this->peerClockDeltas[pair.first]);
        }
    }
    
    if (deltas.size() == 0) return std::time(0);

    std::sort(deltas.begin(), deltas.end());
    
    // compute median
    uint64_t medianTime;
    if (deltas.size() % 2 == 0) {
        int32_t avg = (deltas[deltas.size()/2] + deltas[deltas.size()/2 - 1])/2;
        medianTime = std::time(0) + avg;
    } else {
        int32_t delta = deltas[deltas.size()/2];
        medianTime = std::time(0) + delta;
    }

    return medianTime;
}   

/*
    Asks nodes for their current POW and chooses the best peer
*/
string HostManager::getGoodHost() {
    if (this->currPeers.size() < 1) return "";
    Bigint bestWork = 0;
    string bestHost = this->currPeers[0]->getHost();
    this->lock.lock();
    for(auto h : this->currPeers) {
        if (h->getTotalWork() > bestWork) {
            bestWork = h->getTotalWork();
            bestHost = h->getHost();
        }
    }
    this->lock.unlock();
    return bestHost;
}

/*
    Returns number of block headers downloaded by peer host
*/
map<string,uint64_t> HostManager::getHeaderChainStats() {
    map<string, uint64_t> ret;
    for(auto h : this->currPeers) {
        ret[h->getHost()] = h->getCurrentDownloaded();
    }
    return ret;
}

/*
    Returns the block count of the highest PoW chain amongst current peers
*/
uint64_t HostManager::getBlockCount() {
    if (this->currPeers.size() < 1) return 0;
    uint64_t bestLength = 0;
    Bigint bestWork = 0;
    this->lock.lock();
    for(auto h : this->currPeers) {
        if (h->getTotalWork() > bestWork) {
            bestWork = h->getTotalWork();
            bestLength = h->getChainLength();
        }
    }
    this->lock.unlock();
    return bestLength;
}

/*
    Returns the total work of the highest PoW chain amongst current peers
*/
Bigint HostManager::getTotalWork() {
    Bigint bestWork = 0;
    if (this->currPeers.size() < 1) return bestWork;
    this->lock.lock();
    for(auto h : this->currPeers) {
        if (h->getTotalWork() > bestWork) {
            bestWork = h->getTotalWork();
        }
    }
    this->lock.unlock();
    return bestWork;
}

/*
    Returns the block header hash for the given block, peer host
 */
SHA256Hash HostManager::getBlockHash(string host, uint64_t blockId) {
    SHA256Hash ret = NULL_SHA256_HASH;
    this->lock.lock();
    for(auto h : this->currPeers) {
        if (h->getHost() == host) {
            ret = h->getHash(blockId);
            break;
        }
    }
    this->lock.unlock();
    return ret;
}


/*
    Returns N unique random hosts that have pinged us
*/
set<string> HostManager::sampleFreshHosts(int count) {
    vector<string> freshHosts;
    for (auto pair : this->hostPingTimes) {
        uint64_t lastPingAge = std::time(0) - pair.second;
        // only return peers that have pinged
        if (lastPingAge < HOST_MIN_FRESHNESS && !isJsHost(pair.first)) { 
            freshHosts.push_back(pair.first);
        }
    }

    // TODO: do this more efficiently
    int numToPick = min(count, (int)freshHosts.size());
    set<string> sampledHosts;
    while(sampledHosts.size() < numToPick) {
        string host = freshHosts[rand()%freshHosts.size()];
        sampledHosts.insert(host);
    }
    return sampledHosts;
}

/*
    Adds a peer to the host list, 
*/
void HostManager::addPeer(string addr, uint64_t time, string version, string network) {
    if (network != this->networkName) return;
    if (version < this->minHostVersion) return;

    // check if host is in blacklist
    if (this->blacklist.find(addr) != this->blacklist.end()) return;

    // check if we already have this peer host
    auto existing = std::find(this->hosts.begin(), this->hosts.end(), addr);
    if (existing != this->hosts.end()) {
        this->hostPingTimes[addr] = std::time(0);
        // record how much our system clock differs from theirs:
        this->peerClockDeltas[addr] = std::time(0) - time;
        return;
    } 

    // check if the host is reachable:
    if (!isJsHost(addr)) {
        try {
            json name = getName(addr);
        } catch(...) {
            // if not exit
            return;
        }
    }

    // add to our host list
    if (this->whitelist.size() == 0 || this->whitelist.find(addr) != this->whitelist.end()){
        Logger::logStatus("Added new peer: " + addr);
        hosts.push_back(addr);
    } else {
        return;
    }

    // check if we have less peers than needed, if so add this to our peer list
    if (this->currPeers.size() < RANDOM_GOOD_HOST_COUNT) {
        this->lock.lock();
        this->currPeers.push_back(new HeaderChain(addr, this->checkpoints, this->bannedHashes));
        this->lock.unlock();
    }

    // pick random neighbor hosts and forward the addPeer request to them:
    set<string> neighbors = this->sampleFreshHosts(ADD_PEER_BRANCH_FACTOR);
    vector<future<void>> reqs;
    string _version = this->version;
    string networkName = this->networkName;
    for(auto neighbor : neighbors) {
        reqs.push_back(std::async([neighbor, addr, _version, networkName](){
            if (neighbor == addr) return;
            try {
                pingPeer(neighbor, addr, std::time(0), _version, networkName);
            } catch(...) {
                Logger::logStatus("Could not add peer " + addr + " to " + neighbor);
            }
        }));
    }

    for(int i =0 ; i < reqs.size(); i++) {
        reqs[i].get();
    }   
}


bool HostManager::isDisabled() {
    return this->disabled;
}


/*
    Downloads an initial list of peers and validates connectivity to them
*/
void HostManager::refreshHostList() {
    if (this->hostSources.size() == 0) return;
    
    Logger::logStatus("Finding peers...");

    set<string> fullHostList;

    // Iterate through all host sources merging into a combined peer list
    for (int i = 0; i < this->hostSources.size(); i++) {
        try {
            string hostUrl = this->hostSources[i];
            http::Request request{hostUrl};
            const auto response = request.send("GET","",{},std::chrono::milliseconds{TIMEOUT_MS});
            json hostList = json::parse(std::string{response.body.begin(), response.body.end()});
            for(auto host : hostList) {
                fullHostList.insert(string(host));
            }
        } catch (...) {
            continue;
        }
    }

    if (fullHostList.size() == 0) return;

    // iterate through all listed peer hosts
    vector<std::thread> threads;
    std::mutex lock;
    for(auto hostJson : fullHostList) {
        // if we've already added this host skip
        string hostUrl = string(hostJson);
        auto existing = std::find(this->hosts.begin(), this->hosts.end(), hostUrl);
        if (existing != this->hosts.end()) continue;

        // if host is in blacklist skip:
        if (this->blacklist.find(hostUrl) != this->blacklist.end()) continue;

        // otherwise try connecting to the host to confirm it's up
        HostManager & hm = *this;
        threads.emplace_back(
            std::thread([hostUrl, &hm, &lock](){
                try {
                    json hostInfo = getName(hostUrl);
                    if (hostInfo["version"] < hm.minHostVersion) {
                        Logger::logStatus(RED + "[ UNREACHABLE ] " + RESET  + hostUrl);
                        return;
                    }
                    lock.lock();
                    if (hm.whitelist.size() == 0 || hm.whitelist.find(hostUrl) != hm.whitelist.end()){
                        hm.hosts.push_back(hostUrl);
                        Logger::logStatus(GREEN + "[ CONNECTED ] " + RESET  + hostUrl);
                        hm.hostPingTimes[hostUrl] = std::time(0);
                    }
                    lock.unlock();
                    
                } catch (...) {
                    Logger::logStatus(RED + "[ UNREACHABLE ] " + RESET  + hostUrl);
                }
            })
        );
    }
    for (auto& th : threads) th.join();

    this->syncHeadersWithPeers();
}

void HostManager::syncHeadersWithPeers() {
    // free existing peers
    Logger::logStatus("Starting header chain sync. This may take up to 15 minutes.");
    this->lock.lock();
    for(auto peer : this->currPeers) {
        delete peer;
    }
    this->currPeers.empty();
    
    // pick N random peers
    set<string> hosts = this->sampleFreshHosts(RANDOM_GOOD_HOST_COUNT);

    for (auto h : hosts) {
        this->currPeers.push_back(new HeaderChain(h, this->checkpoints, this->bannedHashes));
    }
    this->lock.unlock();
}


/*
    Returns a list of all peer hosts
*/
vector<string> HostManager::getHosts(bool includeSelf) {
    vector<string> ret;
    for (auto pair : this->hostPingTimes) {
        uint64_t lastPingAge = std::time(0) - pair.second;
        // only return peers that have pinged
        if (lastPingAge < HOST_MIN_FRESHNESS) { 
            ret.push_back(pair.first);
        }
    }
    if (includeSelf) {
        ret.push_back(this->address);
    }
    return ret;
}

size_t HostManager::size() {
    return this->hosts.size();
}