#include "transaction.hpp"
#include "helpers.hpp"
#include "block.hpp"
#include "openssl/sha.h"
#include <sstream>
#include <iostream>
 #include <cstring>
#include <ctime>
using namespace std;

Transaction::Transaction(PublicWalletAddress from, PublicWalletAddress to, TransactionAmount amount, int blockId, PublicKey signingKey, TransactionAmount fee) {
    this->from = from;
    this->to = to;
    this->amount = amount;
    this->isTransactionFee = false;
    this->blockId = blockId;
    this->nonce = randomString(TRANSACTION_NONCE_SIZE);
    this->timestamp = std::time(0);
    this->fee = fee;
    this->signingKey = signingKey;
}

Transaction::Transaction() {

}

Transaction::Transaction(const TransactionInfo& t) {
    this->to = t.to;
    if (!t.isTransactionFee) this->from = t.from;
#ifdef SECP256K1
    memcpy((void*)this->signature.data, (void*)t.signature, 64);
    memcpy((void*)this->signingKey.data, (void*)t.signingKey, 64);
#else
    memcpy((void*)this->signature.data(), (void*)t.signature, 64);
    memcpy((void*)this->signingKey.data(), (void*)t.signingKey, 32);
#endif
    this->nonce = string((char*)t.nonce, TRANSACTION_NONCE_SIZE);
    this->amount = t.amount;
    this->isTransactionFee = t.isTransactionFee;
    this->blockId = t.blockId;
    this->timestamp = t.timestamp;
    this->fee = t.fee;
}
TransactionInfo Transaction::serialize() {
    TransactionInfo t;
    t.blockId = this->blockId;
#ifdef SECP256K1
    memcpy((void*)t.signature, (void*)this->signature.data, 64);
    memcpy((void*)t.signingKey, (void*)this->signingKey.data, 64);
#else
    memcpy((void*)t.signature, (void*)this->signature.data(), 64);
    memcpy((void*)t.signingKey, (void*)this->signingKey.data(), 32);
#endif
    memcpy((char*)t.nonce, (char*)this->nonce.c_str(), TRANSACTION_NONCE_SIZE);
    t.timestamp = this->timestamp;
    t.to = this->to;
    t.from = this->from;
    t.amount = this->amount;
    t.fee = this->fee;
    t.isTransactionFee = this->isTransactionFee;
    return t;
}


Transaction::Transaction(const Transaction & t) {
    this->to = t.to;
    this->from = t.from;
    this->signature = t.signature;
    this->amount = t.amount;
    this->isTransactionFee = t.isTransactionFee;
    this->blockId = t.blockId;
    this->nonce = t.nonce;
    this->timestamp = t.timestamp;
    this->fee = t.fee;
    this->signingKey = t.signingKey;
}

Transaction::Transaction(PublicWalletAddress to, int blockId) {
    this->to = to;
    this->amount = MINING_FEE; // TODO make this a function
    this->isTransactionFee = true;
    this->blockId = blockId;
    this->nonce = randomString(TRANSACTION_NONCE_SIZE);
    this->timestamp = getCurrentTime();
    this->fee = 0;
}

Transaction::Transaction(json data) {
    PublicWalletAddress to;
    this->timestamp = stringToTime(data["timestamp"]);
    this->to = stringToWalletAddress(data["to"]);
    this->blockId = data["id"];
    this->nonce = data["nonce"];
    this->fee = data["fee"];
    if(data["from"] == "") {        
        this->amount = MINING_FEE; // TODO: Mining fee should come from function
        this->isTransactionFee = true;
    } else {
        this->from = stringToWalletAddress(data["from"]);
        this->signature = stringToSignature(data["signature"]);
        this->amount = data["amount"];
        this->isTransactionFee = false;
        this->signingKey = stringToPublicKey(data["signingKey"]);
    }
}

void Transaction::setTransactionFee(TransactionAmount amount) {
    this->fee = amount;
}
TransactionAmount Transaction::getTransactionFee() const {
    return this->fee;
}


json Transaction::toJson() {
    json result;
    result["to"] = walletAddressToString(this->toWallet());
    result["amount"] = this->amount;
    result["timestamp"] = timeToString(this->timestamp);
    result["id"] = this->blockId;
    result["nonce"] = this->nonce;
    result["fee"] = this->fee;
    if (!this->isTransactionFee) {
        result["from"] = walletAddressToString(this->fromWallet());
        result["signingKey"] = publicKeyToString(this->signingKey);
        result["signature"] = signatureToString(this->signature);
    } else {
        result["from"] = "";
    }
    
    return result;
}


bool Transaction::isFee() const {
    return this->isTransactionFee;
}

void Transaction::setTimestamp(time_t t) {
    this->timestamp = t;
}

time_t Transaction::getTimestamp() {
    return this->timestamp;
}


void Transaction::setNonce(string n) {
    this->nonce = n;
}

string Transaction::getNonce() const {
    return this->nonce;
}

void Transaction::setBlockId(int id) {
    this->blockId = id;
}

int Transaction::getBlockId() const {
    return this->blockId;
}

TransactionSignature Transaction::getSignature() const {
    return this->signature;
}

void Transaction::setAmount(TransactionAmount amt) {
    this->amount = amt;
}

bool Transaction::signatureValid() const {
    if (this->isFee()) return true;
    SHA256Hash hash = this->hashContents();
    return checkSignature((const char*)hash.data(), hash.size(), this->signature, this->signingKey);

}

SHA256Hash Transaction::getHash() const {
    SHA256Hash ret;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256Hash contentHash = this->hashContents();
    SHA256_Update(&sha256, (unsigned char*)contentHash.data(), contentHash.size());
    if (!this->isTransactionFee) {
        SHA256_Update(&sha256, (unsigned char*)this->signature.data(), this->signature.size());
    }
    SHA256_Final(ret.data(), &sha256);
    return ret;
}

PublicWalletAddress Transaction::fromWallet() const {
    return this->from;
}
PublicWalletAddress Transaction::toWallet() const {
    return this->to;
}

TransactionAmount Transaction::getAmount() const {
    return this->amount;
}

SHA256Hash Transaction::hashContents() const {
    SHA256Hash ret;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    PublicWalletAddress wallet = this->toWallet();
    SHA256_Update(&sha256, (unsigned char*)wallet.data(), wallet.size());
    if (!this->isTransactionFee) {
        wallet = this->fromWallet();
        SHA256_Update(&sha256, (unsigned char*)wallet.data(), wallet.size());
    }
    SHA256_Update(&sha256, (unsigned char*)&this->fee, sizeof(TransactionAmount));
    SHA256_Update(&sha256, (unsigned char*)&this->amount, sizeof(TransactionAmount));
    SHA256_Update(&sha256, (unsigned char*)this->nonce.c_str(), nonce.length());
    SHA256_Update(&sha256, (unsigned char*)&this->blockId, sizeof(int));
    SHA256_Update(&sha256, (unsigned char*)&this->timestamp, sizeof(time_t));
    SHA256_Final(ret.data(), &sha256);
    return ret;
}

void Transaction::sign(PublicKey pubKey, PrivateKey signingKey) {
    SHA256Hash hash = this->hashContents();
    TransactionSignature signature = signWithPrivateKey((const char*)hash.data(), hash.size(), pubKey, signingKey);
    this->signature = signature;
}

bool operator<(const Transaction& a, const Transaction& b) {
    return a.signature < b.signature;
}

bool operator==(const Transaction& a, const Transaction& b) {
    if (a.blockId != b.blockId) return false;
    if( a.nonce != b.nonce) return false;
    if(a.timestamp != b.timestamp) return false;
    if(a.toWallet() != b.toWallet()) return false;
    if(a.getTransactionFee() != b.getTransactionFee()) return false;
    if( a.amount != b.amount) return false;
    if( a.isTransactionFee != b.isTransactionFee) return false;
    if (!a.isTransactionFee) {
        if( a.fromWallet() != b.fromWallet()) return false;
        if(signatureToString(a.signature) != signatureToString(b.signature)) return false;
        if (publicKeyToString(a.signingKey) != publicKeyToString(b.signingKey)) return false;
    }
    return true;
}