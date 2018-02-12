// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "assert.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

//
// Main network
//

unsigned int pnSeed[] =
{
    0xA7428285,
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xad;
        pchMessageStart[1] = 0x5a;
        pchMessageStart[2] = 0xeb;
        pchMessageStart[3] = 0x9f;
        vAlertPubKey = ParseHex("0424b0747fd86f094719ef1b584790d9a863194f4dcfa91530b2f7b06775e3af7604602ee974123ddb5836f281b362c2319d2ead7395864b8396c2a2e204662acd");
        nDefaultPort = 9981;
        nRPCPort = 9982;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 18);
        nSubsidyHalvingInterval = 800000;

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //
        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e
        const char* pszTimestamp = "V2hvIGlzIHRoaXMgS2luZyBvZiBHbG9yeT8gQ2hpbmVzZSBTY2hvbGFyIFNheXMgRmlnaHQgVGhlIFN0YXRlIE9uIFJlbGlnaW9u";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        printf("genesis.BuildMerkleTree = %s\n", genesis.BuildMerkleTree().ToString().c_str());
        genesis.nVersion = 1;
        genesis.nTime    = 1518401710;
        genesis.nBits    = 0x1e3fffff;
        genesis.nNonce   = 0;

        hashGenesisBlock = genesis.GetHash();
#if 0
        {
            printf("calc new genesis block\n");
            printf("hashMerkleRoot %s\n", genesis.hashMerkleRoot.ToString().c_str());
            printf("bnProofOfWorkLimit 0x%x\n", bnProofOfWorkLimit.GetCompact());
            printf("genesis.nBits 0x%x\n", genesis.nBits);

            for (genesis.nNonce = 0; ; genesis.nNonce++) {
                hashGenesisBlock = genesis.GetHash();
                if (hashGenesisBlock <= bnProofOfWorkLimit.getuint256()) break;
            }

            printf("hashGenesisBlock %s\n", hashGenesisBlock.ToString().c_str());
            printf("genesis.nNonce %d\n", genesis.nNonce);
        }
#endif
        assert(hashGenesisBlock == uint256("0x0"));  //assert(hashGenesisBlock == uint256("0x")); for generating genesis block
        assert(genesis.hashMerkleRoot == uint256("0x0"));  //assert(genesis.hashMerkleRoot == uint256("0x")); for generating genesis block
        
        
       // printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
       // assert(hashGenesisBlock == uint256("0x9b56d25ff3fdeb76f6a86922a74da2f8ba9b821d3fac485fac23b4317701f9b5"));
        //assert(genesis.hashMerkleRoot == uint256("0x58348f6f36b9a4a4bc212e226b3b7f9ac4646fef01265aad4583c08adca8c3b6"));

//        vFixedSeeds.clear();
        vSeeds.clear();
//        vSeeds.push_back(CDNSSeedData("yenten.org", "seed.yenten.org"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,78);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,10);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,123);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' of between one and two
            // weeks ago.
            const int64_t nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x95;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0xe4;
        pchMessageStart[3] = 0x95;
        vAlertPubKey = ParseHex("047492b1ef597c2b15825e097313b5b74602079fcd6d88f61ce2f5557f56c729b81b82dce39fa59f19585dc0f3650c7a0b9225ec2e94d85c59bac10fd6950d5644");
        nDefaultPort = 19981;
        nRPCPort = 19982;
        strDataDir = "testnet3";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1507032223;
        genesis.nNonce = 238202;
        hashGenesisBlock = genesis.GetHash();
        //printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
#if 0
        {
            printf("(test)calc new genesis block\n");
            printf("hashMerkleRoot %s\n", genesis.hashMerkleRoot.ToString().c_str());
            printf("bnProofOfWorkLimit 0x%x\n", bnProofOfWorkLimit.GetCompact());
            printf("genesis.nBits 0x%x\n", genesis.nBits);

            for (genesis.nNonce = 0; ; genesis.nNonce++) {
                hashGenesisBlock = genesis.GetHash();
                if (hashGenesisBlock <= bnProofOfWorkLimit.getuint256()) break;
            }

            printf("hashGenesisBlock %s\n", hashGenesisBlock.ToString().c_str());
            printf("genesis.nNonce %d\n", genesis.nNonce);

        }
#endif
        assert(hashGenesisBlock == uint256("0x00003a0c79f595bddb7f37a22eb63fd23c541ab6a7dd7efd0215e7029bde225c"));
        assert(hashGenesisBlock == uint256("0x07bda78794cfcdca03b9ab7d93e41ae59a07bc32f4232db87dc1dafe31ebce3a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org"));
        //vSeeds.push_back(CDNSSeedData("bluematt.me", "testnet-seed.bluematt.me"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,112);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,197);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,240);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xaf;
        pchMessageStart[1] = 0xfb;
        pchMessageStart[2] = 0x5b;
        pchMessageStart[3] = 0xad;
        nSubsidyHalvingInterval = 150;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1296688602;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 1;
        hashGenesisBlock = genesis.GetHash();
        printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        nDefaultPort = 18432;
        strDataDir = "regtest";
        //printf("hashGenesisBlock %s\n", hashGenesisBlock.ToString().c_str());
        assert(hashGenesisBlock == uint256("0x8fe0c415967c7f736ee4bd65e44604d0035461570cd33078b2445b62d3ce2b0d"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
