/* Copyright (c) 2009-2012 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include "ClusterMetrics.h"
#include "Cycles.h"
#include "ShortMacros.h"
#include "Crc32C.h"
#include "ObjectFinder.h"
#include "OptionParser.h"
#include "RamCloud.h"
#include "Tub.h"
#include <unistd.h>
#include <algorithm>
#include <vector>
#include <fstream>
#include <iostream>

using namespace RAMCloud;

/*
 * Speed up recovery insertion with the single-shot FillWithTestData RPC.
 */
uint8_t numSameSizeObj = 1;
bool fillWithTestData = false;

/**
 * This method is used for testing coordinator crash recovery. It is
 * normally invoked repeatedly. Each invocation runs a set of representative
 * cluster operations, with some consistency checks mixed in.
 * 
 * \param client
 *      Connection to the RAMCloud cluster.
 */
void
exerciseCluster(RamCloud* client)
{
    // This method maintains a collection of tables with names of the
    // form "tableX" where X is a number. At any given time a contiguous
    // range of tables should exist, such as table2, table3, and table4.
    // Over time, tables get created and deleted such that the existing
    // range gradually moves up. Each table contains a single object
    // named "tableName" whose value should be the same as the name of
    // the table.

    // Index of the last table that we believe should exist (0 means "none").
    static int expectedLast = 0;

    // Step 1: find the beginning of the range of existing tables.
    char tableName[100];
    int first, last;
    uint64_t tableId = 0;
    for (first = 1; first < 1000; first++) {
        snprintf(tableName, sizeof(tableName), "table%d", first);
        try {
            tableId = client->getTableId(tableName);
            break;
        } catch (TableDoesntExistException& e) {
            // This table doesn't exist; just go on to the next one.
        }
    }
    if (tableId == 0) {
        first = 1;
        printf("Couldn't find existing tables; starting at table1\n");
    }

    // Step 2: scan all existing tables to make sure they have the expected
    // objects.
    for (last = first; ; last++) {
        snprintf(tableName, sizeof(tableName), "table%d", last);
        try {
            tableId = client->getTableId(tableName);
            Buffer value;
            try {
                client->read(tableId, "tableName", 9, &value);
                const char* valueString = static_cast<const char*>(
                        value.getRange(0, value.size()));
                if (strcmp(valueString, tableName) != 0) {
                    printf("Bad value for tableName object in %s; "
                            "expected \"%s\", got \"%s\"\n",
                            tableName, tableName, valueString);
                }
            } catch (ClientException& e) {
                printf("Error reading tableName object in %s: %s\n",
                        tableName, e.toString());
            }
        } catch (TableDoesntExistException& e) {
            // End this step when we reach a table that does not exist.
            break;
        }
    }

    // Step 3: verify that what we have is what we expected.
    int numTables = last - first;
    last--;
    printf("-------------------------------------------------\n");
    if (numTables > 0) {
        printf("Found existing tables: table%d..table%d\n", first, last);
    }
    if (expectedLast > 0) {
        int expectedFirst = expectedLast - 4;
        if (expectedFirst < 1) {
            expectedFirst = 1;
        }
        if ((last != expectedLast) || (first != expectedFirst)) {
            printf("*** Error: expected table%d..table%d\n", expectedFirst,
                    expectedLast);
        }
    }
    printf("-------------------------------------------------\n");

    // Step 4: if we already have a bunch of tables, delete the oldest
    // table.
    if (numTables >= 5) {
        snprintf(tableName, sizeof(tableName), "table%d", first);
        try {
            client->dropTable(tableName);
            printf("Dropped %s\n", tableName);
        } catch (ClientException& e) {
            printf("Error dropping %s: %s\n",
                    tableName, e.toString());
        }
    }

    // Step 4: unless we already have a lot of tables, make a new table.
    last++;
    if (numTables <= 5) {
        snprintf(tableName, sizeof(tableName), "table%d", last);
        try {
            tableId = client->createTable(tableName, 1);
            try {
                client->write(tableId, "tableName", 9, &tableName,
                        downCast<uint32_t>(strlen(tableName) + 1));
            } catch (ClientException& e) {
                printf("Error write tableName object in %s: %s\n",
                        tableName, e.toString());
            }
            printf("Created new table %s\n", tableName);
        } catch (ClientException& e) {
            printf("Error creating %s: %s\n",
                    tableName, e.toString());
        }
    }
    expectedLast = last;
}

class ObjectList
{
  public:
      ObjectList();
      void append(float probDist, int serverId, int objectSize
                   , uint64_t tableId, char **keyList, char* tableName
                   , ObjectList* prev);

  public:
      float probDist;
      int serverId;
      int objectSize;
      uint64_t tableId;
      char** keyList;
      uint16_t objReadMap;
      char* tableName;
      ObjectList *next;
};


ObjectList::ObjectList(): probDist(0) 
                        , serverId(0)
                        , objectSize(0)
                        , tableId(0)
                        , keyList(NULL)
                        , objReadMap(0)
                        , tableName(NULL)
                        , next(NULL)
{
}

void
ObjectList::append(float probDist, int serverId, int objectSize
                    , uint64_t tableId, char **keyList, char* tableName
                    , ObjectList* prev)
{
    this->probDist = probDist;
    this->serverId = serverId;
    this->objectSize = objectSize;
    this->tableId = tableId;
    this->keyList = new char*[numSameSizeObj];
    for (int i = 0; i < numSameSizeObj; i++) {
        this->keyList[i] = new char[strlen(keyList[i]) + 1];
        strcpy(this->keyList[i] ,keyList[i]);
    }
    this->objReadMap = 0;
    this->tableName = new char[strlen(tableName) + 1];
    strcpy(this->tableName, tableName);
    this->next = NULL;
    prev->next = this;
}

void freeObjectList(ObjectList* objToFree)
{
    if (objToFree->next) {
        freeObjectList(objToFree->next);
    }
    for (int i = 0; i < numSameSizeObj; i++){
        delete[] objToFree->keyList[i];
    }
    delete[] objToFree->keyList; 
    delete objToFree->tableName;
    delete objToFree;
}

void printObj(ObjectList* objToPrint){
    LOG(NOTICE, "\n**********Object Fields**********:\n Distribution: %f\
, Object Size: %d , Table ID: %lu, Table Name: %s, Server ID: %d\
, Object Key: %s", objToPrint->probDist, objToPrint->objectSize
, objToPrint->tableId, objToPrint->tableName, objToPrint->serverId
, objToPrint->keyList[0]);
}

void 
initRandomSeed(){
    static bool initialized = false;
    if( !initialized ){
        srand ( int ( time( NULL ) ) );
        initialized = true;
    }
}

double 
randomReal( double low, double high) {
    initRandomSeed();
    double d = rand() / (double(RAND_MAX) + 1);
    return low + d * ( double(high)  - low );
}

int 
randomInteger( int low, int high){
    initRandomSeed();
    double d = rand() / (double (RAND_MAX) + 1);
    return int(low + floor( d * (double(high) - low + 1)));
}
        

//open file, read the number of servers and objects, create a link list of 
//objects
int readFile(std::vector<float> &probVector, std::vector<int> &objSizeVec) 
{
    string lineString;
    string word;
    int objectSize = 0;
    float probDist = 0;
    int wordCount = 0;
    int lineCounter = 0;
    float prob = 0;
    int serversTotal = 0;
    std::ifstream inFile("/home/alizade/ramcloud/Distribution.txt");
    if (inFile.is_open()) {
        while (!inFile.eof()) {
            getline(inFile, lineString, '\n');
            lineCounter++;
            std::stringstream lineStream(lineString);
            //LOG(NOTICE,"%s",line);
            //the numebr of servers is in the first line of file
            if (lineCounter == 1) {
                serversTotal = std::stoi(lineString);
            } else {	  
                while (lineStream >> word) {
                    if (wordCount == 0 ) {
                        prob = stof(word);
                        wordCount = 1;
                        //filling the probabilities vector, 
                        //using in traffic generator 
                        probDist = probDist + prob;
                        probVector.push_back(probDist);
                              
                    } else {
                        objectSize = stoi(word);
                        objSizeVec.push_back(objectSize);
                        wordCount = 0;
                    }

                }
            }
        }
        inFile.close();
        return serversTotal;
    } else {
        LOG(NOTICE,"Unable to open the file");
        return 0;
    }
}


ObjectList*
createObjects(RamCloud &client, std::vector<int> objSizeVec
              , std::vector<float> probVector, int serverNum)
{
    //Creating Tables
    char tableName[100];
    uint64_t table;
    int serverId;
    std::vector<std::string> tableNameVec;
    tableNameVec.clear();
    std::vector<uint64_t> tableIdVec;
    tableIdVec.clear();
    int objectSize;
    for ( int j = 0; j < int(objSizeVec.size()); j++) {
        objectSize = objSizeVec.at(j);
        for (int i = 1; i <= serverNum; i++) {
            sprintf(tableName
                    , "table_ObjSize%dServer%d"
                    , objectSize, i);
            client.createTable(tableName);
            table = client.getTableId(tableName);
            tableNameVec.push_back(std::string(tableName));
            tableIdVec.push_back(table);
            LOG(NOTICE,"created table %s with id %lu"
               , tableNameVec.at(serverNum*j+i-1).c_str(), table);
        }
    }
    
    ObjectList* head = new ObjectList;
    ObjectList *objPrev = head;
    ObjectList* objCurr = NULL;
    char **objKeyList = new char*[numSameSizeObj];
    for (int i = 0; i < numSameSizeObj; i++)
        objKeyList[i] = new char[100]; 
    int writtenObjects = 0;
    for (int i = 0; i < serverNum; i++) {
        serverId = i + 1;
        for (int j = 0; j < int(objSizeVec.size()); j++) {
            objectSize = objSizeVec.at(j);
            char val[objectSize];
            memset(val, 0xcc, objectSize);
            for (int k = 0; k < numSameSizeObj; k++) {
                sprintf(objKeyList[k]
                        , "key%d_objSize%dServer%d", k+1, objectSize, i+1);
                LOG(NOTICE,"keyList: %s",objKeyList[k]);
                client.write(tableIdVec.at(i + serverNum * j), objKeyList[k]
                             , downCast<uint16_t>(strlen(objKeyList[k]))
                             , val
                             , downCast<uint32_t>(strlen(val) + 1));
                writtenObjects++;
            }
            objCurr = new ObjectList;
            objCurr->append(probVector.at(j)
                             , serverId, objectSize
                             , tableIdVec.at(i + serverNum * j)
                             , objKeyList
                             , const_cast<char*>
                                    (tableNameVec.at(i + serverNum * j).c_str())
                             , objPrev);
            objPrev = objCurr;
        }
    }

    ObjectList* temp = head;
    head = head->next;
    delete temp;
    
    for (int i = 0; i < numSameSizeObj; i++){
        delete[] objKeyList[i];
    }
    delete[] objKeyList;

    objCurr = head;
    while (objCurr){
        printObj(objCurr);
        objCurr = objCurr->next;
    }  

    LOG(NOTICE,"\n-----------write complete for total of %d objects----------"
              , writtenObjects);
    return head;
}

class RpcList
{
  public:
    RpcList();
  public:
    int objectSize;
    int serverId;
    uint64_t start;
    Buffer *buffer;
    ReadRpc *rpc; 
    RpcList *next;
};

RpcList::RpcList(): objectSize(0) 
                  , serverId(0)
                  , start(0)
                  , buffer(NULL)
                  , rpc(NULL)
                  , next(NULL)
{
}

int
main(int argc, char *argv[])
try
{

    int activeRpcCap;
    int count, removeCount;
    uint32_t objectDataSize;
    uint32_t tableCount;
    uint32_t skipCount;
    int clientIndex;
    int numClients;
    bool exercise;
    uint64_t thruput;
    
    // need external context to set log levels with OptionParser
    Context context(true);

    OptionsDescription clientOptions("Client");
    clientOptions.add_options()

        // These first two options are currently ignored. They're here so that
        // this script can be run with cluster.py.
        ("clientIndex",
         ProgramOptions::value<int>(&clientIndex)->
            default_value(0),
         "Index of this client (first client is 0; currently ignored)")
        ("numClients",
         ProgramOptions::value<int>(&numClients)->
            default_value(1),
         "Total number of clients running (currently ignored)")

        ("fast,f",
         ProgramOptions::bool_switch(&fillWithTestData),
         "Use a single fillWithTestData rpc to insert recovery objects.")
        ("tables,t",
         ProgramOptions::value<uint32_t>(&tableCount)->
            default_value(1),
         "The number of tables to create with number objects on the master.")
        ("skip,k",
         ProgramOptions::value<uint32_t>(&skipCount)->
            default_value(1),
         "The number of empty tables to create per real table."
         "An enormous hack to create partitions on the crashed master.")
        ("number,n",
         ProgramOptions::value<int>(&count)->
            default_value(1024),
         "The number of values to insert.")
        ("removals,r",
         ProgramOptions::value<int>(&removeCount)->default_value(0),
         "The number of values inserted to remove (creating tombstones).")
        ("size,s",
         ProgramOptions::value<uint32_t>(&objectDataSize)->
            default_value(1024),
         "Number of bytes to insert per object during insert phase.")
        ("throughput,p",
         ProgramOptions::value<uint64_t>(&thruput)->default_value(10000000000),
         "Client network bandwdith")
        ("exercise",
         ProgramOptions::bool_switch(&exercise),
         "Call exerciseCluster repeatedly (intended for coordinator "
         "crash testing).")
        ("rpccap,c",
         ProgramOptions::value<int>(&activeRpcCap)->default_value(25),
         "Maximum number of outstanding RPC's at a time");



    OptionParser optionParser(clientOptions, argc, argv);
    context.transportManager->setSessionTimeout(
            optionParser.options.getSessionTimeout());

    LOG(NOTICE, "client: Connecting to %s",
        optionParser.options.getCoordinatorLocator().c_str());

    string locator = optionParser.options.getExternalStorageLocator();
    if (locator.size() == 0) {
        locator = optionParser.options.getCoordinatorLocator();
    }
    RamCloud client(&context, locator.c_str(),
            optionParser.options.getClusterName().c_str());

    if (exercise) {
        while (1) {
            exerciseCluster(&client);
            usleep(2000000);
        }
    }
    
    std::vector<float> probVector;
    probVector.clear();
    std::vector<int> objSizeVec;
    objSizeVec.clear();
    int serversTotal = readFile(probVector, objSizeVec);
    if (probVector.size() != objSizeVec.size()){
        
        LOG(NOTICE, "error in reading file, totoal objects read:%zu,\
total probs read:%zu", probVector.size(), objSizeVec.size());
        return 0;
    }

    ObjectList* head = createObjects(client, objSizeVec
                                     , probVector, serversTotal);
    // a simple read of the objects to make sure all abjects can 
    // be read
    Buffer buf;
    for (int i = 0; i < 10; i++) {
        ObjectList* objCurr = head;
        while (objCurr) {
            uint64_t st = Cycles::rdtsc();
            client.read(objCurr->tableId, objCurr->keyList[0]
                        , downCast<uint16_t>(strlen(objCurr->keyList[0]))
                        , &buf);
            uint64_t sp = Cycles::rdtsc();
            LOG(NOTICE,"read took %lu nanoseconds for object %d on server %d"
                , Cycles::toNanoseconds(sp - st)
                , objCurr->objectSize, objCurr->serverId);
            objCurr = objCurr->next;

        }
    }
    LOG(NOTICE, "******************************************End of the usual \
reads*************************************");

    vector<uint64_t> latency(size_t(count), 0);
    vector<int> objectSizes(size_t(count), 0);
    vector<int> serverIds(size_t(count),0);
    uint64_t stop = 0;
    int rpcCount = 0;
    int activeRpcNum = 0;
    RpcList* headRpc = NULL;
    int ind = 0;
    while (true) {
        if (activeRpcNum <= activeRpcCap && rpcCount < count) {
            //find a random object in a random server 
            ObjectList* objCurr = head;
            double r = randomReal(0, 1);
            int serverNum = randomInteger(1, serversTotal);
            while (objCurr) {
                if( (objCurr->serverId == serverNum) 
                    && (objCurr->probDist >= r) ) {

                    LOG(DEBUG, 
                        "found the server to read object from. \
    ServerId is: %d, ObjectSize is: %d"
                        , objCurr->serverId, objCurr->objectSize);

                    break;
                }
                objCurr = objCurr->next;
            }

            //add a new rpc to the list
            RpcList* currRpc = new RpcList;
            currRpc->next = headRpc;
            headRpc = currRpc;
            currRpc->start = Cycles::rdtsc();
            currRpc->objectSize = objCurr->objectSize;
            currRpc->serverId = objCurr->serverId;
            currRpc->buffer = new Buffer;
            currRpc->rpc = new ReadRpc(
                                 &client, objCurr->tableId, objCurr->keyList[0]
                               , downCast<uint16_t>(strlen(objCurr->keyList[0]))
                               , currRpc->buffer);

            LOG(DEBUG,"memory address of the rpc:%p",currRpc->rpc);
            activeRpcNum++;
            rpcCount++;
        }
        for (int rr = 0; rr < 2; rr++) {
            client.clientContext->dispatch->poll();
        }
        //check on the list of rpc. If any of them is finished, remove it from 
        //the list and add measure the latency for it.
        RpcList* currRpc = headRpc;
        RpcList* prevRpc = NULL; 
        while (currRpc) {
            if (currRpc->rpc->isReady()) {
                stop = Cycles::rdtsc();
                latency.at(ind) = Cycles::toNanoseconds(stop 
                                                          - currRpc->start);
                serverIds.at(ind) = currRpc->serverId;
                objectSizes.at(ind++) = currRpc->objectSize;
                currRpc->buffer->reset();
                delete currRpc->buffer;
                delete currRpc->rpc;
                RpcList *toBeDeleted = currRpc;

                activeRpcNum--;
                if (currRpc == headRpc)
                    headRpc = headRpc->next;
                currRpc = currRpc->next;
                if (prevRpc)
                    prevRpc->next = currRpc;

                delete toBeDeleted;
            } else {
                prevRpc = currRpc;
                currRpc = currRpc->next;
            }
        }

        LOG(DEBUG,"number of total rpc sent: %d and number of active rpc: %d"
            , rpcCount, activeRpcNum);
        
        if ((activeRpcNum == 0) && (rpcCount ==  count))
            break;
    }
    std::ofstream outFile;
    outFile.open("/home/alizade/ramcloud/latency.txt");
    for(size_t j = 0; j < latency.size(); j++)
        outFile << std::fixed << std::setprecision(12) << latency[j] << ",\t" 
                << objectSizes[j] << ",\t" << serverIds[j] <<"\n";
    outFile.close();

    freeObjectList(head); 
    return 0;
} catch (RAMCloud::ClientException& e) {
    fprintf(stderr, "RAMCloud exception: %s\n", e.str().c_str());
    return 1;
} catch (RAMCloud::Exception& e) {
    fprintf(stderr, "RAMCloud exception: %s\n", e.str().c_str());
    return 1;
}
