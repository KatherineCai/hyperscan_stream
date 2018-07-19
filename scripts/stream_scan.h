#include <cstring>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <boost/algorithm/string.hpp>
#include <limits.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <hs.h>

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using std::unordered_map;
using std::vector;

static unsigned int id_array[10];
static unsigned long long from_array[10];
static unsigned long long to_array[10];
static int callback_count = 0;

static int onMatch(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *ctx);


class Clock {
public:
    void start() {
        time_start = std::chrono::system_clock::now();
    }

    void stop() {
        time_end = std::chrono::system_clock::now();
    }

    double seconds() const {
        std::chrono::duration<double> delta = time_end - time_start;
        return delta.count();
    }
private:
    std::chrono::time_point<std::chrono::system_clock> time_start, time_end;
};




// Class wrapping all state associated with the benchmark
class Benchmark {
private:


    vector<size_t>stream_ids;
    vector<string> packets;
    //Hyperscan compiled database (block mode)
    const hs_database_t *db_streaming;
    const hs_database_t *db_block;
	hs_scratch_t *scratch;
    vector<hs_stream_t*>streams;
    // Count of matches found during scanning
    size_t matchCount;

public:
    Benchmark(const hs_database_t *streaming,const hs_database_t *block)
        : db_streaming(streaming),db_block(block), scratch(nullptr),
          matchCount(0) {
		hs_error_t err = hs_alloc_scratch(db_streaming, &scratch);
        if (err != HS_SUCCESS) {
            exit(-1);
        }
        err = hs_alloc_scratch(db_block,&scratch);
        if(err != HS_SUCCESS){
            exit(-1);
        }
    }

    ~Benchmark() {
        // Free scratch region
        hs_free_scratch(scratch);
    }

    bool readStreams(const  char **readBuffer);

#if 0
    //Return the number of bytes scanned
    size_t bytes() const {
        size_t sum = 0;
        for (const auto &packet : packets) {
            sum += packet.size();
        }
        return sum;
    }
#endif
    // Return the number of matches found.
    size_t matches() const ;

    // Clear the number of matches found.
    void clearMatches();
   
    void openStreams();

	void closeStreams();
    // Hyperscan using the block-mode interface.
    void scanStreams();

    void scanBlock();

  	void displayStats() ;
};


static void parseFile(const char *filename, vector<string> &patterns,
                      vector<unsigned> &flags, vector<unsigned> &ids);

static hs_database_t *buildDatabase(const vector<const char *> &expressions,const vector<unsigned> flags,const vector<unsigned> ids,unsigned int mode);


static void databasesFromFile(const char *filename,hs_database_t **db_streaming,hs_database_t **db_block);

static void usage(const char *prog);

//static char *readHttpPacket(const char *pkt_data, unsigned int *length);
static unsigned parseFlags(const string &flagsStr);
