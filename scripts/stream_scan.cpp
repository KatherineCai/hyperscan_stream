#include "stream_scan.h"
// Match event handler: called every time Hyperscan finds a match.
static
int onMatch(unsigned int id, unsigned long long from, unsigned long long to,unsigned int flags, void *ctx) {
    // Our context points to a size_t storing the match count
	size_t *matches = (size_t *)ctx;
    (*matches)++;
    id_array[callback_count] = id; 
    from_array[callback_count] = from;
    to_array[callback_count] = to; 
    callback_count++;
    //temp = id;
    //pair <unsigned long long , unsigned long long> fromto (from, to);
    //pair <unsigned int, pair <unsigned long long, unsigned long long>> id_from (id, from);
    printf ("id = %d, form = %d, to = %d\n", id, from, to);
	printf("matches = %d\n", *matches);

	return 0; // continue matching
}
// Class wrapping all state associated with the benchmark
bool Benchmark::readStreams(const  char **readBuffer) {
		if (readBuffer == nullptr) {
			cerr << "ERROR: Unable to read HTTP packet from buffer!" << endl;
			return false;
		}
		#if 0
		struct http_pkthdr pktHeader;
		const unsigned char *pktData;
		while (pktData = http_next(readBuffer, &pktHeader) != nullptr) {
			unsigned int offset = 0, length = 0;
			if (!payloadOffset(pktData, &offset, &length)) {
				continue;
			}
			
			const char *payload = (const char *)pktData + offset;

			packets.push_back(string(payload, length));
		}
		#endif 
		for(size_t i = 0;i != sizeof(readBuffer)/4; ++i){
		//	cout << readBuffer[i] << "    "<< strlen(readBuffer[i])<<endl;
			packets.push_back(string(readBuffer[i],strlen(readBuffer[i])));
		//cout << "i :" << i <<endl << packets[i] << endl;
		}
		return !packets.empty();
	}

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
size_t Benchmark:: matches() const {
        return matchCount;
    }

    // Clear the number of matches found.
void Benchmark::clearMatches() {
        matchCount = 0;
    }
   
void Benchmark::openStreams(){
		streams.resize(1);
		stream_ids.push_back(0);// ALL ID  IS NUMBER 0
	 	
		for (auto &stream : streams) {
            hs_error_t err = hs_open_stream(db_streaming, 0, &stream);
            if (err != HS_SUCCESS) {
               cerr << "ERROR: Unable to open stream. Exiting." << endl;
               exit(-1);
            }
        } 
	}

void Benchmark::closeStreams() {
        for (auto &stream : streams) {
            hs_error_t err = hs_close_stream(stream, scratch, onMatch,
                                             &matchCount);
            if (err != HS_SUCCESS) {
              cerr << "ERROR: Unable to close stream. Exiting." << endl;
              exit(-1);
            }
        }
    }	


    // Hyperscan using the block-mode interface.
void Benchmark::scanStreams() {
	//	printf("stream_ids[0]:%d",stream_ids[0]);
		for(size_t i = 0; i != packets.size(); ++i ){
			const std::string &pkt = packets[i];
			hs_error_t err = hs_scan_stream(streams[stream_ids[0]],pkt.c_str() , pkt.length(), 0,scratch, onMatch, &matchCount);		
			//printf("matchCount = %d\n", matches());
			if (err != HS_SUCCESS) {
				cout << "ERROR: Unable to scan STREAM packet. Exiting." << endl;
				exit(-1);
			}
		}
    }

void Benchmark::scanBlock(){
      	for(size_t i = 0; i != packets.size(); ++i){
			const std::string &pkt = packets[i];
			hs_error_t err = hs_scan(db_block, pkt.c_str(), pkt.length(), 0,scratch, onMatch, &matchCount);	
			//printf("matchCount = %d\n", matches());
		if (err != HS_SUCCESS) {
			cout << "ERROR: Unable to scan BLOCK  packet. Exiting." << endl;
			exit(-1);
		}
	}
	}	
    // Display some information about the compiled database and scanned data.
void Benchmark::displayStats() {
        hs_error_t err;
        size_t dbStream_size = 0;
		size_t dbBlock_size = 0;
        err = hs_database_size(db_streaming, &dbStream_size);
        if (err == HS_SUCCESS) {
            cout << "stream mode Hyperscan database size        : "
                 << dbStream_size << " bytes." << endl;
        } else {
            cout << "Error getting stream mode Hyperscan database size"
                 << endl;
        }
		err = hs_database_size(db_block,&dbBlock_size);
		if (err == HS_SUCCESS) {
            cout << "block  mode Hyperscan database size        : "
                 << dbBlock_size << " bytes." << endl;
        } else {
            cout << "Error getting block  mode Hyperscan database size"
                 << endl;
        } 
    }

#if 0
static char *http_next(const unsigned char *pktBuffer, struct http_pkthdr *pktHeader, int offset, int control)
{

	if (pktBuffer + offset == nullptr) {
		cerr << "ERROR: Unable to read HTTP packet from buffer!" << endl;
		exit(-1);	
	}

	char buffer[control-offset+1];
	strncpy(buffer, pktBuffer + offset, control - offset);

	string str(buffer);
	vector<string> pktStrs;
	vector<string> pktline;

	boost::split(pktStrs, str, boost::is_any_of("\r\n"));

	for(auto &line in pktStrs) {
		boost::split(pktline, line, boost::is_any_of(" "));

		if (line[0] == "GET") {
			getpacket packet;
			state = "GET";
			packet.url = line[1];
		}
		else if (line[0] == "POST") {
			postpacket packet;
			state = "POST";
			packet.url = line[1];
		} else if (line[0] == "Host:")
			packet.host = line[1];
		else if (line[0] == "Cdn-Src-Ip:")
			packet.srcip = line[1];


	}
	if (http_url[0] == "GET") {
		url = "http://" + http_ip[1] + http_url[1];
	} else if (http_url[0] == "POST") {
		url = http_data[1] + http_url[1];
		string body = http_data[http_data.size()-1];
	}
	
	*length = (unsigned int)url.length();
	cout << url << endl;
	char *p = (char*)url.c_str();
	return p;

}


/**
 * Helper function to locate the offset of the first byte of the payload in the
 * given http packet. Offset into the packet, and the length of the payload
 * are returned in the arguments @a offset and @a length.
 */
static bool payloadOffset(const unsigned char *pkt_data, unsigned int *offset, unsigned int *length)
{
	const	
}
#endif
// helper function - see end of file
/*static void parseFile(const char *filename, vector<string> &patterns,
                      vector<unsigned> &flags, vector<unsigned> &ids);
*/
static hs_database_t *buildDatabase(const vector<const char *> &expressions,
                                    const vector<unsigned> flags,
                                    const vector<unsigned> ids,
                                    unsigned int mode) {
    hs_database_t *db;
    hs_compile_error_t *compileErr;
    hs_error_t err;

    Clock clock;
    clock.start();

    err = hs_compile_multi(expressions.data(), flags.data(), ids.data(),
                           expressions.size(), mode, nullptr, &db, &compileErr);

    clock.stop();

    if (err != HS_SUCCESS) {
        if (compileErr->expression < 0) {
            // The error does not refer to a particular expression.
            cerr << "ERROR: " << compileErr->message << endl;
        } else {
            cerr << "ERROR: Pattern '" << expressions[compileErr->expression]
                 << "' failed compilation with error: " << compileErr->message
                 << endl;
        }
        // As the compileErr pointer points to dynamically allocated memory, if
        // we get an error, we must be sure to release it. This is not
        // necessary when no error is detected.
        hs_free_compile_error(compileErr);
        exit(-1);
    }

    cout << "Hyperscan " << " mode database compiled in " 
		<< clock.seconds() << " seconds." << endl;

    return db;
}

/**
 * This function will read in the file with the specified name, with an
 * expression per line, ignoring lines starting with '#' and build a Hyperscan
 * database for it.
 */
static void databasesFromFile(const char *filename,
                              hs_database_t **db_streaming,hs_database_t **db_block) {
    // hs_compile_multi requires three parallel arrays containing the patterns,
    // flags and ids that we want to work with. To achieve this we use
    // vectors and new entries onto each for each valid line of input from
    // the pattern file.
    vector<string> patterns;
    vector<unsigned> flags;
    vector<unsigned> ids;

    // do the actual file reading and string handling
    parseFile(filename, patterns, flags, ids);

    // Turn our vector of strings into a vector of char*'s to pass in to
    // hs_compile_multi. (This is just using the vector of strings as dynamic
    // storage.)
    vector<const char*> cstrPatterns;
    for (const auto &pattern : patterns) {
        cstrPatterns.push_back(pattern.c_str());
    }

    cout << "Compiling Hyperscan databases with " << patterns.size()
         << " patterns." << endl;
			
	*db_streaming = buildDatabase(cstrPatterns, flags, ids, HS_MODE_STREAM)	;
    *db_block = buildDatabase(cstrPatterns, flags, ids, HS_MODE_BLOCK);
}



static void usage(const char *prog) {
    cerr << "Usage: " << prog << " [-n repeats] <pattern file> <pcap file>" << endl;
}

/**
 * Fill a data buffer from the given filename, returning it and filling @a
 * length with its length. Returns NULL on failure.
 */
static char *readInputData(const char *inputFN, unsigned int *length) {
    FILE *f = fopen(inputFN, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: unable to open file \"%s\": %s\n", inputFN,
                strerror(errno));
        return NULL;
    }

    /* We use fseek/ftell to get our data length, in order to keep this example
     * code as portable as possible. */
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }
    long dataLen = ftell(f);
    if (dataLen < 0) {
        fprintf(stderr, "ERROR: ftell() failed: %s\n", strerror(errno));
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }

    /* Hyperscan's hs_scan function accepts length as an unsigned int, so we
     * limit the size of our buffer appropriately. */
    if ((unsigned long)dataLen > UINT_MAX) {
        dataLen = UINT_MAX;
        printf("WARNING: clipping data to %ld bytes\n", dataLen);
    } else if (dataLen == 0) {
        fprintf(stderr, "ERROR: input file \"%s\" is empty\n", inputFN);
        fclose(f);
        return NULL;
    }

    char *inputData =(char *)malloc(dataLen);
    if (!inputData) {
        fprintf(stderr, "ERROR: unable to malloc %ld bytes\n", dataLen);
        fclose(f);
        return NULL;
    }

    char *p = inputData;
    size_t bytesLeft = dataLen;
    while (bytesLeft) {
        size_t bytesRead = fread(p, 1, bytesLeft, f);
        bytesLeft -= bytesRead;
        p += bytesRead;
        if (ferror(f) != 0) {
            fprintf(stderr, "ERROR: fread() failed\n");
            free(inputData);
            fclose(f);
            return NULL;
        }
    }

    fclose(f);

    *length = (unsigned int)dataLen;
    return inputData;
}

/*****************************************************************
 *  +---------------+-------+-----+-------+----------+----+----+ *
 *  |request method | space | URL | space | protocol | \r | \n | *
 *  +---------------+-------+-----+-------+----------+----+----+ *
 *  |      Host     |   :   |             |   \r     |   \n    | *
 *  +---------------+-------+----------------------------------+ *
 *  |  Cdn-Src-IP   |   :   |    IP       |   \r     |   \n    | *
 *  +---------------+-------+-------------+----------+---------+ *
 *  |                         ...                              | *
 *  +----------------------------------------------------------+ *
 *****************************************************************
 */ 
static char *readHttpPacket(const char *pkt_data, unsigned int *length)
{	
	if (pkt_data == nullptr) {
		cerr << "ERROR: http packet is null." << endl;
		exit(-1);	
	}
	string url;
	string str = pkt_data;
	vector<string> http_data;
	vector<string> http_url;
	vector<string> http_ip;
	boost::split(http_data, str, boost::is_any_of("\r\n"));
	boost::split(http_url, http_data[0], boost::is_any_of(" "));
	boost::split(http_ip, http_data[2], boost::is_any_of(" "));

	if (http_url[0] == "GET") {
		url = "http://" + http_ip[1] + http_url[1];
	} else if (http_url[0] == "POST") {
		url = http_data[1] + http_url[1];
		string body = http_data[http_data.size()-1];
	}
	
	*length = (unsigned int)url.length();
	cout << url << endl;
	char *p = (char*)url.c_str();
	return p;
}
/*
urlValid(const char *inputNF)
{

}

writeData(const char *inputData)
{
	callback(*inputData);
}
*/
// Main entry point.
int main(int argc, char **argv) 
{
    const char *patternFile = "regular.txt";
    //const char *inputFN = "GET /admin/user/index.html HTTP/1.1\r\nHost: wf3.394225.com:8081\r\nCdn-Src-Ip:218.63.117.136";
	const char  * inputData[] = {"abcde","fghijk"};
    // Read our pattern set in and build Hyperscan databases from it.
    cout << "Pattern file: " << patternFile << endl;
    hs_database_t *db_streaming;
  	hs_database_t *db_block;
	static bool no_compile = true;
    Clock clock;
	Clock clock1;
	if (no_compile) {
        //Clock clock;
        clock.start();
		clock1.start();
        databasesFromFile(patternFile, &db_streaming,&db_block);
        clock.stop();
		clock1.stop();
        no_compile = false;
    }    


    // Read our input PCAP file in
    Benchmark bench(db_streaming,db_block);
    bench.displayStats();

    // Scan all our packets in block mode.
	unsigned int length;
//	char *inputData = readHttpPacket(inputFN, &length);

	if (!inputData) {
		hs_free_database(db_streaming);
		hs_free_database(db_block);
		return -1;
	}
 	if(!bench.readStreams(inputData)){
		cerr << "Unable to read packets from inputData.Exiting"<<endl;
	}	
	double  secsStreamingScan = 0.0;
	double secsStreamingOpenClose = 0.0;
	
	clock1.start();
    bench.scanBlock();
    clock1.stop();
    cout << " Scan times of block mode: " << clock1.seconds() << endl;
	printf ("block matchCount = %d\n", bench.matches());

	bench.clearMatches();
	
	clock.start();
    bench.openStreams();
    clock.stop();
    secsStreamingOpenClose += clock.seconds();

	bench.clearMatches();
	clock.start();
	bench.scanStreams();
	clock.stop();
	secsStreamingScan += clock.seconds();
	
	clock.start();
    bench.closeStreams();
    clock.stop();
    secsStreamingOpenClose += clock.seconds();

	//urlValid(inputFN);
	//if (bench.matches()) {
	//	writeData(callback, *inputData);
	//}
	cout << " Scan times of stream mode: " << clock.seconds() << endl;
	printf ("stream matchCount = %d\n", bench.matches());
    
    bench.clearMatches();

    // Close Hyperscan databases
    //hs_free_database(db_streaming);

    return 0;
}


static unsigned parseFlags(const string &flagsStr) { 
    unsigned flags = 0; 
    for (const auto &c : flagsStr) { 
        switch (c) { 
        case 'i': 
            flags |= HS_FLAG_CASELESS; break; 
        case 'm': 
            flags |= HS_FLAG_MULTILINE; break; 
        case 's': 
            flags |= HS_FLAG_DOTALL; break; 
        case 'd':
            flags |= HS_FLAG_SOM_LEFTMOST; break;
        case 'H':
            flags |= HS_FLAG_SINGLEMATCH; break;
        case 'V':
            flags |= HS_FLAG_ALLOWEMPTY; break;
        case '8':
            flags |= HS_FLAG_UTF8; break;
        case 'W':
            flags |= HS_FLAG_UCP; break;
        case '\r': // stray carriage-return
            break;
        default:
            cerr << "Unsupported flag \'" << c << "\'" << endl;
            exit(-1);
        }
    }
    return flags;
}
static void parseFile(const char *filename, vector<string> &patterns,
                      vector<unsigned> &flags, vector<unsigned> &ids) {
    ifstream inFile(filename);
    if (!inFile.good()) {
        cerr << "ERROR: Can't open pattern file \"" << filename << "\"" << endl;
        exit(-1);
    }

    for (unsigned i = 1; !inFile.eof(); ++i) {
        string line;
        getline(inFile, line);

        // if line is empty, or a comment, we can skip it
        if (line.empty() || line[0] == '#') {
            continue;
        }

		size_t colonIDx = line.find_first_of(":");
        if (colonIDx == string::npos) {
            cerr << "ERROR: Could not parse line " << i << endl;
            exit(-1);
        }

        //we should have an unsigned int as an ID, before the colon
        unsigned id = std::stoi(line.substr(0, colonIDx).c_str());

        //rest of the expression is the PCRE
        const string expr(line.substr(colonIDx + 1));

        size_t flagsStart = expr.find_last_of('/');
        if (flagsStart == string::npos) {
            cerr << "ERROR: no trailing '/' char" << endl;
            exit(-1);
        }

		string pcre(expr.substr(1, flagsStart - 1));
        string flagsStr(expr.substr(flagsStart + 1, expr.size() - flagsStart));
        unsigned flag = parseFlags(flagsStr);
        patterns.push_back(pcre);
        flags.push_back(flag);
        ids.push_back(id);
    }
}
