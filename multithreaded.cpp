// prerequisites: sudo apt-get install openssl libssl-dev libcrypto++-dev libcrypto++-utils
// compile: g++ multithreaded.cpp -o multithreaded -pthread -lcrypto -lcryptopp
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

// sha256
#include <openssl/sha.h>
// keccak256
#include <cryptopp/keccak.h>
#include <cryptopp/hex.h>

using namespace std;

// function declarations
vector<int> compute_lps_array(string pattern, int M, vector<int> &lps);
void dumbo_check(string word);
void find_shortest_username(string name_start, bool only_print_if_multiple_occurrences, uint64_t interval_lower, uint64_t interval_upper);
vector< tuple<uint64_t,uint64_t> > generate_multithreaded_intervals(uint64_t upper_limit, const unsigned int processor_count);
string keccak256(string& message);
int kmp_search(string text, string pattern);
string sha256(const string& input);
void start_hashing(string word, uint64_t upper_limit, bool only_print_double_multioccurrences);
bool vector_contains_string_already(vector<string>& v, string s);


// prefix table for KMP algorithm
vector<int> compute_lps_array(string pattern, int M, vector<int> &lps) {
    int len = 0;
    lps[0] = 0;
    int i = 1;

    while (i < M) {
        if (pattern[i] == pattern[len]) {
            len++;
            lps[i] = len;
            i++;
        } else {
            if (len != 0) {
                len = lps[len - 1];
            } else {
                lps[i] = 0;
                i++;
            }
        }
    }
    return lps;
}


void dumbo_check(string word){
	static const set<char> hex_compatible_chars = {'a', 'b', 'c', 'd', 'e', 'f'};
	for (char c : word){
        if (hex_compatible_chars.find(c) == hex_compatible_chars.end()) {
        	cout << "An input word that has a non-hex char can never pass any of the tests. Also make sure you wrote the word in lowercase. Exiting." << endl;
            exit(0);
        }
	}
	
}


void find_shortest_username(string name_start, bool only_print_if_multiple_occurrences, uint64_t interval_lower, uint64_t interval_upper) {

    while (interval_lower < interval_upper){
    	string hashinput = name_start + to_string(interval_lower); // combine name_start with interval_lower
    	
    	string sha256_hashresult = sha256(hashinput);		// hash it using sha256
    	string keccak256_hashresult = keccak256(hashinput);	// hash it using keccak256
   	
    	// sha256 contains name
    	if (sha256_hashresult.find(name_start) != string::npos){
    			// keccak256 contains name too
    			if (keccak256_hashresult.find(name_start) != string::npos){

				    if (!only_print_if_multiple_occurrences){
				    	cout << "Input: " << hashinput << "\nSHA256: " << sha256_hashresult << "\nKECCAK256: " << keccak256_hashresult <<"\n" << endl;
				    }

					// count occurrences of word in hash
					int sha_count = kmp_search(sha256_hashresult, name_start);
					int keccak_count = kmp_search(keccak256_hashresult, name_start);
					
					if (  (sha_count > 1)  && (keccak_count > 1)){
						cout << "\nDOUBLE MULTI-OCCURRENCE!" << "\nInput: " << hashinput << "\nSHA256: " << sha256_hashresult << "\nKECCAK256: " << keccak256_hashresult << "\nSHA Occurrences: " << sha_count << "\nKeccak Occurrences: " << keccak_count << endl;
					}
					
    			}
    		
    	}

    	++interval_lower;
    
    }
	
}


// depending on available cores and max number splits workload evenly among threads
vector< tuple<uint64_t,uint64_t> > generate_multithreaded_intervals(uint64_t upper_limit, const unsigned int processor_count) {
	// get vector<tuple<uint64_t,uint64_t>> for multithreaded intervals
	uint64_t interval_cardinality = upper_limit / processor_count;
	vector< tuple<uint64_t,uint64_t> > intervals;
	uint64_t cur_interval_upper_limit = 0;
	uint64_t cur_interval_lower_limit = 0;
	for (unsigned int i=0; i<processor_count; ++i){
		cur_interval_lower_limit = cur_interval_upper_limit + 1;
		cur_interval_upper_limit += interval_cardinality;
		intervals.push_back(make_tuple(cur_interval_lower_limit, cur_interval_upper_limit));

	}
	
	return intervals;
}


// hash using keccak256
string keccak256(string& message) {
    CryptoPP::Keccak_256 keccak256;
    byte digest[CryptoPP::Keccak_256::DIGESTSIZE];

    keccak256.CalculateDigest(digest, (byte*)message.c_str(), message.length());

    CryptoPP::HexEncoder encoder;
    string output_uppercase;
    encoder.Attach(new CryptoPP::StringSink(output_uppercase));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

	string output_lowercase;
	for (char c : output_uppercase){
		if (  (c > 64) && (c < 93)  ) {
			output_lowercase += c+32;	// look at ascii table
		}
		else {
			output_lowercase += c;
		}
		
	}
	
	
	return output_lowercase;

}


// count occurrences of substring in string using KMP (Knuth–Morris–Pratt algorithm)
int kmp_search(string text, string pattern) {
    int M = pattern.size();
    int N = text.size();
    int count = 0;

    vector<int> lps(M);

    compute_lps_array(pattern, M, lps);

    int i = 0; 
    int j = 0; 
    while (i < N) {
        if (pattern[j] == text[i]) {
            j++;
            i++;
        }

        if (j == M) {
            count++;
            j = lps[j - 1];
        } else if (i < N && pattern[j] != text[i]) {
            if (j != 0)
                j = lps[j - 1];
            else
                i = i + 1;
        }
    }
    return count;
}


// hash using sha256
string sha256(const string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}


void start_hashing(string word, uint64_t upper_limit, bool only_print_double_multioccurrences) {
	// get amount of available cores (8 on my machine)
	const unsigned int processor_count = std::thread::hardware_concurrency();
	
	if (processor_count > 0){
		vector< tuple<uint64_t,uint64_t> > interval_vec = generate_multithreaded_intervals(upper_limit, processor_count);
		
		// create thread vector
		vector<thread> threads;
		
		// assign intervals to threads and specify task
		for (tuple<uint64_t,uint64_t> value : interval_vec){
			threads.emplace_back(find_shortest_username, word, only_print_double_multioccurrences, get<0>(value), get<1>(value));
		}
		
		// print some user info before starting the run
		cout << "Word: " << word << "\nThreads: " << processor_count << "\nAmount Hashing Operations: " << upper_limit << "\nMining..\n" << endl;
		
		// run tasks concurrently
		for (auto &thread : threads)
    	{
        	thread.join();
    	}
		
	}
	else {
		cout << "Failed to get amount of cores. Starting slow, singled-threaded search:\n" << endl;
		find_shortest_username(word, only_print_double_multioccurrences, 0, upper_limit);
	}
	
	cout << "\nAll threads have completed their search." << endl;
}


// checks if vector contains given string already
bool vector_contains_string_already(vector<string>& v, string s) {
	if (find(v.begin(), v.end(), s) != v.end())
	{
	  return true;
	}
	else {
		return false;
	}
}


/* What does this do?

Takes base word (e.g. cafe)
Generates numbers
Combines <word><number> and hashes it using SHA256 and KECCAK256

Two modes:
-> bool true: only prints input if both SHA256 AND KECCAK256 output contains base word
-> bool false: only prints input if both SHA256 AND KECCAK256 EACH have MULTIPLE occurrences of base word (much harder)

What is the point?
Find cool usernames that are not taken already!
*/
int main(){
	string word = "dad";								// lowercase-only! recommendation would be smaller than 6 chars for any setting
	uint64_t upper_limit = 100000000ULL;				// current value is 100 million, theoretical max value is 18446744073709551615ULL
	bool only_print_double_multioccurrences = true;		// if this is true and word is longer than 3 chars its likely this wont find much
	
	dumbo_check(word);
	start_hashing(word, upper_limit, only_print_double_multioccurrences);

	return 0;

}

/* My fav config: 100 million upper limit, 8 threads -> ca. 120 - 150 seconds on my machine
				 Words of length 4 or longer will probably require higher upper limit than 100 million (even with bool false)

Double multihit examples:
	bad76789122
	bed96933575
	bed147373429
	cab14703815
	cab4956872262356474594
	cab8651203168295016433
	dad23131298
	dad43585819

my fav name so far:
	bed147373429 (why? 2x sha occurr 2x keccak occurr and notable every occurrence close (1 and 2 other chars between))


Inspriations for search words:
bad, bed, cab, cafe, dad, dead, decade, decaf, facade
*/

