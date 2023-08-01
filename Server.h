#include "cryptoUtility.h"
#define SERVERPRIVATEKEYPATH "./server/server_rsa_privkey.pem"
#define SERVERPUBLICKEYPATH "./server/server_rsa_pubkey.pem"

const int MAX_CLIENTS = 10; 
const int BUFFER_SIZE = 4096;
const int NUMBER_OF_TRANSFER = 20; // it is the T parameter of the project 
static unsigned char id_clients=0;

struct LoggedUser { //handle multiple clients
    string username;
    int id;
    unsigned char * session_key;
    unsigned char * HMAC_key;
    time_t session_key_generation_ts;
    int operation_counter_client;
    int operation_counter_server;
    uint16_t port;
    bool logged;
};
class Server{
public:
    Server(const uint16_t port);
    ~Server();
    void run();
    string perform_operation(string commands, int sd,int index); // handle clients operations at an application level
    string read_balance(int index);
    string balance(string filepath);
    void logout(int index);
    int transfer(string username, string receiver, int amount); 
    void authAndLogin(unsigned char * buffer, int len,int sd); 
    void reportError(int sd, int index);
    void reportError(int sd, unsigned char * session_key,unsigned char * mac_key);
    bool verifyClientExist(string username);
    string getClientOperation(unsigned char * buffer,int byterec,int index); // receives the ciphertext and obtain the command for operation
    unsigned char * respondToClient(string operation,int sd,int index,int &byte_tosend); // creates the ciphertext for the result of an operation
    
private: 
    int port;
    int listener;
    int new_socket;
    int sd;
    int max_sd;
    struct sockaddr_in address;
    struct sockaddr_in cl_addr;
    fd_set master;
    fd_set read_fds;
    int fdmax;
    socklen_t addrlen;
    unsigned char buffer[BUFFER_SIZE];
    EVP_PKEY * publicKey; // server public key
    vector<LoggedUser> user_logged;
    int indexOfUser(string username); //utility function
    int indexOfUser(unsigned char id);
};
