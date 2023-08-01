#include "cryptoUtility.h"


#define STDIN 0
#define OP_LEN 4
#define USER_LEN 30
#define PASSWORD_LEN 30
#define BUFFER_LEN 4096



class Client{
public:
    Client(const uint16_t clientP, const uint16_t serverP);
    ~Client();
    void ClientListen();
    int checkLocalInput(char* buffer);
    sockaddr_in getClient(){return client_address;};
    uint16_t getClientPort(){return client_address.sin_port;}
    uint16_t getServerPort(){return server_port;}
    int checkTCPInput(int i);
    void setId(int i){id=i;}
    int getId(){return id;}
    int incrementAndReturnCounter(){return ++counter;}
    int getCounterServer(){return counter_server;}
    void incrementCounterServer(){counter_server++;}
    bool isPubServerKeyLoaded();
    //void controllaInput();
    //void add_client(int client_id);
    //void remove_client(int client_id);
    //void broadcast(std::string message);
private:
    //std::vector<int> client_ids;
    //bool is_running;
    //uint16_t server_port;
    int server_port;
    string usr_name;
    int id;
    int counter = 0;
    int counter_server = 0;
    bool logged_in = false;
    sockaddr_in client_address, server_address;
    static const int BACKLOG = 10;
    EVP_PKEY * publicKeyServer;
    EVP_PKEY * publicKeyClient;
    DH* dh;
    //unsigned char * sharedSecret; 
    unsigned char * sessionKey;
    unsigned char * HMACKey;
    int createConnection();
    void setUsername(string usr){usr_name = usr;}
    void sendHistoryRequestAndListen(string cmd);
    int sendmsg(char* send_content);
    bool transfer(string cmd);
    void login();
    void logout();
    void balance();
    void preTransfer();
    void history();
    int sendmsg(unsigned char * send_content, size_t len);
    int sendLoginMsg(string sent, unsigned char ** nonce, unsigned char ** dh_uchar, EVP_PKEY ** dh_pub);
    int receiveServerLoginAnswer(int sd, unsigned char** nonce_server, unsigned char** dh_params_server,
                                unsigned char** sharedSecret, EVP_PKEY ** dh_pub, unsigned char * dh_client, 
                                unsigned char * nonce_client);
    int sendHashCheck(int sd, string password, EVP_PKEY* privkey, unsigned char* client_dh,
                    unsigned char * nonce_client, unsigned char* server_dh,
                    unsigned char *nonce_server);
};
