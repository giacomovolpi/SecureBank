#include "Server.h"

Server::Server(uint16_t serverPort) {
        port=serverPort;
        listener=0;
        new_socket=0;
        sd=0;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        publicKey=readPublicKey(SERVERPUBLICKEYPATH); // read the public key of the server and load it in memory
        id_clients=0;
    }

void Server::run() {
        if(!publicKey){
            cerr<<"Failed to load server public key"<<endl;
            exit(EXIT_FAILURE);
        }
        if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            perror("Failed to create socket");
            exit(EXIT_FAILURE);
        }
        if (::bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("Failed to bind");
            exit(EXIT_FAILURE);
        }
        printf("Listener on port %d \n", port);

        if (listen(listener, MAX_CLIENTS) < 0) {
            perror("Failed to listen");
            exit(EXIT_FAILURE);
        }
        FD_ZERO(&master);
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &master); 
        FD_SET(listener, &master);
        fdmax=listener;
        puts("Waiting for connections ...");
        while (true) {
            read_fds = master;
            sd = select(fdmax + 1, &read_fds, NULL, NULL, NULL);
            if(sd>0){
            for (sd = 0; sd <= fdmax; sd++) {
                if (FD_ISSET(sd, &read_fds)) {
                    if (sd == listener) { // new request
                        addrlen = sizeof(cl_addr);
                        new_socket = accept(listener, (struct sockaddr *)&cl_addr, &addrlen);
                        printf("New connection, socket fd is %d, IP is: %s, port: %d\n", new_socket, inet_ntoa(cl_addr.sin_addr), ntohs(cl_addr.sin_port));
                        FD_SET(new_socket, &master); // add the descriptor to fsd master
                        if (new_socket > fdmax)
                            fdmax = new_socket;
                    }
                    else if (sd == STDIN_FILENO) { 
                        int byteread=0;
                        byteread=read(STDIN_FILENO, buffer, BUFFER_SIZE);
                        DEBUG_PRINT(("Buffer read %s | %d",buffer,byteread));
                        if(memcmp(buffer,"exit\n",5)==0){
                            return;
                        }
                    }
                    else { 
                        int byterec=recv(sd, buffer, BUFFER_SIZE,0);
                        DEBUG_PRINT(("Byte received %d",byterec));
                        DEBUG_PRINT(("Received command from socket fd: %d", sd));
                        if(memcmp(buffer,"NEW",COMMAND_SIZE)==0){  // authentication request
                            authAndLogin(buffer+COMMAND_SIZE,byterec-COMMAND_SIZE,sd);
                        }
                        else { // operation request
                            DEBUG_PRINT(("Received operation"));
                            int indexUser=indexOfUser(buffer[0]); // get the index of the user logged
                            if(indexUser>=0){
                                string operation = getClientOperation(buffer,byterec,indexUser); // get client's request
                                string result_operation = perform_operation(operation,sd,indexUser); // perform operation and prepare response
                                result_operation += " " + to_string(++user_logged[indexUser].operation_counter_server); // add operation counter
                                int byte_tosend=0;
                                unsigned char * cptxt = respondToClient(result_operation,sd,indexUser,byte_tosend); // encrypt the response and send back to client
                                send(sd,cptxt,byte_tosend,0);
                                securefree(cptxt,byte_tosend); // delete the ciphertext
                            }
                            else{ // the request has come from a user not authenticated
                                reportError(sd, -1);
                            }
                        }
                        close(sd);
                        FD_CLR(sd, &master);
                        memset(buffer,0,BUFFER_SIZE);
                    }
              
                }
            }
        }
        }
}

/* getClientOperation receives the ciphertext and obtain the command according to the protocol */
string Server::getClientOperation(unsigned char * buffer,int byterec,int index){
    DEBUG_PRINT(("byterec %d ct bytes %d\n", byterec, byterec-IVLEN-SHA256LEN-1));

    string operation = decryptCipherText(buffer,byterec-IVLEN-SHA256LEN-1,user_logged[index].session_key,user_logged[index].HMAC_key);
    DEBUG_PRINT(("Operation received %s",operation.c_str()));

    if(difftime(time(0), user_logged[index].session_key_generation_ts)>TTL){ // session time to live
        operation="EXPIRE";
    }
    return operation;
}

string Server::perform_operation(string buffer,int sd,int index){
    if(buffer.empty())
        return "";
    if(buffer.compare("EXPIRE")==0) // if the session is expired no operation is performed
        return buffer;
    istringstream iss(buffer);
    vector<string> tokens;
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    if(tokens.size()<0){
        cerr<<"No operation received\n";
        return "ERR";
    }
    int counter_operation = stoi(tokens[tokens.size()-1]); 
    DEBUG_PRINT(("Counter operation %d",counter_operation));
    DEBUG_PRINT(("Index %d",index));
    if(counter_operation<=user_logged[index].operation_counter_client){ // check against a possible replay attack
        DEBUG_PRINT(("Replay attack"));
        return "";
    }
    user_logged[index].operation_counter_client++;
    if(tokens[0].compare("BAL")==0){ // balance operation
        string balance=read_balance(index);
        return "BALRES "+balance;
    }
    if(tokens[0].compare("TNS")==0){ // transfer operation
        switch(transfer(tokens[1],tokens[2],stoi(tokens[3]))){
            case 0:
                return "INS"; // insufficient credit
            case 1:
                return "OK";
            case 2:
                return "NOE";
            default:
                return "ERR";
        }
    }
    if(tokens[0].compare("HST")==0){ // history of transfers operation
        string historyPath = getPath(user_logged[index].username) + "/history.txt.enc";
        EVP_PKEY * privkey = readPrivateKey(SERVERPRIVATEKEYPATH, "server");
        string historyBuffer = decryptFile(privkey, historyPath);
        EVP_PKEY_free(privkey);
        vector<string> decrypted_history = splitStringByNewline(historyBuffer);
        vector<string> last_movements = getLastElements(decrypted_history,NUMBER_OF_TRANSFER);
        string returnS = joinStringsByNewline(last_movements);
        return returnS;
    }
    if(tokens[0].compare("OUT")==0){ // logout operation
        user_logged[index].logged=false;
        return "OUT";
    }
    return "ERR"; // not recognized operation
}

/* respondToClient receives the operation response, encrypts it and return the ciphertext buffer */
unsigned char * Server::respondToClient(string operation,int sd,int index,int &byte_tosend){
    if(operation.empty())
        return nullptr;
    if(operation.compare("OUT")==0){
        operation="OK";
    }
    DEBUG_PRINT(("Operation result: %s",operation.c_str()));
    unsigned char* IV = nullptr;
    unsigned char* to_hashed = nullptr;
    unsigned char* MAC = nullptr;
    unsigned char* to_enc = nullptr;
    int msg_len = 0;
    int enc_len = 0;
    unsigned char * cptxt = createCiphertext(operation,user_logged[index].id,user_logged[index].session_key,
                                            &IV,&to_hashed,&MAC,user_logged[index].HMAC_key,&to_enc,&msg_len, &enc_len);
    
    if(IV!=nullptr)
        securefree(IV, IVLEN);
    if(to_hashed!=nullptr)
        securefree(to_hashed, IVLEN+enc_len+1);
    if(MAC!=nullptr)
        securefree(MAC, SHA256LEN);
    if(to_enc != nullptr)
        securefree(to_enc, operation.length()+1);
    if(cptxt == nullptr){
        printf("Error in generating the message for answer\n");
    }
    byte_tosend=msg_len;
    if(!user_logged[index].logged || operation.compare("EXPIRE")==0){
        logout(index);
    }
    return cptxt;
}
string Server::read_balance(int index){
    string filepath = getPath(user_logged[index].username)+"/balance.txt.enc";
    return balance(filepath);
}

string Server::balance(string filepath){
    DEBUG_PRINT(("File path %s", filepath.c_str()));

    EVP_PKEY * privkey = readPrivateKey(SERVERPRIVATEKEYPATH, "server");
    string balance_string = decryptFile(privkey, filepath);
    EVP_PKEY_free(privkey);
    
    if(balance_string.compare("")==0){
        cerr<<"Could not decrypt file\n";
        return "";
    }
    
    DEBUG_PRINT(("Balance %s",balance_string.c_str()));
    
    return balance_string;
}
int Server::transfer(string username,string receiver,int amount){
    if(username.compare(receiver)==0){ // check if user is trying to send money to him/herself
        return -1;
    }
    string idAndBalanceSender = balance(getPath(username)+"/balance.txt.enc");
    string idAndBalanceReceiver = balance(getPath(receiver)+"/balance.txt.enc");
    if(idAndBalanceReceiver.empty() || idAndBalanceSender.empty()){
        return 2;
    }
    istringstream iss(idAndBalanceSender);
    string accountIdSender, balanceSender;
    iss >> accountIdSender >> balanceSender;
    istringstream iss2(idAndBalanceReceiver);
    string accountIdReceiver, balanceReceiver;
    iss2 >> accountIdReceiver >> balanceReceiver;

    int current_balance=stoi(balanceSender);
    int balanceRecv = stoi(balanceReceiver);
    if (current_balance<0 || balanceRecv<0)
        return -1;
    if(current_balance<amount)
        return 0;
    
    current_balance-=amount;
    DEBUG_PRINT(("Receiver balance before update %d",balanceRecv));
    balanceRecv+=amount;
    DEBUG_PRINT(("Receiver balance after update %d",balanceRecv));
    string pathSender=getPath(username);
    string pathReceiver = getPath(receiver);
    string historypathSender = pathSender+"/history.txt.enc";
    EVP_PKEY * privkey = readPrivateKey(SERVERPRIVATEKEYPATH, "server");
    string senderHistory = decryptFile(privkey,historypathSender);
    EVP_PKEY_free(privkey);
    time_t timetoday;
    time (&timetoday);
    string writebuff;
    writebuff=receiver+"\t"+to_string(amount)+"\t"+asctime(localtime(&timetoday)); // creates the new line for the movement
    senderHistory+=writebuff;
    
    // update all the files 
    if(!encryptFile(publicKey,senderHistory, historypathSender)){ 
        cerr<<"Error in overwriting the history file\n";
        return -1;
    }

    if(!encryptFile(publicKey,accountIdSender+" "+to_string(current_balance), pathSender+"/balance.txt.enc")){
        cerr<<"Error in overwriting the sender balance file\n";
        return -1;
    }
    if(!encryptFile(publicKey,accountIdReceiver+" "+to_string(balanceRecv), pathReceiver+"/balance.txt.enc")){
        cerr<<"Error in overwriting the receiver balance file\n";
        return -1;
    }
    
    return 1;
}

// return the index of the user in LoggedUser structure
int Server::indexOfUser(string username){
    for(long unsigned int i=0; i<user_logged.size();++i){ 
        if(user_logged[i].username.compare(username)==0)
            return i;
    }
    return -1;
}
// return the index of the user in LoggedUser structure
int Server::indexOfUser(unsigned char id){
    for(long unsigned int i=0; i<user_logged.size();++i){ 
        if(user_logged[i].id==(int)id)
            return i;
    }
    return -1;
}


void Server::logout(int index){
        // delete the session/MAC keys and remove the structure in the vector
        securefree(user_logged[index].session_key,AES128LEN);
        securefree(user_logged[index].HMAC_key,SHA256LEN);
        user_logged.erase(user_logged.begin()+index);
        DEBUG_PRINT(("Elements on vector %lu", user_logged.size()));
}

void Server::reportError(int sd, int index){
    if(index<0){ // if the user is not logged report error on plaintext
        send(sd, "ERR", 4, 0);
        return;
    }
    string cmd = "ERR";
    DEBUG_PRINT(("cmd: %s\n", cmd.c_str()));
    unsigned char* IV = nullptr;
    unsigned char* to_hashed = nullptr;
    unsigned char* MAC = nullptr;
    unsigned char* to_enc = nullptr;
    int msg_len = 0;
    int enc_len = 0;
    unsigned char * msg = createCiphertext(cmd, user_logged[index].id, user_logged[index].session_key,
                        &IV, &to_hashed, &MAC,user_logged[index].HMAC_key, &to_enc, &msg_len, &enc_len);
    if(IV!=nullptr)
        securefree(IV, IVLEN);
    if(to_hashed!=nullptr)
        securefree(to_hashed, IVLEN+enc_len+1);
    if(MAC!=nullptr)
        securefree(MAC, SHA256LEN);
    if(to_enc != nullptr)
        securefree(to_enc, cmd.length()+1);
    if(msg == nullptr){
        printf("Error in generating the error message\n");
    }
    
    send(sd,msg,msg_len,0);
    securefree(msg,msg_len);
}
void Server::reportError(int sd, unsigned char * session_key,unsigned char * mac_key){
    string cmd = "ERR";
    DEBUG_PRINT(("cmd: %s\n", cmd.c_str()));
    unsigned char* IV = nullptr;
    unsigned char* to_hashed = nullptr;
    unsigned char* MAC = nullptr;
    unsigned char* to_enc = nullptr;
    int msg_len = 0;
    int enc_len = 0;
    unsigned char * msg = createCiphertext(cmd,0, session_key,
                        &IV, &to_hashed, &MAC,mac_key, &to_enc, &msg_len, &enc_len);
    if(IV!=nullptr)
        securefree(IV, IVLEN);
    if(to_hashed!=nullptr)
        securefree(to_hashed, IVLEN+enc_len+1);
    if(MAC!=nullptr)
        securefree(MAC, SHA256LEN);
    if(to_enc != nullptr)
        securefree(to_enc, cmd.length()+1);
    if(msg == nullptr){
        printf("Error in generating the error message\n");
    }
    send(sd,msg,msg_len,0);
    securefree(msg,msg_len);
}
Server::~Server(){
    for(long unsigned int i=0; i<user_logged.size();i++){ // destroy all session keys
        securefree(user_logged[i].session_key,AES128LEN);
        securefree(user_logged[i].HMAC_key,SHA256LEN);
    }
    EVP_PKEY_free(publicKey);
}