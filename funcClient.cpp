#include"client.h"

//  Constructor function
Client::Client(const uint16_t clientP, const uint16_t serverP){
    // Clear the memory of client_address and server_address structures
    memset(&client_address, 0, sizeof(client_address));
    memset(&server_address, 0, sizeof(server_address));

    // Set client address configuration
    client_address.sin_family=AF_INET;          // TCP/IP
    client_address.sin_addr.s_addr=INADDR_ANY;  // client addr--permit all connection
    client_address.sin_port=htons(clientP);     // client port
    
    // Set server address configuration
    server_address.sin_family=AF_INET;
    server_address.sin_addr.s_addr=INADDR_ANY;
    server_address.sin_port=htons(serverP);
    server_port=serverP;

    // Print the values for debugging purposes
    DEBUG_PRINT(("listening on %d, communicating with server on %d", client_address.sin_port, server_address.sin_port));
    // get the public key from memory
    publicKeyServer=readPublicKey("./server/server_rsa_pubkey.pem");
}

// Utility function returns true if the public key has been loaded correctly
bool Client::isPubServerKeyLoaded(){
    if(!publicKeyServer)
        return false;
    return true;
}

// Create a connection through a socket descriptor, returns it after 
int Client::createConnection(){
    int sd;
    sd = socket(AF_INET, SOCK_STREAM, 0);

    // Convert the server IP address from string to binary form
    inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);

    // Establish a connection with the server
    if (connect(sd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Error in connection phase\n");
        return -1;
    }

    // Return the socket descriptor
    return sd;
}

// Sends a message of unsigned char* of size len, returns the socket descriptor
int Client::sendmsg(unsigned char * send_content, size_t len){
    // Create a socket and establish a connection
    int sd = createConnection();
    if(sd<0){
        perror("Error in creation of the socket");
        return sd;
    }

    //send a message to server
    send(sd, send_content, len, 0);
    return sd;
}

/*
    LEGACY FUNCTION NOT USED AS OF NOW
    Returns:
    -1 for server/application failures
    0 for operation unable to complete due to application rule 
    1 operation successful
*/
int Client::sendmsg (char * send_content){
    // Create a socket and establish a connection
    int sd = createConnection();
    if(sd<0){
        perror("Error in creation of the socket");
        return sd;
    }

    // Create a send buffer and copy the send_content into it
    char send_buf[strlen(send_content)+1];
    memset(send_buf, '\0', sizeof(send_buf));
    strcpy(send_buf, send_content);

    //send a message to server
    send(sd, send_buf, strlen(send_buf), 0);
    return sd;
}

// check the TCP input, decrypts the incoming message and perform the necessary operation
// returns 1 if the operation is completed successfully, 0 if not but without server/decryption/encryption errors
// -1 if there are errors or the session is expired
int Client::checkTCPInput(int i){
    // Read input from socket descriptor 'i' into the buffer
    unsigned char ubuf[BUFFER_LEN];
    int received = read(i, ubuf, BUFFER_LEN);
    
    // Decrypt the incoming message
    string cmd = decryptCipherText(ubuf, received-IVLEN-SHA256LEN-1, this->sessionKey,this->HMACKey);
    DEBUG_PRINT(("cmd received %s", cmd.c_str()));

    // use a stringstream to iterate through the received command
    istringstream iss(cmd);
    vector<string> tokens;
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    if(tokens.size()<0){
        cerr<<"No operation received\n";
        return -1;
    }

    // If the client is logged in checks for replay attack with the help of a counter
    if(logged_in){
        int counter_operation = stoi(tokens[tokens.size()-1]);
        if(counter_operation<=getCounterServer()){
            DEBUG_PRINT(("Replay attack"));
            return -1;
        }
        incrementCounterServer();
    }

    // Login successful
    if(!strcmp("OKLOG", tokens[0].c_str())){
        setId(stoi(tokens[1]));
        printf("Login completed correctly. Welcome %s\n", usr_name.c_str());
        fflush(stdout);
        return 1;
    }
    
    // Logout successful
    else if(!strcmp("OUT",  tokens[0].c_str())){
        return 1;
    }

    // Login failure
    else if(!strcmp("NOTLOG",  tokens[0].c_str())){
        printf("Login failed, wrong username and password\n");
        return 0;
    }

    // General operation successful (testing purposes)
    else if(!strcmp("OK", tokens[0].c_str())){
        DEBUG_PRINT(("Operation successful\n"));
        return 1;
    }

    // Insufficent balance for the operation
    else if(!strcmp("INS", tokens[0].c_str())){
        DEBUG_PRINT(("INS"));
        cout<<"Error! Insufficient balance"<<endl;
        return 0;
    }

    else if(!strcmp("NOE", tokens[0].c_str())){
        DEBUG_PRINT(("NOE"));
        cout<<"Error! The specified user does not exist"<<endl;
        return 0;
    }

    // Server response for the balance operation
    else if(!strcmp("BALRES", tokens[0].c_str())){
        cout<<"Account ID: "<<tokens[1]<<" Balance: "<<tokens[2]<<endl;
        return 1;
    }

    // Session expired signal
    else if(!strcmp("EXPIRED", tokens[0].c_str())){
        cout<<"Session expired. Please login again!"<<endl;
        securefree(this->sessionKey, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
        securefree(this->HMACKey, SHA256LEN);
        logged_in=false;
        return -1;
    }

    // General error response
    else if(!strcmp("ERR", tokens[0].c_str())){
        printf("Error on completing the operation, try again\n");
        fflush(stdout);
        return -1;
    }

    // Server response not classified
    else{
        printf("MSG received corrupted or tampered with if the problem persist close the connection\n");
        return -1;
    }
}

// Sends the transfer request to the server, returns true if the operation is successful
bool Client::transfer(string cmd){
    // Prepare the variables to handle memory
    unsigned char* IV = nullptr;
    unsigned char* to_hashed = nullptr;
    unsigned char* MAC = nullptr;
    unsigned char* to_enc = nullptr;
    int msg_len = 0;
    int enc_len = 0;
    unsigned char * msg = createCiphertext(cmd, getId(), this->sessionKey,
                        &IV, &to_hashed, &MAC, this->HMACKey,&to_enc, &msg_len, &enc_len);
    
    // Free the memory
    if(IV!=nullptr)
        securefree(IV, IVLEN);
    if(to_hashed!=nullptr)
        securefree(to_hashed, IVLEN+enc_len+1);
    if(MAC!=nullptr)
        securefree(MAC, SHA256LEN);
    if(to_enc != nullptr)
        securefree(to_enc, cmd.length()+1);
    if(msg == nullptr){
        printf("Error in generating the message for balance\n");
    }

    int i = sendmsg(msg, msg_len); // Send the message and get the socket descriptor
    securefree(msg,msg_len);
    
    // Check the response received from the server
    bool check = false;
    if(checkTCPInput(i)==1){
        check=true;
    }
    close(i);

    // Return if the transfer completed successfully
    return check;
}

// Perform the login operation, the function is divided in three subfunction
// Send first login message, listen for the server response, send the hashcheck
void Client::login(){
    //char username[USER_LEN+1], password[PASSWORD_LEN+1];
    string username, password;
    // Prompt the user to enter the username and read from terminal
    cin.clear();
    cout<<"insert username max 30 char"<<endl;
    do{getline(cin, username);}
    while(username.empty() || username.size()>USER_LEN);
    setUsername(username);
    // Prompt the user to enter the password and read from terminal
    cout<<"insert password max 30 char"<<endl;
    getline(cin, password);

    // Prompt the user to enter the password for the private key
    cout<<"insert password for digital sign"<<endl;
    char signPassword[PASSWORD_LEN];
    cin.getline(signPassword, PASSWORD_LEN+1);
    string filepath = "./server/users/" + usr_name + "/" + usr_name + "_rsa_privkey.pem";
    EVP_PKEY * privkey = readPrivateKey(filepath,signPassword);
    if(!privkey){
        cerr<<"Incorrect login credentials"<<endl;
        return;
    }
    // Prepare the command and variable to manege memory
    //string cmd = "LOG "+string(username)+" "+string(password);
    unsigned char* nonce = nullptr;
    unsigned char* dh_uchar = nullptr;
    EVP_PKEY * dh_pub = nullptr;
    int sd = sendLoginMsg(username, &nonce, &dh_uchar, &dh_pub);

    if(sd<0){
        printf("error in the first message\n");
        return;
    }
    

    // Prepare the variable for memory management for the server answer
    unsigned char* nonce_server = nullptr;
    unsigned char* dh_params_server = nullptr;
    unsigned char * sharedSecret = nullptr;
    int ret = receiveServerLoginAnswer(sd, &nonce_server, &dh_params_server, &sharedSecret, 
                                                &dh_pub, dh_uchar, nonce);
    
    if(ret!=0){
        securefree(dh_uchar, DHPARLEN);
        securefree(nonce, NONCELEN);
        EVP_PKEY_free(privkey);
        EVP_PKEY_free(dh_pub);
        send(sd, "ERR", COMMAND_SIZE, 0);
        close(sd);
        return;
        
    }
    if(sharedSecret!=nullptr)
        securefree(sharedSecret, AES128LEN+SHA256LEN);
    
    // Prepare variable for memory management in hashcheck response
    ret = sendHashCheck(sd, password, privkey, dh_uchar, nonce, dh_params_server, nonce_server);
    EVP_PKEY_free(privkey);

    // Free remaining memory
    securefree(dh_uchar, DHPARLEN);
    securefree(nonce, NONCELEN);
    securefree(dh_params_server, DHPARLEN);
    securefree(nonce_server, NONCELEN);
    if(ret<0){
        printf("error in the hash-check phase\n");
        send(sd, "ERR", COMMAND_SIZE, 0);
        return;
    }

    // Check the final answer
    if(checkTCPInput(sd)==1){
        logged_in=true;
        DEBUG_PRINT(("Id number: %d\n", getId()));
    }
    else{
        cout<<"Error username or password incorrect\n";
        securefree(this->sessionKey, AES128LEN);
        securefree(this->HMACKey, SHA256LEN);
    }

    EVP_PKEY_free(dh_pub);
}

// Perform the logout operation
void Client::logout(){

    // Prepare the command and variable to manege memory
    string cmd = "OUT " + std::string(usr_name) + " " + to_string(incrementAndReturnCounter());
    unsigned char* IV = nullptr;
    unsigned char* to_hashed = nullptr;
    unsigned char* MAC = nullptr;
    unsigned char* to_enc = nullptr;
    int msg_len = 0;
    int enc_len = 0;
    unsigned char * msg = createCiphertext(cmd, getId(), this->sessionKey,
                        &IV, &to_hashed, &MAC, this->HMACKey,&to_enc, &msg_len, &enc_len);
    
    // Free memory
    if(IV!=nullptr)
        securefree(IV, IVLEN);
    if(to_hashed!=nullptr)
        securefree(to_hashed, IVLEN+enc_len+1);
    if(MAC!=nullptr)
        securefree(MAC, SHA256LEN);
    if(to_enc != nullptr)
        securefree(to_enc, cmd.length()+1);
    if(msg == nullptr){
        printf("Error in generating the message for balance\n");
    }

    int i = sendmsg(msg, msg_len); // Send the message and get the socket descriptor
    securefree(msg,msg_len);
    checkTCPInput(i);
    
    // Set the logged_in flag to false
    logged_in = false;
}

// Perform the balance operation
void Client::balance(){
    
    // Prepare the command and variable to manege memory
    string cmd = "BAL " + std::string(usr_name) + " " + to_string(incrementAndReturnCounter());
    DEBUG_PRINT(("cmd: %s\n", cmd.c_str()));
    unsigned char* IV = nullptr;
    unsigned char* to_hashed = nullptr;
    unsigned char* MAC = nullptr;
    unsigned char* to_enc = nullptr;
    int msg_len = 0;
    int enc_len = 0;
    unsigned char * msg = createCiphertext(cmd, getId(), this->sessionKey,
                        &IV, &to_hashed, &MAC, this->HMACKey,&to_enc, &msg_len, &enc_len);
    
    // Free memory
    if(IV!=nullptr)
        securefree(IV, IVLEN);
    if(to_hashed!=nullptr)
        securefree(to_hashed, IVLEN+enc_len+1);
    if(MAC!=nullptr)
        securefree(MAC, SHA256LEN);
    if(to_enc != nullptr)
        securefree(to_enc, cmd.length()+1);
    if(msg == nullptr){
        printf("Error in generating the message for balance\n");
    }

    int i = sendmsg(msg, msg_len); // Send the message and get the socket descriptor
    securefree(msg,msg_len);
    checkTCPInput(i); // Check the response of the server
}

// Perform the preparation to the transfer operation, mainly check local inputs
void Client::preTransfer(){
    // Create the array to store the destination user and the quantity to send
    string user_dest;
    int quantity = 0;

    cout<<"insert username max 30 char"<<endl;
    cin>>user_dest; // Get the destination user from input line
    if(user_dest.size() > USER_LEN){
        printf("insert a valid destination user, max 30 chars\n");
        return;
    }
    // If the destination user is empty, return without proceeding
    if (user_dest.empty()) {
        std::cout << "Insert a destination user to send the money" << std::endl;
        return;
    }

    cout<<"insert money to transfer, max 9 digits"<<endl;
    while (!(std::cin >> quantity)) {
        cout << "Invalid input. Please enter a valid number: " << std::endl;
        cin.clear(); // Clear the error state
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Ignore remaining characters in the buffer
    }
    

    // If the quantity is a not valid number, return without proceeding
    if(quantity>999999999 || quantity<=0){
        printf("insert a correct quantity to transfer\n");
        return;
    }

    // Construct the transfer message 
    string msg = "TNS " +std::string(usr_name) + " " + std::string(user_dest) + " " + to_string(quantity) + " " + to_string(incrementAndReturnCounter());
    
    // Send the message to the server return true if executed correctly
    if(transfer(msg)){
        printf("Transfer completed successfully, send %d to %s\n", quantity, user_dest.c_str());
    }
    else{
        printf("you tried to send %d to %s\n", quantity, user_dest.c_str());
    }

}

// Perform the history request to the server and wait for its response
void Client::history(){
    // Prepare the variables to handle memory
    string cmd = "HST " + std::string(usr_name) + " " + to_string(incrementAndReturnCounter());
    unsigned char* IV = nullptr;
    unsigned char* to_hashed = nullptr;
    unsigned char* MAC = nullptr;
    unsigned char* to_enc = nullptr;
    int msg_len = 0;
    int enc_len = 0;
    unsigned char * msg = createCiphertext(cmd, getId(), this->sessionKey,
                        &IV, &to_hashed, &MAC, this->HMACKey,&to_enc, &msg_len, &enc_len);
    
    // Free memory
    if(IV!=nullptr)
        securefree(IV, IVLEN);
    if(to_hashed!=nullptr)
        securefree(to_hashed, IVLEN+enc_len+1);
    if(MAC!=nullptr)
        securefree(MAC, SHA256LEN);
    if(to_enc != nullptr)
        securefree(to_enc, cmd.length()+1);
    if(msg == nullptr){
        printf("Error in generating the message for balance\n");
    }

    int sd = sendmsg(msg, msg_len); // Send the message and get the socket descriptor
    securefree(msg,msg_len);

    unsigned char ubuf[BUFFER_LEN];
    memset(ubuf, 0, sizeof(ubuf)); // Clearing the buffer before receiving data
    int bytesRead = recv(sd, ubuf, sizeof(ubuf), 0); // Receive the msg from the server and store it into buffer
    
    // Decipher the incoming cipherText
    string history = decryptCipherText(ubuf, bytesRead-IVLEN-SHA256LEN-1, this->sessionKey,this->HMACKey);
    DEBUG_PRINT(("History received %s",history.c_str()));
    // Get the last word from the string containing the operation counter 
    int n = history.length();
    int i;
    for (i = n - 1; i >= 0; i--) {
        if (history[i] == ' ') {
            break;
        }
    }

    // Check for possible replay attacks
    int counter_operation = stoi(history.substr(i + 1));
    DEBUG_PRINT(("counter_op %d",counter_operation));
    DEBUG_PRINT(("Counter server %d", getCounterServer()));
    if(counter_operation<=getCounterServer()){
        DEBUG_PRINT(("Replay attack")); 
        return;
    }
    incrementCounterServer();
    
    // Remove the counter from the string, then print it
    history = history.substr(0, i);
    cout<<"History of transfer:\n"<<history<<endl;
    close(i); // Close the socket
    return;
}

/*
    List of commands:
    login --> initiate the login procedure with the key exchange
    logout --> initiate the logout procedure with the distruction of the session key
    balance --> check the balance of the account and prints it
    transfer --> transfer an amaount of money x to a user
    history --> request the history of transfer to the server and prints it
    exit --> close the process, also calls the logout procedure
    help --> prints the avaible commands
*/

int Client::checkLocalInput(char* buffer){
    if (buffer == nullptr || strlen(buffer) == 0) {
        cerr<<"invalid input\n";
        return 0;
    }
    // Check if the user is logged in
    if(!logged_in){
        if(!strcmp("login\n", buffer)){
            DEBUG_PRINT(("LOGIN"));
            login();
        }
        else if(!strcmp("help\n", buffer)){
            DEBUG_PRINT(("HELP"));
            cout<<"Here's the list of available commands: \n";
            cout<<"login: login into SecureBank\n";
            cout<<"logout: logout from SecureBank\n";
            cout<<"balance: request your balance to SecureBank\n";
            cout<<"transfer:transfer an amount of money to someone else through SecureBank\n";
            cout<<"history: look at the history of you transfer kept by SecureBank\n";
            cout<<"help: see the list of available commands\n";
        }
        else if(!strcmp("exit\n", buffer)){
            cout<<"Goodbye\n";
            exit(0);
        }
        else{
            printf("Command not recognised, remember to login before issuing other commands\n");
            fflush(stdout);
        }
    }
    else{
        if(!strcmp("balance\n", buffer)){
            DEBUG_PRINT(("BALANCE"));
            balance();
        }

        else if(!strcmp("transfer\n", buffer)){
            DEBUG_PRINT(("TRANSFER"));
            preTransfer();
        }

        else if(!strcmp("history\n", buffer)){
            DEBUG_PRINT(("history"));
            history();
        }
        else if(!strcmp("help\n", buffer)){
            DEBUG_PRINT(("HELP"));
            cout<<"Here's the list of available commands: \n";
            cout<<"login: login into SecureBank\n";
            cout<<"logout: logout from SecureBank\n";
            cout<<"balance: request your balance to SecureBank\n";
            cout<<"transfer:transfer an amount of money to someone else through SecureBank\n";
            cout<<"history: look at the history of you transfer kept by SecureBank\n";
            cout<<"help: see the list of available commands\n";
        }
        else if(!strcmp("exit\n", buffer)){
            DEBUG_PRINT(("EXIT"));
            logout();
            printf("Goodbye\n");
            securefree(this->sessionKey, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
            securefree(this->HMACKey, SHA256LEN);
            exit(0);
        }
        else if(!strcmp("logout\n", buffer)){
            logout();
            printf("Goodbye\n");
            securefree(this->sessionKey, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
            securefree(this->HMACKey, SHA256LEN);
            this->counter=0;
            this->counter_server=0;
            return 0;
        }
        else{
            printf("Command not recognised\n");
            fflush(stdout);
        }
    }
    return 0;
    
}


