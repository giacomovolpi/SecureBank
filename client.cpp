#include"client.h"

struct file_descriptor_set{
    fd_set master;
    fd_set read_fds;
    int fdmax;
} fds;

void checkInput(int client_port, int server_port){
    
        int ret, newfd, listener, i;
        socklen_t addrlen;
        struct sockaddr_in my_addr, server_addr;
        char buffer[BUFFER_LEN];
        pid_t pid;


        //viene creato il socket, sttatto l'indirizzo del device 
        //e viene eseguita la bind
        listener = socket(AF_INET, SOCK_STREAM, 0);
        Client* client = new Client(client_port, server_port);
        if(!client->isPubServerKeyLoaded()){
            cerr<<"Could not load server public key"<<endl;
            exit(0);
        }
        my_addr = client->getClient();
        ret = ::bind(listener, (struct sockaddr *)&my_addr, sizeof(my_addr));
        if (ret < 0) {
            perror("Bind listener non riuscita\n");
            exit(0);
        }

        //se la bind viene eseguita con successo, viene creata la coda di ingresso,
        //vengono resettati i file descriptor e successivamente inseriti i fd per
        //il listener e STDIN
        listen(listener, 10);
        DEBUG_PRINT(("in ascolto sulla porta %d", client_port));

        FD_ZERO(&(fds.master));
        FD_ZERO(&(fds.read_fds));

        FD_SET(STDIN, &(fds.master));
        FD_SET(listener, &(fds.master));
        fds.fdmax = listener;

        while (1) {
            //viene effettuata la pulizia del buffer e viene chiamata la select
            memset(buffer, '\0', BUFFER_LEN);
            fds.read_fds = fds.master;
            i = select(fds.fdmax + 1, &(fds.read_fds), NULL, NULL, NULL);
            if (i < 0) {
                perror("select: ");
                exit(1);
            }
            if (i > 0) {
                
                //scorro tutti i fds presenti
                for (i = 0; i <= fds.fdmax+1; i++) {
                    if (FD_ISSET(i, &(fds.read_fds))) {
                        //DEBUG_PRINT(("%d is set\n", i));

                        //se i==listener vuol dire che è arrivata una richiesta 
                        //di connessione TCP e, dopo essere stata accettata
                        //viene aggiunto il relativo fd al fds
                        if (i == listener) { // 
                            addrlen = sizeof(server_addr);
                            newfd = accept(listener, (struct sockaddr *)&server_addr, &addrlen);
                            FD_SET(newfd, & fds.master);
                            if (newfd > fds.fdmax)
                                fds.fdmax = newfd;
                        }

                        //altrimenti se i == STDIN vuol dire che è stato rilevato un
                        //input da tastiera per cui passo il buffer di ingresso
                        //alla funzione che si occupa di gestire lo STDIN
                        else if (i == STDIN) { 
                            if (read(STDIN, buffer, 1024)){
                                DEBUG_PRINT(("STDIN"));
                                client->checkLocalInput(buffer);
                            }
                                
                        }

                        //altrimenti vuol dire che è stato rilevato un messaggio TCP
                        //per cui viene creato un figlio per gestire la connessione
                        else { 
                            pid = fork();
                            if (pid == -1) {
                                perror("Errore durante la fork: ");
                                return;
                            }
                            //figlio
                            if (pid == 0) {
                                DEBUG_PRINT(("TCP"));
                                close(listener);
                                client->checkTCPInput(i);
                                exit(0);
                            }
                            close(i);
                            FD_CLR(i, &(fds.master));
                        }
                
                    }
                }
            }
        }

        close(listener);
    
}


int main(int argc, char **argv) {
    if(argc<2){
        cerr<<"Missing ports\n";
        exit(-1);
    }
    if(argc<3){
        cerr<<"Missing server port\n";
        exit(-1);
    }
    if(atoi(argv[1])<1024 || atoi(argv[2])<1024){
        cerr<<"A port you input is reserved, try something else\n";
        exit(-1);
    }
    
    int client_port = atoi(argv[1]);
    int server_port = atoi(argv[2]);
    cout<<"Welcome! enter a command, remember to login before doing anything else:\n";
    cout<<"login: login into SecureBank\n";
    cout<<"logout: logout from SecureBank\n";
    cout<<"balance: request your balance to SecureBank\n";
    cout<<"transfer:transfer an amount of money to someone else through SecureBank\n";
    cout<<"history: look at the history of you transfer kept by SecureBank\n";
    cout<<"help: see the list of avaible commands\n";
    checkInput(client_port, server_port);
    return 0;
}