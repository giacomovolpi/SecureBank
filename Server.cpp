#include "Server.h"

int main(int argc, char *argv[]) {
    if(argc<2){
        cerr<<"Error: missing server port!\n";
        exit(EXIT_FAILURE);
    }
    if(atoi(argv[1])<1024){
        cerr<<"Error: the port inserted is reserved!\n";
        exit(EXIT_FAILURE);
    }
    Server server(atoi(argv[1]));
    server.run();
    return 0;
}