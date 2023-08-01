all: client server

# make rule per il client client: client.o

client: client.o cryptoClient.o funcClient.o cryptoUtility.o util.o
	g++ -Wall -std=c++17  -o client.exe client.o cryptoClient.o funcClient.o cryptoUtility.o util.o -lssl -lcrypto

# make rule per il server
server: server.o cryptoServer.o funcServer.o util.o cryptoUtility.o
	g++ -Wall -std=c++17 -o server.exe server.o cryptoServer.o funcServer.o util.o cryptoUtility.o -lssl -lcrypto 

enc: cryptoUtility.o util.o enc.o
	g++ -Wall -std=c++17  -o enc.exe enc.o cryptoUtility.o util.o -lssl -lcrypto

enc.o: encryptFile.cpp
	g++ -c  -Wall -std=c++17 encryptFile.cpp -o enc.o
client.o: client.cpp
	g++ -c  -Wall -std=c++17 client.cpp -o client.o
	
cryptoClient.o: cryptoClient.cpp
	g++ -c  -Wall -std=c++17 cryptoClient.cpp -o cryptoClient.o

funcClient.o: funcClient.cpp
	g++ -c  -Wall -std=c++17 funcClient.cpp -o funcClient.o

server.o: Server.cpp
	g++ -c  -Wall -std=c++17 Server.cpp -o server.o

cryptoServer.o: cryptoServer.cpp
	g++ -c -Wall -std=c++17 cryptoServer.cpp -o cryptoServer.o

funcServer.o: funcServer.cpp
	g++ -c  -Wall -std=c++17 funcServer.cpp -o funcServer.o

util.o: util.cpp
	g++ -c -Wall -std=c++17 util.cpp -o util.o

cryptoUtility.o: cryptoUtility.cpp
	g++ -c  -Wall -std=c++17 cryptoUtility.cpp -o cryptoUtility.o

clean:
	rm client.o server.o cryptoClient.o funcClient.o cryptoServer.o funcServer.o util.o cryptoUtility.o enc.o enc.exe client.exe server.exe

	