#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <list>
#include <string>
#include <openssl/evp.h>
#include <openssl/sha.h>

// // Need to link with Ws2_32.lib
// #pragma comment (lib, "Ws2_32.lib")
// // #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

using namespace std;

class Client {
    public:
        SOCKET ClientSocket;
        bool handshake;
        Client(SOCKET ClientSocket) {
            this->ClientSocket = ClientSocket; 
            handshake = false;
        }

        bool checkHandshake(string buffer) {
            if (handshake == true) return true;
            string str;
            string key;
            string key2 = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            int pos = 0;
            int pos2 = 0;
            char encodedData[100];

            while((pos2 = buffer.find("\r\n", pos)) != string::npos) {
                str = buffer.substr(pos, pos2 - pos);
                printf("#%s\n", str.c_str());
                pos = pos2 + 2;
                if (str.find("Sec-WebSocket-Key") != string::npos) {
                    key = str.substr(str.find(":") + 2, string::npos);
                    printf("%s\n", key.c_str());
                    key.append(key2);
                    unsigned char hash[SHA_DIGEST_LENGTH]; 

                    EVP_Q_digest(NULL, "SHA1", NULL, (unsigned char*)key.c_str(), strlen(key.c_str()), hash, NULL);
                    EVP_EncodeBlock((unsigned char *)encodedData, hash, SHA_DIGEST_LENGTH);
                    printf(encodedData);

                    string r1 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "; 
                    string r2 = "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                    string rr = r1;
                    rr.append(encodedData);
                    rr.append(r2);

                    printf("%s", rr.c_str());

                    // Echo the buffer back to the sender
                    int iSendResult = send(ClientSocket, rr.c_str(), (int)strlen(rr.c_str()), 0 );
                    if (iSendResult == SOCKET_ERROR) {
                        printf("send failed with error: %d\n", WSAGetLastError());
                        closesocket(ClientSocket);
                        return false;
                    }    
                    handshake = true;

                    break;
                }
            } 
            return true; 
        }
};

int __cdecl main(void) 
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    list<Client> ClientList;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    FD_SET ReadSet;

    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    const TIMEVAL timeVal = {1, 0};
    
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    printf("listening\n");

    while (true) {
        FD_ZERO(&ReadSet);
        FD_SET(ListenSocket, &ReadSet);
        list<Client>::iterator it;
        for (it = ClientList.begin(); it != ClientList.end(); ++it) {
            FD_SET(it->ClientSocket, &ReadSet);
        }

        select(0, &ReadSet, NULL, NULL, &timeVal);

        for (it = ClientList.begin(); it != ClientList.end(); ++it) {
            printf("%x ", *it);
            if (FD_ISSET(it->ClientSocket, &ReadSet)) {
                iResult = recv(it->ClientSocket, recvbuf, recvbuflen, 0);
                printf("result=%d ", iResult);
                if (iResult > 0) {
                    recvbuf[iResult] = 0;
                    printf("Bytes received: %d\n%s\n", iResult, recvbuf);
                    if (!it->checkHandshake(recvbuf)) {
                        it = ClientList.erase(it);
                        it--;
                        continue;
                    }
                    for (int i = 0; i < iResult; i++) {
                        printf("%u ", (unsigned char)recvbuf[i]);
                    }
                    printf("\n");            
                }
            }
        }
        printf("\n");

        if (FD_ISSET(ListenSocket, &ReadSet)) {
            // Accept a client socket
            ClientSocket = accept(ListenSocket, NULL, NULL);
            if (ClientSocket == INVALID_SOCKET) {
                printf("accept failed with error: %d\n", WSAGetLastError());
            }
            else {
                Client client(ClientSocket);
                ClientList.push_back(client);
                printf("Connected\n");
            }

            // No longer need server socket
            //closesocket(ListenSocket);

            // Receive until the peer shuts down the connection
            // do {

            //     iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
            //     if (iResult > 0) {
            //         recvbuf[iResult] = 0;
            //         printf("Bytes received: %d\n%s\n", iResult, recvbuf);

            //         strcat(recvbuf, " 123");
            //     // Echo the buffer back to the sender
            //         iSendResult = send( ClientSocket, recvbuf, (int)strlen(recvbuf), 0 );
            //         if (iSendResult == SOCKET_ERROR) {
            //             printf("send failed with error: %d\n", WSAGetLastError());
            //             closesocket(ClientSocket);
            //             WSACleanup();
            //             return 1;
            //         }
            //         printf("Bytes sent: %d\n", iSendResult);
            //     }
            //     else if (iResult == 0)
            //         printf("Connection closing...\n");
            //     else  {
            //         printf("recv failed with error: %d\n", WSAGetLastError());
            //         closesocket(ClientSocket);
            //         WSACleanup();
            //         return 1;
            //     }

            // } while (iResult > 0);
        }
    }

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}