#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <list>
#include <string>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// // Need to link with Ws2_32.lib
// #pragma comment (lib, "Ws2_32.lib")
// // #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "9899"

namespace mask {
    const int
        OPCODE_MASK = 0x0F,
        FIN_MASK = 0x80,
        MASK_MASK = 0x80,
        LENGTH_MASK = 0x7F;
};

using namespace std;

class Client {
    public:
        SOCKET ClientSocket;
        bool handshake;
        Client(SOCKET ClientSocket) {
            this->ClientSocket = ClientSocket; 
            handshake = false;
        }

        bool doHandshake(string buffer) {
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

        string decodeFrame(char frame[], int size, int &opcodeRet) {
            printf("\n");
            for (int i = 0; i < size; i++) {
                printf("%u ", (unsigned char)frame[i]);
            }
            printf("\n");
            unsigned int opcode = (unsigned int)frame[0] & mask::OPCODE_MASK;
            switch (opcode) {
                case 0x01:
                    opcodeRet = 1;
                    return decodeText(frame, size);
                case 0x08:
                    opcodeRet = 8;
                    return "";
                case 0x09:
                    opcodeRet = 9;
                    return decodeText(frame, size);
            }
            return "";
        }

        string decodeText(char frame[], int size) {
            unsigned int length = (unsigned char)frame[1] & mask::LENGTH_MASK;
            if(length < 126) {
                printf("Length(less than 7 bits): %u\n", length);
                string encode;
                for (int i = 6; i < size; i++) {
                    encode.append(1, frame[i]);
                }
                if (((unsigned char)frame[1] & mask::MASK_MASK) == 0x80) {
                    string mask;
                    for (int i = 2; i < 6; i++) {
                        mask.append(1, frame[i]);
                    }
                    unmask(mask, encode);
                }
                return encode;
            }
            else if(length == 126) {
                length = (unsigned char)frame[2] * 256 + (unsigned char)frame[3];
                printf("Length(16 bits): %u\n", length);
                string message;
                for (int i = 8; i < size; i++) {
                    message.append(1, frame[i]);
                }
                if (((unsigned char)frame[1] & mask::MASK_MASK) == 0x80) {
                    string mask;
                    for (int i = 4; i < 8; i++) {
                        mask.append(1, frame[i]);
                    }
                    unmask(mask, message);
                }
                return message;
            }
            else {
                length = 0;
                for (int i = 7; i >= 0; i--) {
                    length += (unsigned char)frame[2 + (7-i)] * pow(256, i);
                }
                printf("Length(64 bits): %u\n", length);
                return "";
            }
        }

        void unmask(string mask, string& encode) {
            string decode;
            for (int i = 0; i < encode.size(); i++) {
                decode.append(1, (unsigned char)encode[i] ^ (unsigned char)mask[i%4]);
            }
            encode = decode;
        }

        string encode(string message, int opcode) {
            string encode;
            unsigned char firstByte;
            if (opcode == 1) {
                firstByte = (unsigned char)0x81;
            }
            else if (opcode == 9) {
                firstByte = (unsigned char)0x8A;
            }
            encode.append(1, firstByte);
            if (message.size() < 126) {
                encode.append(1, (unsigned char)message.size());
                encode += message;
                printf("%s %d\n", encode.c_str(), encode.size());
                return encode;
            }
            else if (message.size() < pow(2, 16)) {
                encode.append(1, (unsigned char)126);
                encode.append(1, (unsigned char)(message.size() / 256));
                encode.append(1, (unsigned char)(message.size() % 256));
                encode.append(message); 
                printf("%u %u\n", encode[2], encode[3]);
                printf("%d\n%s %d\n", message.size(), encode.c_str(), encode.size());
                return encode;
            }
            return "";
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
            if (FD_ISSET(it->ClientSocket, &ReadSet)) {
                string message;
                iResult = recv(it->ClientSocket, recvbuf, recvbuflen, 0);
                printf("result=%d ", iResult);
                if (iResult == 0) {
                    it = ClientList.erase(it);
                    it--;
                    continue;
                }
                if (iResult > 0) {
                    recvbuf[iResult] = 0;
                    //printf("Bytes received: %d\n%s\n", iResult, recvbuf);
                    if (it->handshake) {
                        int opcode;

                        message = it->decodeFrame(recvbuf, iResult, opcode);
                        switch (opcode) {
                            case 1: {
                                printf("%s\n", message.c_str());
                                string frame = it->encode(message, opcode);
                                list<Client>::iterator sent;
                                for (sent = ClientList.begin(); sent != ClientList.end(); ++sent) {
                                    if (it == sent) continue;
                                    int iSendResult = send(sent->ClientSocket, frame.c_str(), frame.length(), 0);
                                    if (iSendResult == SOCKET_ERROR) {
                                        printf("send failed with error: %d\n", WSAGetLastError());
                                        closesocket(it->ClientSocket);
                                        return 1;
                                    }
                                }
                                break;
                            }
                            case 8: {
                                string frame;
                                frame.append(1, (unsigned char)136);
                                frame.append(1, (unsigned char)0);
                                int iSendResult = send(it->ClientSocket, frame.c_str(), frame.length(), 0);
                                if (iSendResult == SOCKET_ERROR) {
                                    printf("send failed with error: %d\n", WSAGetLastError());
                                    closesocket(it->ClientSocket);
                                    return 1;
                                }
                                it = ClientList.erase(it);
                                it--; 
                                break;
                            }
                            case 9: {
                                string frame = it->encode(message, opcode);
                                int iSendResult = send(it->ClientSocket, frame.c_str(), frame.length(), 0);
                                if (iSendResult == SOCKET_ERROR) {
                                    printf("send failed with error: %d\n", WSAGetLastError());
                                    closesocket(it->ClientSocket);
                                    return 1;
                                }
                                break;
                            }
                        }
                    }
                    else {
                        if (!it->doHandshake(recvbuf)) {
                            it = ClientList.erase(it);
                            it--;
                            continue;
                        }
                    }            
                }
            }
        }

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