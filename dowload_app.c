#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>

#include <string.h>

typedef enum {
    RECEIVE_USER,
    RECEIVE_PASS,
    PASS_REC,
    PASV_MODE,
    TRANSFER,
    TRANSFER_COMPLETE
} connection_state;

typedef enum{
    CODE,
    ONE,
    MANY,
    END
} response_state;

static response_state response_st = CODE;

/*SERVER RESPONSES*/
#define RV_USER 200
#define RC_PASS 331
#define PASS_OK 230
#define ENTER_PASV 227
#define FILE_TRANSFER 150
#define TRANSFER_COMPLETE 226

int parseParameters(char* input, char* host_ip, char *path, char* user, char* pass){

    char protocol [6]; 
    sscanf(input, "%3[^:]://",protocol);

    if(strcmp(protocol, "ftp") != 0){
        printf("Wrong protocol. Use ftp\n");
        return -1;
    }

    int matched = sscanf(input, "ftp://%100[^:]:%100[^@]@%1000[^/]%1000[^\n]",user,pass, host_ip, path);

    //no password and user found. Using default values
    if(matched < 3){
        strcpy(user,"anonymous");
        strcpy(pass,"anonynous");
        sscanf(input, "ftp://%1000[^/]%1000[^\n]",host_ip, path);
    }

    //gets the ip of the domain given
    struct hostent *h;
    if ((h = gethostbyname(host_ip)) == NULL) {
        herror("gethostbyname()");
        exit(-1);
    }
    strcpy( host_ip, inet_ntoa(*((struct in_addr *) h->h_addr)));

    long host_len = strlen(host_ip);
    host_ip[host_len] = '\0';

    return 0;
}

void response_state_machine(char *byte){
    switch(response_st){
        //first characters (response code)
        case CODE:

            if(*byte == ' '){
                response_st = ONE;
            }
            else if(*byte == '-'){
                response_st = MANY;
            }
            else if(*byte == '\n'){
                response_st = END;
            }
            break;

        //last line or just one line
        case ONE:
            if(*byte == '\n'){
                response_st = END;
            }
            break;

        //there are still many lines
        case MANY:
            if(*byte == '\n'){
                response_st = CODE;
            }
            break;
        
        case END:
            break;
    }

}

int readServerResponsePassive(const int socket, char* response, int* filePort){
    char passiveResponse [1000];
    read(socket, passiveResponse, 1000);

    //get the response code
    memcpy(response, passiveResponse, 3 * sizeof(char));

    //parse the response to calculate the new port for receiving the file
    int v1,v2,v3,v4,v5,v6;
    sscanf(passiveResponse, "%*[^(](%d,%d,%d,%d,%d,%d)%*[^\n]", &v1,&v2,&v3,&v4,&v5,&v6);

    *filePort = v5 * 256 + v6;

    printf("NewPort = %d\n", *filePort);

    response[3] = '\0';
    printf("Server answered with : %s\n\n", response);

    return 0;

}
//gets the server response (code number)
int readServerResponse(const int socket, char* response){
    char *byte = malloc(sizeof(char) * 2);
    int index = 0;

    response_st = CODE;
    
    while(response_st != END){
        read(socket, byte, 1);

        response_state_machine(byte);

        if(index < 3 && response_st == CODE){
            response[index] = *byte;  
            index++;   
        }

        
        
    }

    free(byte);
    response[3] = '\0';
    printf("Server answered with : %s\n\n", response);
    return 0;
}

//sends information to the server. It can be the username, password, or requests
int sendInfo(const int socket, char* info){
    size_t bytes = write(socket, info, strlen(info));
    if (bytes > 0)
        printf("Bytes written: %ld\n", bytes);
    else {
        perror("write()");
        return -1;
    }

    return 0;
}

int createSockect(int *sockfd, int port, char* host_ip){
    struct sockaddr_in server_addr;

    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(host_ip);    /*32 bit Internet address network byte ordered*/
    server_addr.sin_port = htons(port); //use 21 becasue is the one used in ftp

    /*open a TCP socket*/
    if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }

    /*connect to the server*/
    if (connect(*sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect()");
        return -1;;
    }

    return 0;
}

int readFile(int sockfd, char *filename){

    FILE *file = fopen(filename, "w+");
    if(file == NULL){
        printf("Error while creating/opening the file %s\n", filename);
        return -1;
    }

    int bytes = 1;
    char readBuffer [1000];
    while(bytes > 0){

        bytes = read(sockfd, readBuffer, 999);
        readBuffer[bytes] = '\n';

        if(fwrite(readBuffer, bytes, sizeof(char), file) < 0){
            return -1;
        }
    }

    fclose(file);
    return 0;
}

int main (int argc, char* argv[]){

    if(argc == 0){
        printf("INSTRUCTIONS: \n\n");
        printf("Use the following: ftp://[<user>:<password>@]<host>/<url-path>\n");
        printf("Max length user = 100 chars\n");
        printf("Max length password = 100 chars\n");
        printf("Max length host/path = 1000 chars\n");
    }

    if(argc > 2){
        printf("Cannot receive more than 1 argument. Use the following: ftp://[<user>:<password>@]<host>/<url-path>");
        exit(-1);
    }

    printf("\n\nSTARTING\n\n");

    //parse the url received
    char *host_ip = malloc(sizeof(char) * 1000);
    char *path = malloc(sizeof(char) * 1000);
    char *user = malloc(sizeof(char) * 100);
    char *pass = malloc(sizeof(char) * 100);
    if(parseParameters(argv[1], host_ip, path, user, pass) < 0){
        return -1;
    }

    //received parameters
    printf("host = %s\n", host_ip);
    printf("user = %s\n", user);
    printf("password = %s\n\n\n", pass);

    int sockfd;
    if(createSockect(&sockfd, 21, host_ip) < 0){
        printf("Error while creating the socket A\n");
        return -1;
    }

    //receive confirmation to insert the user name
    char *response = malloc(sizeof(char) * 3);
    memset(response, 0, 3);
    readServerResponse(sockfd,response );
    if(strcmp(response, "220") != 0){
        printf("Server side problem. Wrong reponse. Please try again.\n");
        return -1;
    }


    //send username
    memset(response, 0, 3 * sizeof(char));
    char *info = malloc(sizeof(char) * 1000);
    memcpy(info, "user ", 5);
    memcpy(info + 5, user, strlen(user));
    info[5 + strlen(user)] = '\n';
    info[5 + strlen(user) + 1] = '\0';
    printf("%s", info);
    sendInfo(sockfd, info);
    readServerResponse(sockfd,response );
    if(strcmp(response, "331") != 0){
        printf("Unknown User. Please try again\n");
        return -1;
    }

    //send password
    memset(response, 0, 3 * sizeof(char));
    memset(info, 0, 1000 * sizeof(char));
    memcpy(info, "pass ", 5);
    memcpy(info + 5, pass , strlen(pass));
    info[5 + strlen(pass)] = '\n';
    info[5 + strlen(user) + 1] = '\0';
    printf("%s", info);
    sendInfo(sockfd, info);
    readServerResponse(sockfd, response);
    if(strcmp(response, "230") != 0){
        printf("Wrong password. Please try again\n");
        return -1;
    }

    //send passive mode command
    memset(response, 0, 3 * sizeof(char));
    memset(info, 0, 1000 * sizeof(char));
    memcpy(info, "pasv\n\0", 6);
    printf("%s", info);
    sendInfo(sockfd, info);
    int newport = 0;
    readServerResponsePassive(sockfd, response, &newport);
    if(strcmp(response, "227") != 0){
        printf("Server side erro while changing to passive mode. Please try again\n");
        return -1;
    }

    //connect another socket 
    int sockfd2;
    if(createSockect(&sockfd2, newport, host_ip) < 0){
        printf("Error while creating the socket B\n");
        return -1;
    }

    //receive confirmation of the connection to B
    memset(response, 0, 3 * sizeof(char));
    memset(info, 0, 1000 * sizeof(char));
    memcpy(info, "retr ", 5);
    memcpy(info + 5, path, strlen(path));
    memcpy(info + 5 + strlen(path), "\n\0", 2);
    printf("%s", info);
    sendInfo(sockfd,info);
    readServerResponse(sockfd, response);
    if(strcmp(response, "150") != 0){
        printf("Bad connection to server by socket B. Please try again\n");
        return -1;
    }

    //read file in socket B
    char * filename = malloc(sizeof(char) * 1000);
    strcpy(filename, strrchr(path,'/') + 1);
    size_t size_name = strlen(strrchr(path,'/') + 1);
    filename[size_name] = '\0';
    readFile(sockfd2, filename);

    //get the confirmation that the file was transferred
    memset(response, 0, 3 * sizeof(char));
    memset(info, 0, 1000 * sizeof(char));
    readServerResponse(sockfd, response);
    if(strcmp(response, "226") != 0){
        printf("Something went wrong when transferring the file. Please try again\n");
        return -1;
    }

    printf("\nConnection completed successfully!!!\n");

    //close the socket previously open
    if (close(sockfd)<0) {
        perror("close()");
        exit(-1);
    }

    if(close(sockfd2) < 0){
        perror("close()");
        exit(-1);
    }

    free(host_ip);
    free(user);
    free(pass);
    free(response);
    free(info);
    free(filename);

    return 0;
}