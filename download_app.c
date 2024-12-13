#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>

#include <string.h>

#define MAX_LEN 500

/*
typedef enum{
    CODE,
    ONE,
    MANY,
    END
} response_state;

static response_state response_st = CODE;
*/

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
        strcpy(pass,"anonymous");
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
    //buffer used to store the response content
    char message[500];
    char line[500];
    memset(message, 0, 500);
    memset(line, 0, 500);

    bool multi = false; 
    char byte;
    int idx = 0;
    
    while (true) {
        int b = read(socket, &byte, 1);

        if(b <= 0){
            //read error
            return -1;
        }

        if (byte == '\n') { 
            //finnished to read the line

            line[idx] = '\0';

            //reset the idx because we have a new line coming next 
            idx = 0;

            //check if is first line of the response
            if (strlen(message) == 0) {
               //copy the response code
                memcpy(response, line, 3);

                //the response is multiline
                if (line[3] == '-') {
                    multi = true; 
                }
            }

            //copy the line content to the message
            strcpy(message, line);
            strcpy(message + strlen(message), "\n");
            printf("%s", message);

            //check if is only one line. We don't have nothing more to read
            if (!multi) {
                break; 
            }

            //check if is last line so that we can exit the loop and send another request
            if(line[3] != '-' && strncmp(line, response, 3) == 0){
                break;
            }

        } else {   
            if (idx < 499) {
                line[idx] = byte;
                idx++;
            } else {
                //reached the limit of the buffer. Could not catch the \n
                return -1;
            }
        }
    }

    

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

    //open the file or create a new one if it doesn't exist
    FILE *file = fopen(filename, "w+");
    if(file == NULL){
        printf("Error while creating/opening the file %s\n", filename);
        return -1;
    }

    int bytes = 1;
    char readBuffer [1000];

    while(bytes > 0){

        //read the content from the socket
        bytes = read(sockfd, readBuffer, 999);
        readBuffer[bytes] = '\n';

        //write the content retrieved from the socket to the file
        if(fwrite(readBuffer, bytes, sizeof(char), file) < 0){
            return -1;
        }
    }

    fclose(file);
    return 0;
}

int main (int argc, char* argv[]){

    if(argc == 1){
        printf("INSTRUCTIONS: \n\n");
        printf("Use the following: ftp://[<user>:<password>@]<host>/<url-path>\n");
        printf("Max length user = 100 chars\n");
        printf("Max length password = 100 chars\n");
        printf("Max length host/path = 1000 chars\n");
        exit(-1);
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
    char *response = malloc(sizeof(char) * 4);
    memset(response, 0, 4);
    readServerResponse(sockfd,response );
    if(strcmp(response, "220") != 0){
        printf("Server side problem. Wrong reponse. Please try again.\n");
        return -1;
    }


    //send username
    memset(response, 0, 4 * sizeof(char));
    char *info = malloc(sizeof(char) * 1000);
    memcpy(info, "USER ", 5);
    memcpy(info + 5, user, strlen(user));
    info[5 + strlen(user)] = '\r';
    info[5 + strlen(user) + 1] = '\n';
    info[5 + strlen(user) + 2] = '\0';
    printf("%s", info);
    sendInfo(sockfd, info);
    readServerResponse(sockfd,response);
    printf("%s\n", response);
    if(strcmp(response, "331") != 0){
        printf("Unknown User. Please try again\n");
        return -1;
    }

    //send password
    memset(response, 0, 4 * sizeof(char));
    memset(info, 0, 1000 * sizeof(char));
    memcpy(info, "PASS ", 5);
    memcpy(info + 5, pass , strlen(pass));
    info[5 + strlen(pass)] = '\r';
    info[5 + strlen(pass) + 1] = '\n';
    info[5 + strlen(pass) + 2] = '\0';
    printf("%s", info);
    sendInfo(sockfd, info);
    readServerResponse(sockfd, response);
    if(strcmp(response, "230") != 0){
        printf("Wrong password. Please try again\n");
        return -1;
    }

    //send passive mode command
    memset(response, 0, 4 * sizeof(char));
    memset(info, 0, 1000 * sizeof(char));
    memcpy(info, "pasv\r\n\0", 7);
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
    memset(response, 0, 4 * sizeof(char));
    memset(info, 0, 1000 * sizeof(char));
    memcpy(info, "retr ", 5);
    memcpy(info + 5, path, strlen(path));
    memcpy(info + 5 + strlen(path), "\r\n\0", 3);
    printf("%s", info);
    sendInfo(sockfd,info);
    readServerResponse(sockfd, response);
    if( (strcmp(response, "150") == 0) || (strcmp(response, "125") == 0)){
        printf("Connection to server with socket B was sucessfull !\n");
    }
    else{
        printf("Bad connection to server by socket B. Please try again\n");
        return -1;
    }

    //read file in socket B
    char * filename = malloc(sizeof(char) * 1000);
    strcpy(filename, strrchr(path,'/') + 1);
    size_t size_name = strlen(strrchr(path,'/') + 1);
    filename[size_name] = '\0';
    readFile(sockfd2, filename);

    //close B socket
    if(close(sockfd2) < 0){
        perror("close()");
        exit(-1);
    }

    //get the confirmation that the file was transferred
    memset(response, 0, 4 * sizeof(char));
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

    free(host_ip);
    free(user);
    free(pass);
    free(response);
    free(info);
    free(filename);

    return 0;
}