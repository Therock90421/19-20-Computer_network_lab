/* client application */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
 
int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in server;
    char message[1000], server_reply[2000];
    int *fd;
    int file_name;
    
     
    // create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("create socket failed");
		return -1;
    }
    printf("socket created");
     
    server.sin_addr.s_addr = inet_addr("10.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(80);
 
    // connect to server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect failed");
        return 1;
    }
     
    printf("connected\n");
    char sendData[] = "GET /1.txt HTTP/1.1\r\n\r\n"; 
    char sendData2[] = "GET /2.txt HTTP/1.1\r\n\r\n";  
    while(1) {
        printf("enter message : ");
        scanf("%d", &file_name);
        
        // send some data
        if(file_name == 1)
        {
        if (send(sock, sendData, strlen(sendData), 0) < 0) {
            printf("send failed");
            return 1;
        }
        }
        else {if (send(sock, sendData2, strlen(sendData2), 0) < 0) {
            printf("send failed");
            return 1;
        
        }
        }
        // receive a reply from the server
		int len = recv(sock, server_reply, 2000, 0);
        if (len < 0) {
            printf("recv failed");
            break;
        }
		server_reply[len] = 0;
        
        if(server_reply[9] == '2' )
            printf("HTTP 200 OK\n");
        if(server_reply[9] == '4' )
        {
            printf("HTTP 404 FILE NOT FOUND\n"); 
            continue;

        }
        printf("send massage is : %s\n",file_name == 1?sendData:sendData2);    
        printf("%s\n",server_reply);
        printf("content length is : ");
        char *find = "Content-Length: ";
        char *s1,*s2;
        int position = 0;
        int i = 0;
        int length = 0; 
        while(server_reply[i] != '\0')
        {
            s1 = &server_reply[i];
            s2 = find;
            while(*s1 == *s2 && *s1 != '\0' && *s2 != '\0')
            {
                s1++;
                s2++;
            }
            if(*s2 == '\0')
                break;
            
            i++;
            position++;
        }
        i = position + 16;
        while(server_reply[i]>='0' && server_reply[i] <= '9')
        {
            //printf("%c",server_reply[i]);
            length = 10*length + server_reply[i] - '0';
            i++;
        }
        printf("%d\n",length);
        printf("content :");
        s1 = &server_reply[len - length];
        printf("%s\n", s1);
        fd = open("1_receive.txt",O_RDWR|O_CREAT|O_APPEND);
        if(fd == -1)
        {
            printf("create file failed\n");
            return 1;
        }
        write(fd,s1,length);
    }
     
    close(sock);
    return 0;
}
