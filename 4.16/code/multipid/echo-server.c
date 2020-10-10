#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_THREAD 3
    char *model = "GET /1.txt HTTP/1.1";
    char *ok = "HTTP/1.0 200 OK\r\nContent-Length: 15\r\n\r\n";
    char OK[2000] = {0};
    char buf[1000] = {0};
    char *no = "HTTP/1.0 404 FILE NOT FOUND\r\n\r\n";
    int s;
    int cs;
    struct sockaddr_in server, client;
    char msg[2000];
    
    

    
int main(int argc, const char *argv[])
{
    int x;
    
    pthread_t thread[MAX_THREAD];
    pid_t pid;
    
    
    //read file
    FILE *fd;
    if(!(fd = fopen("1.txt","r")))    
    {
        printf("open 1.txt failed!\n");
        return 1;
    }
    int m = 0;
    while((x = fgetc(fd))!= EOF)
    { 
        buf[m] = x;
        m++;
    }
    
    strcat(OK,ok);
    
    strcat(OK,buf);
    //strcat(OK,"\r\n");
    // create socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("create socket failed");
		return -1;
    }
    
    printf("socket created");
     
    // prepare the sockaddr_in structure
    //for(int i = 0; i < MAX_THREAD; i++)
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(80);
    
    // bind
    
    if (bind(s,(struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind failed");
        return -1;
    }
    
    printf("bind done");
     
    // listen
   
        listen(s, 6);
    
    printf("waiting for incoming connections...");
    
    while(1)
    { 
    // accept connection from an incoming client
  
    int c = sizeof(struct sockaddr_in);
    if ((cs = accept(s, (struct sockaddr *)&client, (socklen_t *)&c)) < 0) {
        perror("accept failed");
        return -1;
    }
    printf("connection accepted");
   
    pid = fork();
    if(pid==0)
    {//child
        close(s);
       
                 int msg_len = 0;
         // receive a message from client
                 while ((msg_len = recv(cs, msg, sizeof(msg), 0)) > 0) {
        // send the message back to client
                     printf("%s\n",msg);
 
                     char message[4000]={0};
                     strcat(message,msg);
                     for(int j = 19; j < strlen(msg);j++)
                         message[j] = 0;
                     printf("%s\n",message);
                     if(strcmp(message,model) == 0)
                     {
            
                          write(cs,OK,strlen(OK));
                     }
                     else write(cs,no,strlen(no));

            

                 //write(cs, msg, msg_len);
                                                                       }
          
                 if (msg_len == 0) {
                     printf("client disconnected");
                     
                                   }
                 else { // msg_len < 0
                     perror("recv failed");
                     close(cs);
	        	return -1;
                      }
        close(cs);
        return 0; 
    }
    else if(pid > 0)
    {//parent
        close(cs);
    }
    else
    {
        printf("fork failed!\n");
        exit(1);
    }
    
    }
     
     
	
     
    return 0;
}
