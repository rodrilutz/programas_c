/************************************************************************

    Software que monitora e analisa o tráfego dentro de uma rede. 
    Esse software captura pacotes de dados, armazenando os mesmos. 

    Criado por: Rodrigo Lutz    Data: 14/11/2020

    Comando para compilar e executar simulteneamente 
    Ex: gcc sniffer2.c && sudo ./a.out

************************************************************************/

#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>                   
#include<stdlib.h>    
#include<string.h>  
#include<stdbool.h>  
 
#include<netinet/ip_icmp.h>     //Declaração para icmp 
#include<netinet/udp.h>         //Declaração para udp
#include<netinet/tcp.h>         //Declaração para tcp 
#include<netinet/ip.h>          //Declaração para ip 
#include<netinet/if_ether.h>    //Declaração para ETH_P_ALL
#include<net/ethernet.h>        //Declaração para ethernet
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

#define SAIR 0
#define UDP 1
#define TCP 2
#define ICMP 3
#define IGMP 4
#define IP_Origem 5
#define IP_Destino 6
#define Porta_Origem 7
#define Porta_Destino 8
#define Flag_ACK 9
#define Nro_Seq 10
#define Ender_Destino 11
#define Ender_Origem 12
#define Todos 99
#define MAX_OP 12
#define MAX_OP2 8

void processamento_pacotes(buffer, data_size);
void pacotes_TCP(unsigned char* Buffer, int Size);
bool existe_opcao(int opcao);
char * retorna_nome_filtro(int opcao, char * msg);
void PrintData (unsigned char* data , int Size);
void print_ip_header(unsigned char* Buffer, int Size);
void print_ethernet_header(unsigned char* Buffer, int Size);
void pacotes_UDP(unsigned char *Buffer , int Size);
void pacotes_ICMP(unsigned char* Buffer , int Size);

// Variaveis globais
FILE *logfile;
struct sockaddr_in source, dest;
int opc[10];
int pos=0;
 
int main()
{
    int saddr_size;
    int data_size;
    int cont=0;
    int op;
    struct sockaddr saddr;
    char msg[20];

    if (!(logfile = fopen("sniffer_log.txt","w")))  /* Caso ocorra algum erro na abertura do arquivo..*/ 
                  {                           /* o programa aborta automaticamente */
        printf("Erro! Impossivel abrir o arquivo!\n");
        exit(1);
    }

    // Faz a limpeza do arquivo
    fclose(logfile);
         
    unsigned char *buffer = (unsigned char *) malloc(65536); 
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

    if(sock_raw < 0)
    {
        perror("Erro ao acessar socket");
        return 1;
    }

    while(1)
    {

        system("clear");     
        pos=0;

        printf("******************************\n");
        printf("******** Menu Sniffer ********\n");
        printf("******************************\n\n");
        printf("Pacotes...\n\n");
        printf(" 0 - SAIR\n");
        printf(" 1 - Pacotes UDP\n");
        printf(" 2 - Pacotes TCP\n");
        printf(" 3 - Pacotes ICMP\n");
        printf(" 4 - Pacotes IGMP\n");        

        scanf("%d", &op);

        if((op==SAIR) || ((op!=UDP)&&(op!=TCP)&&(op!=ICMP)&&(op!=IGMP)))
        {
            break;
        }else
        {
            opc[0] = op;
            pos++;

            system("clear");

            printf("******************************\n");
            printf("******** Menu Sniffer ********\n");
            printf("******************************\n\n");
            printf("Filtros dos pacotes...\n\n");
            printf(" 0 - SAIR\n");
            printf(" 5 - IP de origem\n");
            printf(" 6 - IP destino\n");
            printf(" 7 - Porta de origem\n");
            printf(" 8 - Porta destino\n");
            printf(" 9 - Flag ACK\n");
            printf("10 - Nro. da Sequencia\n");
            printf("11 - Endereco Destino\n");
            printf("12 - Endereco Origem\n");
            printf("99 - Todos\n\n");

            
            scanf("%d", &cont);

            if(cont==0 || cont==99)
            {
                if(cont==0)
                {
                    op=0;
                    break;
                }

                // Aqui Considerar todos os filtros
                opc[pos] =  5; pos++; // Ip de origem
                opc[pos] =  6; pos++; // Ip destino
                opc[pos] =  7; pos++; // Porta de origem
                opc[pos] =  8; pos++; // Porta destino
                opc[pos] =  9; pos++; // Flag ACK
                opc[pos] = 10; pos++; // Nro da Sequencia
                opc[pos] = 11; pos++; // Endereco Destino
                opc[pos] = 12; pos++; // Endereco Origem
                
            }else
            {
                printf("\nEntre com %d opcoes\n", cont);

                for(int i=0;i<cont;i++)
                {
                    if(i>MAX_OP2) 
                        break;

                    scanf("%d", &op);

                    switch(op)
                    {
                        case SAIR: printf("SAIR\n");
                             break;
                        case IP_Origem: printf("Ip de origem...\n");        
                             break;
                        case IP_Destino: printf("Ip destino...\n");          
                             break;
                        case Porta_Origem: printf("Porta de origem...\n");     
                             break;
                        case Porta_Destino: printf("Porta destino...\n");       
                             break;
                        case Flag_ACK: printf("Flag ACK...\n");            
                             break;
                        case Nro_Seq: printf("Nro. da Sequencia...\n");   
                             break;
                        case Ender_Destino: printf("Endereco destino...\n");   
                             break;
                        case Ender_Origem: printf("Endereco origem...\n");   
                             break;
                        default: printf("Opcao invalida!\n");        
                             break;
                    }

                    // Sair do programa
                    if(op == SAIR) break;       

                    // Opcao inválida
                    if((op==SAIR)||((op!=IP_Origem)&&(op!=IP_Destino)&&(op!=Porta_Origem)&&(op!=Porta_Destino)&&(op!=Flag_ACK)&&(op!=Nro_Seq)&&(op!=Ender_Destino)&&(op!=Ender_Origem))) 
                    {   
                        cont++;
                    }else
                    {   
                        // Verifica se a opcão já foi selecionada
                        bool existe_opc = false;
                        if(pos>0)
                        {
                            for(int x=0;x<pos;x++)
                            {
                                if(op==opc[x])
                                {
                                    existe_opc = true;
                                    break;
                                }
                            }    
                        }

                        // Incrementar no vetor
                        if(existe_opc)
                        {
                            printf("Opcao já foi informada, informe novamente!\n");
                            cont++;
                        }else
                        {
                            opc[pos]=op;
                            pos++; 
                        }
                    }
                }
            }
        }

        // Sair do programa
        if(op == SAIR) break; 

        
        system("clear");     

        if (!(logfile = fopen("sniffer_log.txt","a")))  /* Caso ocorra algum erro na abertura do arquivo..*/ 
        {                                               /* o programa aborta automaticamente */
            printf("Erro! Impossivel abrir o arquivo!\n");
            exit(1);
        }

        printf("Filtros selecionados: \n");
        for(int x=0;x<pos;x++)
        {
            retorna_nome_filtro(opc[x], msg);
            printf("%s \n", msg);
            fprintf(logfile,"%s \n", msg);
        }
        printf("\n\nProcessando pacotes...\n\n");
        fprintf(logfile,"\n\nProcessando pacotes...\n\n");

        fclose(logfile);

        //setbuf(stdin,NULL);      
        //getchar(); 
        
        while(1)
        {
            if (!(logfile = fopen("sniffer_log.txt","a")))  /* Caso ocorra algum erro na abertura do arquivo..*/ 
            {                                               /* o programa aborta automaticamente */
                printf("Erro! Impossivel abrir o arquivo!\n");
                exit(1);
            }

            saddr_size = sizeof saddr;

            //Recebendo pacotes
            data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
            if(data_size <0 )
            {
                printf("Falha ao receber dados\n");                
                fprintf(logfile,"Falha ao receber dados\n");
            }

            //Processamento dos pacotes
            processamento_pacotes(buffer , data_size, opc);

            fclose(logfile);
        }
        close(sock_raw);
    }
}

//
// Processamento dos pacotes
//
void processamento_pacotes(unsigned char* buffer, int size)
{
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    switch (iph->protocol) 
    {
        case 1:  //ICMP             
            if(existe_opcao(ICMP))
            {
                pacotes_ICMP( buffer , size);
            } 
            break;
         
        case 2:  //IGMP
            break;
         
        case 6: //TCP
            if(existe_opcao(TCP))
            {
                pacotes_TCP(buffer , size);    
            } 
            break;
         
        case 17: //UDP
            if(existe_opcao(UDP))
            {
                pacotes_UDP(buffer , size);    
            } 
            break;
         
        default: //Outros
            break;
    }
}

//
// Cabeçalho Ethernet
//
void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    if(existe_opcao(Ender_Origem) || existe_opcao(Ender_Destino))
    {
        printf("\n");
        fprintf(logfile,"\n");

        printf(">>> Cabeçalho Ethernet\n");
        fprintf(logfile,">>> Cabeçalho Ethernet\n");

        if(existe_opcao(Ender_Destino))        
        {
            printf("   |-Endereço Destino   : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
            fprintf(logfile,"   |-Endereço Destino   : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
        }
        
        if(existe_opcao(Ender_Origem))
        {
            printf("   |-Endereço Origem    : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
            fprintf(logfile,"   |-Endereço Origem    : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
        }
    }
}

//
// Cabeçalho IP
//
void print_ip_header(unsigned char* Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    if(existe_opcao(IP_Origem) || existe_opcao(IP_Destino))
    {
        printf("\n");
        fprintf(logfile,"\n");

        printf(">>> Cabeçalho IP\n");
        fprintf(logfile,">>> Cabeçalho IP\n");

        if(existe_opcao(IP_Origem))
        {
            printf("   |-IP de origem       : %s\n",inet_ntoa(source.sin_addr));
            fprintf(logfile,"   |-IP de origem       : %s\n",inet_ntoa(source.sin_addr));
        }

        if(existe_opcao(IP_Destino))           
        {
            printf("   |-IP destino         : %s\n",inet_ntoa(dest.sin_addr));
            fprintf(logfile,"   |-IP destino         : %s\n",inet_ntoa(dest.sin_addr));
        }
    }
}

//
// TCP - Porta_Origem - Porta_Destino - Flag_ACK - Nro_Seq
//
void pacotes_TCP(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    print_ip_header(Buffer, Size);

    if(existe_opcao(Porta_Origem)||existe_opcao(Porta_Destino)||existe_opcao(Flag_ACK)||existe_opcao(Nro_Seq))
    {
        printf("\n");
        fprintf(logfile,"\n");

        printf(">>> Cabeçalho TCP\n");
        fprintf(logfile,">>> Cabeçalho TCP\n");

        if(existe_opcao(Porta_Origem))
        {
            printf("   |-Porta origem       : %u\n",ntohs(tcph->source));
            fprintf(logfile,"   |-Porta origem       : %u\n",ntohs(tcph->source));
        }

        if(existe_opcao(Porta_Destino))
        {
            printf("   |-Porta destino      : %u\n",ntohs(tcph->dest));
            fprintf(logfile,"   |-Porta destino      : %u\n",ntohs(tcph->dest));
        }

        if(existe_opcao(Nro_Seq))
        {
            printf("   |-Nro sequencia      : %u\n",ntohl(tcph->seq));
            fprintf(logfile,"   |-Nro sequencia      : %u\n",ntohl(tcph->seq));
        }

        if(existe_opcao(Flag_ACK))
        {
            printf("   |-Nro ACK            : %u\n",ntohl(tcph->ack_seq));    
            printf("   |-Flag ACK           : %d\n",(unsigned int)tcph->ack);
            fprintf(logfile,"   |-Nro ACK            : %u\n",ntohl(tcph->ack_seq));    
            fprintf(logfile,"   |-Flag ACK           : %d\n",(unsigned int)tcph->ack);
        }
    }
}

//
// UPD - Porta_Origem - Porta_Destino - Flag_ACK - Nro_Seq
//
void pacotes_UDP(unsigned char *Buffer , int Size)
{    
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    print_ip_header(Buffer,Size);           

    if(existe_opcao(Porta_Origem)||existe_opcao(Porta_Destino))
    {
        printf("\n");
        fprintf(logfile,"\n");

        printf(">>> Cabeçalho UDP\n");
        fprintf(logfile,">>> Cabeçalho UDP\n");

        if(existe_opcao(Porta_Origem))
        {
            printf("   |-Porta origem       : %d\n" , ntohs(udph->source));
            fprintf(logfile,"   |-Porta origem       : %d\n" , ntohs(udph->source));
        }

        if(existe_opcao(Porta_Destino))
        {
            printf("   |-Porta destino      : %d\n" , ntohs(udph->dest));
            fprintf(logfile,"   |-Porta destino      : %d\n" , ntohs(udph->dest));
        }
    }
}

//
// ICMP - Porta_Origem - Porta_Destino - Flag_ACK - Nro_Seq
//
void pacotes_ICMP(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    print_ip_header(Buffer , Size);
             
    printf("\n");
    fprintf(logfile,"\n");
         
    printf(">>> Cabeçalho ICMP\n");
    fprintf(logfile,">>> Cabeçalho ICMP\n");
    
    printf("   |-Tipo               : %d",(unsigned int)(icmph->type));
    fprintf(logfile,"   |-Tipo               : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        printf("  (TTL Expired)\n");
        fprintf(logfile,"  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        printf("  (ICMP Echo Reply)\n");
        fprintf(logfile,"  (ICMP Echo Reply)\n");
    }
     
    printf("   |-Code               : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile,"   |-Code               : %d\n",(unsigned int)(icmph->code));

    printf("   |-Checksum           : %d\n",ntohs(icmph->checksum));
    fprintf(logfile,"   |-Checksum           : %d\n",ntohs(icmph->checksum));
    
}

bool existe_opcao(int opcao)
{
    if(pos==0) return false;

    for(int x=0;x<pos;x++)
    {
        if(opcao==opc[x]) return true;
    }
    return false;
}

char * retorna_nome_filtro(int opcao, char * msg)
{

    switch(opcao)
    {
        case UDP: strcpy(msg, "(Pacotes UDP)");
             break;
        case TCP: strcpy(msg, "(Pacotes TCP)");         
             break;
        case ICMP: strcpy(msg, "(Pacotes ICMP)");      
             break;
        case IGMP: strcpy(msg, "(Pacotes IGMP)");      
             break;
        case IP_Origem: strcpy(msg, "(Ip de origem)");        
             break;
        case IP_Destino: strcpy(msg, "(Ip destino)");          
             break;
        case Porta_Origem: strcpy(msg, "(Porta de origem)");     
             break;
        case Porta_Destino: strcpy(msg, "(Porta destino)");       
             break;
        case Flag_ACK: strcpy(msg, "(Flag ACK)");            
             break;
        case Nro_Seq: strcpy(msg, "(Nro. da Sequencia)");   
             break;
        case Ender_Destino: strcpy(msg, "(Endereco destino)");   
             break;
        case Ender_Origem: strcpy(msg, "(Endereco origem)");   
             break;
        default: strcpy(msg, " ");        
             break;
    }
    return msg;
}
