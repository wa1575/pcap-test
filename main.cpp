#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>//ntohs 사용
#include <arpa/inet.h> //inet_ntoa함수를 호출, IP주소 정보를 담은 문자열의 주소값을 반환

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}



void analysis(const unsigned char *packet );
int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) { //실행 sudo ./pcap-test enp0s3
        struct pcap_pkthdr* header; //이더넷 헤더 버퍼의 시작위치[destmac]
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet); //패킷 수신
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);
        //여기에 코딩!
       analysis(packet );
       //여기까지
    }
    pcap_close(handle);
}


void print_ethernet_header(const unsigned char *packet);
int print_ip_header(const unsigned char *packet); //수정!
void print_tcp_header(const unsigned char *packet);

void analysis(const unsigned char *packet )
{
    int offset = 0;

    print_ethernet_header(packet);

    packet += 14 ;              //이더넷헤더 만큼 더함 -> IPv4 헤더
    offset = print_ip_header(packet);

    packet += offset;           // ip_header의 길이만큼 오프셋시킴
    print_tcp_header(packet);
}



#define MAC_byte 6 //길길위키 참조
typedef struct ethernet_header
{
  unsigned char Dest_mac[MAC_byte];//6
  unsigned char Src_mac[MAC_byte]; //6
  unsigned char type;              //2
}ethernet;

void print_mac(unsigned char *mac);
void print_ethernet_header(const unsigned char *packet)
{
        ethernet *eh = (ethernet *)packet; //이더넷 헤더 변수

        unsigned short ethernet_type;
        ethernet_type = ntohs(eh->type); //나머지는 괜찮은데, ntoh를 해줘야 제대로 순서가 나옵니다.

        // 이더넷 헤더 출력하기
        printf("\n===========이더넷 헤더============\n");
        printf("목적지 MAC 주소 : ");
        print_mac(eh->Dest_mac);

        printf("출발지 MAC 주소 : ");
        print_mac(eh->Src_mac);

        printf("Ether type      :  [0x%x]\n",ethernet_type);
}


void print_mac(unsigned char *mac)
{
    printf("[ ");
    for (int i = 0;i <MAC_byte; ++i) //맥은 6바이트씩 읽음
    {
           printf("%02x ", mac[i]);
    }
    printf("]\n");
}

typedef struct IP_header //길길위키참조
{
  unsigned char Header_size:4;
  unsigned char Version:4;        //길길위키랑 다르다...5가 나오길래 바꾸니깐 4가 나옴..
  unsigned char Service;            //DSCP+ECN = 1바이트
  unsigned short Total_Length;      //2바이트
  unsigned short Identification;    //2바이트
  unsigned char Reserved_must_be_zero:1;
  unsigned char Dont_Fragment:1;
  unsigned char More_Fragment:1;
  unsigned char Fragment_Offset1:5;//13비트는 안되니 5비트+1바이트
  unsigned char Fragment_Offset2;
  unsigned char TTL;             //1바이트
  unsigned char Protocol;        //1바이트
  unsigned short Header_checksum;//2바이트
  struct in_addr Src_add;        //4바이트
  struct in_addr Dest_add;
}ip;

int print_ip_header(const unsigned char *packet)
{
        ip *ih = (ip *)packet;  // 마찬가지로 ip_header의 구조체 형태로 변환
        printf("===============IP 헤더============\n");
        printf("IP 버전         : [ IPv%d ]\n", ih->Version);

        printf("목적지 IP 주소  : [ %s ]\n", inet_ntoa(ih->Dest_add) );
        printf("출발지 IP 주소  : [ %s ]\n", inet_ntoa(ih->Src_add) );


        printf("프로토콜        : ");
        switch (ih->Protocol)
        {
        case 1: printf("[ ICMP ]\n"); break;
        case 2: printf("[ IGMP ]\n"); break;
        case 6: printf("[ TCP ]\n"); break;
        case 17: printf("[ UDP ]\n"); break;
        case 89: printf("[ OSPF ] \n"); break;
        default: printf("식별할 수 없는 프로토콜입니다.\n"); break;
        }

        // 헤더크기의 X4를 해서 오프셋값을 구함
        return ih->Header_size*4;
}

typedef struct TCP_header
{
        unsigned short Source_port;  //2바이트
        unsigned short Dest_port;   //2바이트
        unsigned int Sequence_number;      //4바이트
        unsigned int Acknowledgment_number;   //4바이트
        unsigned char Data_offset:4;
        unsigned char Reserved_part1:3;
        unsigned char NS:1;
        unsigned char CWR:1;
        unsigned char ECE:1;
        unsigned char URG:1;
        unsigned char ACK:1;
        unsigned char PSH:1;
        unsigned char RST:1;
        unsigned char SYN:1;
        unsigned char FIN:1;
        unsigned short Window_Size;
        unsigned short Checksum;
        unsigned short Urgent_pointer;
}tcp;

void print_port(int port);
void print_tcp_header(const unsigned char *packet)
{
        tcp *th = (tcp *)packet;

        printf("==============TCP 헤더============\n");
        printf("목적지 포트 번호  : [ %d ]", ntohs(th->Dest_port) );
        print_port(ntohs(th->Dest_port));


        printf("출발지 포트 번호  : [ %d ]", ntohs(th->Source_port) );
        print_port(ntohs(th->Source_port));

        printf("플래그            :"); //2개이상 나올 수 있으므로 if문
        if(ntohs(th->CWR)) printf(" CWR ");
        if(ntohs(th->ECE)) printf(" ENE ");
        if(ntohs(th->URG)) printf(" URG ");
        if(ntohs(th->ACK)) printf(" ACK ");
        if(ntohs(th->PSH)) printf(" PSH ");
        if(ntohs(th->RST)) printf(" RST ");
        if(ntohs(th->SYN)) printf(" SYN ");
        if(ntohs(th->FIN)) printf(" FIN ");
        printf("\n");

}

void print_port(int port)
{
    if(port==80){
        printf(" | HTTP\n");
    }
    else if(port==21){
        printf(" | FTP\n");
    }
    else if(port==22){
        printf(" | SSH\n");
    }
    else if(port==443){
        printf(" | HTTPS\n");
    }
    else printf("\n");
}



