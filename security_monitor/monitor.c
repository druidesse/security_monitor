#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>

#define MAX_ATTEMPTS 5
#define TIME_WINDOW 60
#define PCAP_TIMEOUT 1000

// 의심스러운 접근 시도를 추적하기 위한 구조체
typedef struct {
    char ip[16];
    time_t timestamp;
} AccessAttempt;

AccessAttempt attempts[1000];
int attempt_count = 0;

// 시스템 종료 함수
void shutdown_system() {
    printf("[경고] 해킹 시도 감지! 시스템을 종료합니다...\n");
    system("init 6");  // 시스템 재부팅 명령
    exit(1);
}

// 패킷 처리 콜백 함수
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    char source_ip[16];
    time_t current_time;
    int suspicious = 0;

    // IP 헤더 추출
    ip_header = (struct ip*)(packet + 14);  // 이더넷 헤더 건너뛰기
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, sizeof(source_ip));
    
    // TCP 헤더 추출
    tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2));
    
    // 의심스러운 패턴 확인
    if (tcp_header->syn && !tcp_header->ack) {  // SYN 스캔 감지
        suspicious = 1;
    }
    
    if (suspicious) {
        time(&current_time);
        
        // 오래된 시도 제거
        int i = 0;
        while (i < attempt_count) {
            if (current_time - attempts[i].timestamp > TIME_WINDOW) {
                memmove(&attempts[i], &attempts[i+1], 
                        (attempt_count - i - 1) * sizeof(AccessAttempt));
                attempt_count--;
            } else {
                i++;
            }
        }
        
        // 새로운 시도 기록
        strncpy(attempts[attempt_count].ip, source_ip, 16);
        attempts[attempt_count].timestamp = current_time;
        attempt_count++;
        
        // 동일 IP의 시도 횟수 확인
        int count = 0;
        for (i = 0; i < attempt_count; i++) {
            if (strcmp(attempts[i].ip, source_ip) == 0) {
                count++;
            }
        }
        
        printf("[감지] 의심스러운 접근 시도 - IP: %s (횟수: %d)\n", source_ip, count);
        
        if (count >= MAX_ATTEMPTS) {
            shutdown_system();
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net, mask;
    
    // root 권한 확인
    if (getuid() != 0) {
        printf("이 프로그램은 root 권한으로 실행해야 합니다.\n");
        return 1;
    }
    
    // 네트워크 디바이스 찾기
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("네트워크 디바이스를 찾을 수 없습니다: %s\n", errbuf);
        return 1;
    }
    
    // 네트워크 정보 가져오기
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        printf("네트워크 정보를 가져올 수 없습니다: %s\n", errbuf);
        return 1;
    }
    
    // 패킷 캡처 시작
    handle = pcap_open_live(dev, BUFSIZ, 1, PCAP_TIMEOUT, errbuf);
    if (handle == NULL) {
        printf("패킷 캡처를 시작할 수 없습니다: %s\n", errbuf);
        return 1;
    }
    
    // 필터 설정
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        printf("필터를 컴파일할 수 없습니다\n");
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("필터를 설정할 수 없습니다\n");
        return 1;
    }
    
    printf("보안 모니터링을 시작합니다...\n");
    printf("주의: 이 프로그램은 위험할 수 있으며, 테스트 목적으로만 사용하세요.\n");
    
    // 패킷 캡처 루프 시작
    pcap_loop(handle, -1, packet_handler, NULL);
    
    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
} 