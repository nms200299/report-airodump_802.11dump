#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // usleep fork
#include <string.h> // memset
#include <time.h>   // clock
//#include <wait.h> // wait

void usage() {
    printf("syntax: 802.11dump <interface>\n");
    printf("sample: 802.11dump wlan0\n");
} // 사용 예시 출력 함수.

void byte2char(int byte){
    switch (byte/16){ // 앞자리
        case 0: case 1: case 2: case 3: case 4:
        case 5: case 6: case 7: case 8: case 9:
            printf("%c",byte/16+48); break; // 숫자 처리
        case 10: case 11: case 12: case 13: case 14: case 15:
            printf("%c",byte/16+55); break; // 문자 처리
    }
    switch (byte%16){ // 뒷자리
        case 0: case 1: case 2: case 3: case 4:
        case 5: case 6: case 7: case 8: case 9:
            printf("%c",byte%16+48); break; // 숫자 처리
        case 10: case 11: case 12: case 13: case 14: case 15:
            printf("%c",byte%16+55); break; // 문자 처리
    }
} // byte 형식을 char 형식(문자열) 16진수로 바꿔서 출력한다.
// (ex. 255 => FF)


int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    } // 인자 값이 2가 아니면 사용 예시 출력 후 비정상 종료.

    char* dev = argv[1];

    pid_t pid;
    pid = fork();
    // 자식 프로세스 생성
    // (이유 : 부모 프로세스에서 iwconfig으로 채널을 바꿔줘도 되는데,
    //         만약 해당 채널에서 패킷이 잡히지 않으면 무한정 대기함..)

//######################### ▼ 부모 프로세스 #########################
    if (pid > 0){ //
        printf("   ___   ___ ____    _ _     _                       \n");
        printf("  ( _ ) / _ \\___ \\  / / | __| |_   _ _ __ ___  _ __  \n");
        printf("  / _ \\| | | |__) | | | |/ _` | | | | '_ ` _ \\| '_ \\ \n");
        printf(" | (_) | |_| / __/ _| | | (_| | |_| | | | | | | |_) |\n");
        printf("  \\___/ \\___/_____(_)_|_|\\__,_|\\__,_|_| |_| |_| .__/ \n");
        printf("                                              |_|    \n");
        printf("Thanks for Useing 802.11dump\n");
        printf("Made by. nms200299\n");
        // 자식 프로세스에서 딜레이를 주고 있는 동안 문구를 출력함.

        char monitormode[99];
        memset(monitormode,0,99);
        strcat(monitormode,"ifconfig ");
        strcat(monitormode,dev);
        strcat(monitormode," down");
        system(monitormode);
        memset(monitormode,0,99);
        strcat(monitormode,"iwconfig ");
        strcat(monitormode,dev);
        strcat(monitormode," mode monitor");
        system(monitormode);
        memset(monitormode,0,99);
        strcat(monitormode,"ifconfig ");
        strcat(monitormode,dev);
        strcat(monitormode," up");
        system(monitormode);
        // 서비스 차원에서 모니터 모드로 전환 해줌.

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        // 인자 값으로 받은 네트워크 장치를 사용해 promiscuous 모드로 pcap를 연다.

        if (handle == nullptr) {
            fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
            return -1;
        } // 열지 못하면 메세지 출력 후 비정상 종료.

        unsigned int info[101][7][7];
        memset(info,0,sizeof(unsigned int)*100*7*7);
        // 배열 초기화

        int num=1;
        time_t t1 = time(0x00);
        struct tm tm1 = *localtime(&t1);
        // Before Time 기록 (첫 실행시 한번)

        while (true) {
            time_t t2 = time(0x00);
            struct tm tm2 = *localtime(&t2);
            // After Time 기록 (루프 돌면서 계속)

            struct pcap_pkthdr* header;
            const u_char* packet;

            int res = pcap_next_ex(handle, &header, &packet);
            // 다음 패킷을 잡고 성공시 1을 반환한다.
            if (res == 0) continue; // timeout이 만기될 경우(0), 다시 패킷을 잡는다.
            if (res == -1 || res == -2) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            } // 에러와(-1), EOF(-2)시 루프를 종료한다.

            if ((packet[24]==0x80) || (packet[24]==0x08) || (packet[24]==0x40)){
            // 만약 (Beacon frame) || (Data) || (Probe Request) 패킷인 경우 통과, 이외는 거름.
                int i,j,k,n,check=0;

                if (packet[24]==0x80) {
                    for(i=0; i<=5; i++){
                        info[0][i][0]=packet[40+i];
                    } // Beacon frame 패킷의 경우 40번째 부터 읽어옴
                } else {
                    for(i=0; i<=5; i++){
                        info[0][i][0]=packet[34+i];
                    } // Data 패킷, Probe Request 패킷의 경우, 34번째 부터 읽어옴
                      //  (Data 패킷의 BSSID 영역은 34번째)
                      //  (Probe Request 패킷의 경우 Source Address 영역이 34번째)
                }
                // ▲ 새로 잡힌 따끈따끈한 BSSID를 임시 공간에 저장함.
                // (임시 공간 영역 = info[0][x][0] (x=0 to 5))

               if (num == 1){
                   for(i=0; i<=5; i++){
                        info[1][i][0] = info[0][i][0];
                   }
                   if ((packet[24]==0x80) || (packet[24]==0x40)){
                        info[1][0][1] = info[1][0][1] + 1;
                        //  Beacon frame, Probe Request 패킷의 경우, info[1][0][1] 공간에서 카운트
                   } else {
                        info[i][0][3] = info[i][0][3] + 1;
                        // Data 패킷의 경우, info[1][0][3] 공간에서 카운트
                   }
                   k = num;
                   num = num + 1;
                  //  ▲ 일단 첫 번째로 잡힌 BSSID는 info[1][x][0] (x=0 to 5)에 할당함.

               } else {
                   for(i=1; i<=num-1; i++){
                       check = 0;
                       for(j=0; j<=5; j++){
                           if (info[i][j][0] == info[0][j][0]){
                              check = check + 1;
                               if (check >= 6) {
                                   break;
                               }
                           }
                       }
                       if (check >= 6) {
                           break;
                       }
                   } //  ▲ 두번째 이상으로 잡힌 BSSID의 경우,
                   //      현재 공간에 저장되어 있는 모든 BSSID 목록와 중복되는지 비교함.

                   if (check >= 6){
                        if ((packet[24]==0x80) || (packet[24]==0x40)) {
                           info[i][0][1] = info[i][0][1] + 1;
                        } else {
                           info[i][0][3] = info[i][0][3] + 1;
                        } // ▲ 만약 중복된다면, 해당 BSSID 공간의 Beacons 개수(Frames 개수) 또는 Data 개수를 +1 함.
                       k = i;

                   } else {
                       for(i=0; i<=5; i++){
                            info[num][i][0] = info[0][i][0];
                       }
                       if ((packet[24]==0x80) || (packet[24]==0x40)) {
                          info[num][0][1] = info[num][0][1] + 1;
                       } else {
                          info[num][0][3] = info[num][0][3] + 1;
                       }
                       k = num;
                       num = num + 1;
                   } // ▲ 만약 중복되지 않는다면, 새롭게 공간을 할당해주고,
                   //     Beacons 개수 또는 Data 개수를 +1 함.
               }

                if ((packet[24]==0x80) || (packet[24]==0x40)) {
                // Beacon 패킷과 Probe Request 패킷의 경우, 데이터 수집이 필요함.

                    info[k][0][2]=256-packet[18];
                    // ▲ PWR 정보를 info[x][0][2]에 저장함.
                    // (와이어샤크 통해서 분석해보니 256에서 빼줘야 '-n dBM' 정보가 나옴.)
                    j=0;

                    // ▼ Beacons 패킷이면 여러가지 정보를 추출해냄.
                    if (packet[24]==0x80) {
                        n=0;
                        i=61+packet[61];
                        for(;packet[i+1]!=0;){
                            switch (packet[i+1]) {
                                case 0: // 0이 의미하는 바는, SSID Tag Number지만 이미 지나왔으므로, packet 배열이 끝났음을 의미함.
                                    break;
                                case 3: // DS Parameter
                                    info[k][0][4] = packet[i+3]; // ◀ CH 정보를 info[x][0][4]에 저장함.
                                    i=i+packet[i+2]+2;           // (CH 정보를 수집하는 이유는 랜카드에 지정한 채널 이외에서도
                                    break;                       //  간섭 등의 이유로 다른 채널의 패킷이 수집되기 때문임.)
                                case 48: // RSN Information
                                    j=1;
                                    i=i+packet[i+2]+2; // ◀ 분석 결과, WPA2 프로토콜을 사용하는 경우 해당 태그가 활성화되어 있음.
                                    break;
                                case 221: // Vendor Specific
                                    if ((packet[i+3] == 0) && (packet[i+4] == 80) && (packet[i+5] == 242)){
                                    // Microsoft Corp.
                                        if (packet[i+6] == 1) n=1; // ◀ 분석 결과, WPA 프로토콜을 사용하는 경우 해당 값이 쓰임.
                                        if (packet[i+6] == 5) n=2; // ◀ 분석 결과, WEP 프로토콜을 사용하는 경우 해당 값이 쓰임.
                                    }
                                    i=i+packet[i+2]+2;
                                    break;
                                default:
                                    i=i+packet[i+2]+2;
                                    break;
                                    // 다음 태그로 넘어가기 위해  (태그 데이터 길이 값) + (태그 넘버 정보 1byte) + (태그 데이터 길이 정보 1byte)
                            }
                        }
                    }

                    if (packet[24]==0x40){
                        info[k][0][6] = 5; // ◀ Probe Request 패킷의 경우, info[x][0][6]에 기록해둠.
                    } else if ((j==0) && (n==0)){
                        info[k][0][6] = 0; // ENC Info (OPN)
                    } else if ((j==0) && (n==1)) {
                        info[k][0][6] = 1; // ENC Info (WPA)
                    } else if ((j==1) && (n==0)) {
                        info[k][0][6] = 2; // ENC Info (WPA2)
                    } else if ((j==1) && (n==1)) {
                        info[k][0][6] = 3; // ENC Info (WPA/WPA2)
                    } else if (n==2){
                        info[k][0][6] = 4; // ENC Info (WEP)
                    } // ▲ 수집한 정보를 바탕으로, ENC 정보를 info[x][0][6]에 저장함.

                    n=0;
                    if (packet[24]==0x80) {
                        info[k][0][5]=packet[61];
                        for (i=1; i<=info[k][0][5]; i++){
                            if (packet[61+i] == 0x00){
                                n=n+1;
                            }
                        } // Beacon 패킷의 경우 Hidden SSID 인지 확인함.

                    } else {
                        info[k][0][5]=packet[49];
                        // Probe Request 패킷의 경우, Fixed Parameters 값이 존재하지 않아
                        // Tagged Parameters 값의 시작 위치가 Beacon 패킷과 다름.
                    }
                    // ▲ SSID의 길이 값 정보를 info[x][0][5]에 저장함.

                    if (info[k][0][5] == 0){ // ◀ SSID의 길이 값 정보가 0이면,
                        info[k][1][1] = '<'; //    Wildcard SSID 임.
                        info[k][1][2] = 'W';
                        info[k][1][3] = 'i';
                        info[k][1][4] = 'l';
                        info[k][1][5] = 'd';
                        info[k][1][6] = 'c';
                        info[k][2][1] = 'a';
                        info[k][2][2] = 'r';
                        info[k][2][3] = 'd';
                        info[k][2][4] = ' ';
                        info[k][2][5] = 'S';
                        info[k][2][6] = 'S';
                        info[k][3][1] = 'I';
                        info[k][3][2] = 'D';
                        info[k][3][3] = '>';
                        info[k][0][5] = 15;
                    } else if (n == info[k][0][5]){ // ◀ SSID 길이 값 정보는 존재하나,
                        info[k][1][1] = '<';        //    NULL로 채워있을 경우,
                        info[k][1][2] = 'l';        //    Hidden SSID 임.
                        info[k][1][3] = 'e';        //    ((n == 0) && (info[k][0][5] == 0))인 경우를 대비해
                        info[k][1][4] = 'n';        //     Wildcard SSID를 위에서 먼저 처리해줌.)
                        info[k][1][5] = 'g';
                        info[k][1][6] = 't';
                        info[k][2][1] = 'h';
                        info[k][2][2] = ':';
                        info[k][2][3] = ' ';
                        if (10 <= info[k][0][5]){
                            info[k][2][4] = info[k][0][5]/10+48; // number (ex 12 -> 1)
                            info[k][2][5] = info[k][0][5]%10+48; // number (ex 12 -> 2)
                            info[k][2][6] = 62; // '>'
                            info[k][0][5] = 12; // 10의 자리수이면 자리수 정보 2바이트를 사용
                        } else {                // (SSID의 최대 길이는 32바이트)
                            info[k][2][4] = info[k][0][5]+48; // number (ex 6 -> 6)
                            info[k][2][5] = 62; // >
                            info[k][0][5] = 11; // 1의 자리수이면 자리수 정보 1바이트를 사용
                        }
                        // ▲ Hidden SSID가 맞다면 SSID 정보를 재가공해서 info[k][1~2][1~6] 공간에 저장함.
                        //   SSID의 길이 값 정보가 담긴 info[x][0][5] 공간 정보를 수정해줌.

                    } else {
                        n=0;
                        for (i=1; i<=info[k][0][5]/6; i++){
                            for (j=1; j<=6; j++){
                                n=n+1;
                                if (packet[24]==0x80) {
                                    info[k][i][j] = packet[61+n];
                                } else {
                                    info[k][i][j] = packet[49+n];
                                } // Beacon인지 Probe Request인지 구분하여 추출
                            }
                        }
                        for (j=1; j<=info[k][0][5]%6; j++){
                            n=n+1;
                            if (packet[24]==0x80) {
                                info[k][i][j] = packet[61+n];
                            } else {
                                info[k][i][j] = packet[49+n];
                            } // Beacon인지 Probe Request인지 구분하여 추출
                        }
                         // ▲ 그냥 SSID의 경우, info[k][1~6][1~6] 공간에 저장함.
                    }
                }


               system("clear"); // 새롭게 그리기 위해서 일단 화면을 지움

               printf("[Before: %d.%02d.%02d. %02d:%02d:%02d]\t[Now: %d.%02d.%02d. %02d:%02d:%02d]\n",
                      tm1.tm_year+1900, tm1.tm_mon+1, tm1.tm_mday, tm1.tm_hour, tm1.tm_min, tm1.tm_sec,
                      tm2.tm_year+1900, tm2.tm_mon+1, tm2.tm_mday, tm2.tm_hour, tm2.tm_min, tm2.tm_sec);
               printf("\n"); // 해당 프로그램을 실행했을 때의 시간과, 현재 시간을 보여줌.

               printf("Number\tBSSID\t\t\tBeacon\tPWR\t#Data\tCH\tENC\t\tESSID\n");
               printf("\n"); // Beacon 패킷 내부 정보들의 명칭을 출력

               n = 0;
               for(i=1; i<=num-1; i++){ // ◀ 배열안에 쌓아둔 리스트를 모두 출력함.
                   if (info[i][0][6] != 5) { // ◀ Beacon 패킷만 처리를 해줌.
                       n=n+1;
                       printf("%d.\t",n); // 넘버를 카운트해서 출력
                       for(j=0; j<=5; j++){
                            byte2char(info[i][j][0]);
                            if (j<5) printf(":");
                       } // BSSID의 경우, byte 정보를 16진수 문자열로 바꿔서 출력함.
                         // (변환 및 출력 함수 : byte2char)

                       printf("\t%d\t-%ddBm\t%d\t%d\t",info[i][0][1], info[i][0][2], info[i][0][3] , info[i][0][4]);
                        // Beacon 패킷 갯수, PWR 정보, Data 패킷 갯수, 채널 정보를 출력함.

                       switch (info[i][0][6]) {
                            case 0:
                                printf("OPN\t\t");
                                break;
                            case 1:
                                printf("WPA\t\t");
                                break;
                            case 2:
                                printf("WPA2\t\t");
                                break;
                            case 3:
                                printf("WPA/WPA2\t");
                                break;
                            case 4:
                                printf("WEP\t\t");
                                break;
                       } // ENC 정보를 출력함.

                       for (j=1; j<=info[i][0][5]/6; j++){
                           for (k=1; k<=6; k++){
                               printf("%c",info[i][j][k]);
                           }
                       }
                       for (k=1; k<=info[i][0][5]%6; k++){
                           printf("%c",info[i][j][k]);
                       } // SSID 정보를 출력함.
                       printf("\n");
                   }
               }

               printf("\n");
               printf("Number\tSTATION\t\t\tFrames\tPWR\tProbes\n");
               printf("\n");  // Probe Request 패킷 내부 정보들의 명칭을 출력
               n=0;

               for(i=1; i<=num-1; i++){ // ◀ 배열안에 쌓아둔 리스트를 모두 출력함.
                    if (info[i][0][6] == 5){ // ◀ Probe Request 패킷만 처리를 해줌.
                        n=n+1;
                        printf("%d.\t",n); // 번호를 카운트해서 출력.
                        for(j=0; j<=5; j++){
                             byte2char(info[i][j][0]);
                             if (j<5) printf(":");
                        } // BSSID의 경우, byte 정보를 16진수 문자열로 바꿔서 출력함.
                          // (변환 및 출력 함수 : byte2char)

                        printf("\t%d\t-%ddBm\t%",info[i][0][1], info[i][0][2]);
                         // Frames 갯수, PWR 정보를 출력함.

                        for (j=1; j<=info[i][0][5]/6; j++){
                            for (k=1; k<=6; k++){
                                printf("%c",info[i][j][k]);
                            }
                        }
                        for (k=1; k<=info[i][0][5]%6; k++){
                            printf("%c",info[i][j][k]);
                        } // SSID 정보를 출력함.
                        printf("\n");
                    }
               }

            }

            usleep(35000);
            // 너무 빠르면 재미없어서 적당히 딜레이를 줌.
        }
        pcap_close(handle);
        // pcap 핸들을 닫음.

//######################### ▼ 자식 프로세스 #########################
    } else if (pid == 0) {
        char channel1='1',channel2='0';
        char command[] = "iwconfig ";
        strcat(command,dev);
        strcat(command," ch ");
        // iwconfig 명령어를 구성할 문자열

        long int first, next;
        first = (long)getppid();
        // 부모 프로세스의 초기 PID 값을 저장함.

        sleep(2);
        // 부모 프로세스에서 랜카드를 모니터 모드로 저장할 동안
        // 딜레이를 줘서, 채널 변경과 모니터 모드 변경의 충돌을 피함.

        while (true){
                next = (long)getppid();
                if (first != next) exit(0);
                // 만약 부모 프로세스의 초기 PID값과 현재 PID값이 다르면 자식 프로세스를 종료함.
                // (고아 프로세스를 막기 위함.)

                if (channel1 >= 58){
                    command[13 + strlen(dev)] = '1';
                    command[14 + strlen(dev)] = channel2;
                    channel2 = channel2 + 1;
                    if (channel2 >= 53){
                        command[14 + strlen(dev)] = 0x00;
                        channel1 = '1';
                        channel2 = '0';
                    }
                } else {
                    command[13 + strlen(dev)] = channel1;
                    channel1 = channel1 + 1;
                }
                 system(command);
                 usleep(500000);
                // 0.5초에 한번씩 iwconfig 명령어로 채널 정보를 바꿈
                // (2.4Ghz 대역 채널인 1~13번 채널 반복)
       }

        // (가지고 있는 랜카드가 2.4Ghz만 지원해서 5.8Ghz 채널 변경은 구현하지 않았음.)

        // 5.8Ghz 대역의 채널 정보는 다음과 같음.
        // A 대역 : 36, 40, 44, 48
        // B 대역 : 52, 56, 60, 64
        // C 대역 : 100, 104, 108, 112, 116, 120
        // D 대역 : 149, 153, 108, 157, 161

//######################### ▼ fork 에러 #########################
    } else {
        exit(1);
        // fork 함수가 에러났을 경우, 종료함.
    }
}
