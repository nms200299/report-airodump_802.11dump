# 802.11.dump
● BoB 9기 공통교육 네트워크 과제

● airodump-ng와 비슷한 출력을 할 수 있는 프로그램임.

## 기능
● 랜카드 Monitor Mode (모니터 모드) 자동 전환

● 2.4Ghz 대역에 대한 Channel Hopping (채널 변경) 기능

(채널 1~13번까지 순회)

● Beacon 패킷을 분석하여 ESSID, Beacon Count, PWR, #Data Count, CH, ENC, ESSID 정보를 출력함.

● Probe Request 패킷을 분석하여 Station Mac, Frames Count, PWR, Probs(SSID) 정보를 출력함.


## 사용법
![802 11 dump_ex](https://user-images.githubusercontent.com/12112214/106164576-755ab180-61cd-11eb-97b3-ba6bd2c839d5.png)

    ./802.11dump [랜카드 이름]

## 예시
![802 11 dump](https://user-images.githubusercontent.com/12112214/106185759-95e33580-61e6-11eb-8a7c-7057a3ab7c50.png)

## airodump-ng와 비교
![airodump](https://user-images.githubusercontent.com/12112214/106185758-94b20880-61e6-11eb-99c2-1d38846ccb20.png)
