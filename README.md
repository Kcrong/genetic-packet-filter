# genetic-packet-filter
유전 알고리즘을 이용한 패킷 필터링

유전 알고리즘을 이용해, 패킷 필터링 규칙이 점점 발달하고 있음을 볼 수 있습니다.

test packet info:
Client -> 192.168.44.1
Server -> 192.168.44.129
Protocol -> Telnet (port 23)

Best Rule at Generation 1:  
Rule: ip dst 192.168.44.129 and not dst port 23 -> -51  
// 도착지 아이피와 공격이 들어온 23번 포트를 Block  

Best Rule at Generation 2:  
Rule: ip dst 192.168.44.129 and not src port 23 and dst port 58634 -> -51  
// 도착지 아이피와 클라이언트가 접속한 58634 포트, telnet 포트가  Block  

Best Rule at Generation 3:  
Rule: ip dst 192.168.44.129 and src port 23 -> -51  
// 서버 아이피와 Telnet 포트가 Block  

Best Rule at Generation 4:  
Rule: ip src 192.168.44.1  and ip dst 192.168.44.129 -> -51  
// 클라이언트 아이피와 서버 아이피가 Block  

Best Rule at Generation 5:  
Rule: ip src 192.168.44.1  and ip dst 192.168.44.129 and dst port 23 -> -51  
// 클라이언트 아이피와 서버 아이피, telnet 포트가 Block  

현재는 IP, PORT 기반으로 Feature를 뽑아냈으나, 학습시키는 공격패킷과 테스트 용 일반패킷의 크기를 늘리고 Feature 의 종류를 늘리면 더 좋은 결과가 기대됨
