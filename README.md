1. dummy interface 추가

sudo ip link add dum0 type dummy
sudo ifconfig dum0 up

** 추가된 interface는 추후 다음과 같은 명령어로 삭제할 수 있다.
sudo ip link del dum0

2-1. packet sniping test
sudo ./pcap-test dum0 // 이후 패킷을 잡을 때 해당 dum0 인터페이스에서 패킷을 수신한다.



2-2. 패킷 전송
sudo tcpreplay -i dum0 test.gilgil.net.pcap // 이후 패킷을 잡을 때 해당 dum0 인터페이스에서 패킷을 수신한다.


0. 설치할 것.
sudo apt-get update && sudo apt-get install libpcap-dev

1. install Tcpreplay
sudo apt install tcpreplay
sudo tcpreplay -i dum0 tcp-port-80-test.gilgil.net.pcap 

2. 