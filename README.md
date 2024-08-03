# Ubuntu | OpenVPN Kurulumu


![openvpn-logo](https://github.com/user-attachments/assets/7e6785c1-aca8-439a-a502-ef7001ccd0c3)

OpenVPN, tam özellikli bir SSL VPN'dir (sanal özel ağ). SSL/TLS protokolünü kullanarak OSI katman 2 veya 3 güvenli ağ uzantısını uygular. Açık kaynaklı bir yazılımdır ve GNU GPL altında dağıtılmaktadır. Bir VPN, havalimanındaki veya oteldeki wifi ağı gibi güvenli olmayan bir genel ağa güvenli bir şekilde bağlanmanıza olanak tanır. VPN, kurumsal veya kurumsal veya ev sunucusu kaynaklarınıza erişmek için de gereklidir. Coğrafi olarak engellenen siteyi atlayabilir ve çevrimiçi gizliliğinizi veya güvenliğinizi artırabilirsiniz. 

## Kurulum Adımları


Aşağıdaki komutu terminalimizde çalıştıralım:

```
wget https://git.io/vpn -O openvpn-install.sh
```

Nano komutu veya vim komutu gibi bir metin düzenleyici kullanarak komut dosyasını doğrulayabiliriz:

```
nano openvpn-install.sh
```

### OpenVPN sunucusunu kurmak için openvpn-install.sh çalıştırma

Aşağıdaki komutu yazın:

Gerekli bilgileri sağladığınızdan emin olun:

```
sudo chmod +x openvpn-install.sh
sudo bash openvpn-install.sh
```

```
Welcome to this OpenVPN road warrior installer!

Which protocol should OpenVPN use?
   1) UDP (recommended)
   2) TCP
Protocol [1]: 1

What port should OpenVPN listen to?
Port [1194]: 

Select a DNS server for the clients:
   1) Current system resolvers
   2) Google
   3) 1.1.1.1
   4) OpenDNS
   5) Quad9
   6) AdGuard
DNS server [1]: 2

Enter a name for the first client:
Name [client]: iphone

OpenVPN installation is ready to begin.
Press any key to continue...
```

[Enter] tuşu gibi herhangi bir tuşa bastığınızda şunları göreceksiniz:

```
writing new private key to '/etc/openvpn/server/easy-rsa/pki/easy-rsa-1768.FjG9Gr/tmp.vQL9q8'
-----
Using configuration from /etc/openvpn/server/easy-rsa/pki/easy-rsa-1768.FjG9Gr/tmp.FiauWW
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
commonName            :ASN.1 12:'server'
Certificate is to be certified until Dec  7 09:22:17 2030 GMT (3650 days)

Write out database with 1 new entries
Data Base Updated

Using SSL: openssl OpenSSL 1.1.1f  31 Mar 2020
Generating a RSA private key
....................................+++++
...................+++++
writing new private key to '/etc/openvpn/server/easy-rsa/pki/easy-rsa-1843.4USwJm/tmp.lOecLW'
-----
Using configuration from /etc/openvpn/server/easy-rsa/pki/easy-rsa-1843.4USwJm/tmp.5j0n6q
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
commonName            :ASN.1 12:'iphone'
Certificate is to be certified until Dec  7 09:22:17 2030 GMT (3650 days)

Write out database with 1 new entries
Data Base Updated

Using SSL: openssl OpenSSL 1.1.1f  31 Mar 2020
Using configuration from /etc/openvpn/server/easy-rsa/pki/easy-rsa-1899.k6zZtP/tmp.riZi2R

An updated CRL has been created.
CRL file: /etc/openvpn/server/easy-rsa/pki/crl.pem


Created symlink /etc/systemd/system/multi-user.target.wants/openvpn-iptables.service → /etc/systemd/system/openvpn-iptables.service.
Created symlink /etc/systemd/system/multi-user.target.wants/openvpn-server@server.service → /lib/systemd/system/openvpn-server@.service.

Finished!

The client configuration is available in: /root/iphone.ovpn
New clients can be added by running this script again.
```


### Ubuntu Güvenlik Duvarı Kurallarında OpenVPN

Hepsi bu. OpenVPN sunucunuz yapılandırıldı ve kullanıma hazır. Eklenen güvenlik duvarı kuralları dosyasını görebilirsiniz:

Örnek kurallar. Lütfen bunları düzenlemeyin: `/etc/systemd/system/openvpn-iptables.service`

```
sudo systemctl cat openvpn-iptables.service
```
```

[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to 172.105.102.90
ExecStart=/usr/sbin/iptables -I INPUT -p udp --dport 1194 -j ACCEPT
ExecStart=/usr/sbin/iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=/usr/sbin/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/usr/sbin/iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to 172.105.102.90
ExecStop=/usr/sbin/iptables -D INPUT -p udp --dport 1194 -j ACCEPT
ExecStop=/usr/sbin/iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=/usr/sbin/iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStart=/usr/sbin/ip6tables -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to 2600:3c04::f03c:92ff:fe42:3d72
ExecStart=/usr/sbin/ip6tables -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=/usr/sbin/ip6tables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/usr/sbin/ip6tables -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to 2600:3c04::f03c:92ff:fe42:3d72
ExecStop=/usr/sbin/ip6tables -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=/usr/sbin/ip6tables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
```

Komut dosyası tarafından oluşturulan openvpn sunucu yapılandırma dosyanızı aşağıdaki gibi görüntüleyebilirsiniz (bu dosyayı elle düzenlemeyin çünkü bu sizin için işleri bozacaktır):

Örnek openvpn yapılandırması:

```
local 172.105.102.90
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0
server-ipv6 fddd:1194:1194:1194::/64
push "redirect-gateway def1 ipv6 bypass-dhcp"
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem
explicit-exit-notify
```

### OpenVPN sunucusunu nasıl başlatırım/durdururum/yeniden başlatırım?


```
sudo systemctl stop openvpn-server@server.service
sudo systemctl start openvpn-server@server.service
sudo systemctl restart openvpn-server@server.service
```

```
sudo systemctl status openvpn-server@server.service
openvpn-server@server.service - OpenVPN service for server
     Loaded: loaded (/lib/systemd/system/openvpn-server@.service; enabled; vendor preset: enabled)
     Active: active (running) since Wed 2020-12-09 09:22:18 UTC; 7min ago
       Docs: man:openvpn(8)
             https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
             https://community.openvpn.net/openvpn/wiki/HOWTO
   Main PID: 2017 (openvpn)
     Status: "Initialization Sequence Completed"
      Tasks: 1 (limit: 4610)
     Memory: 1.2M
     CGroup: /system.slice/system-openvpn\x2dserver.slice/openvpn-server@server.service
             └─2017 /usr/sbin/openvpn --status /run/openvpn-server/status-server.log --status-version 2 --suppress-timestamps --config server.conf

Dec 09 09:22:18 nixcraft-ubuntu-vm openvpn[2017]: Socket Buffers: R=[212992->212992] S=[212992->212992]
Dec 09 09:22:18 nixcraft-ubuntu-vm openvpn[2017]: UDPv4 link local (bound): [AF_INET]172.105.102.90:1194
Dec 09 09:22:18 nixcraft-ubuntu-vm openvpn[2017]: UDPv4 link remote: [AF_UNSPEC]
Dec 09 09:22:18 nixcraft-ubuntu-vm openvpn[2017]: GID set to nogroup
Dec 09 09:22:18 nixcraft-ubuntu-vm openvpn[2017]: UID set to nobody
Dec 09 09:22:18 nixcraft-ubuntu-vm openvpn[2017]: MULTI: multi_init called, r=256 v=256
Dec 09 09:22:18 nixcraft-ubuntu-vm openvpn[2017]: IFCONFIG POOL IPv6: (IPv4) size=252, size_ipv6=65536, netbits=64, base_ipv6=fddd:1194:1194:1194::1000
Dec 09 09:22:18 nixcraft-ubuntu-vm openvpn[2017]: IFCONFIG POOL: base=10.8.0.2 size=252, ipv6=1
Dec 09 09:22:18 nixcraft-ubuntu-vm openvpn[2017]: IFCONFIG POOL LIST
```



### OpenVPN istemci yapılandırması

Sunucuda ~/iphone.ovpn (veya kurulum sırasında verilen ad ne olursa olsun) adlı bir istemci yapılandırma dosyası bulacaksınız. OpenVPN yapılandırma dosyasını bulmak için find komutunu kullanın:

Şimdi, tek yapmanız gereken scp'yi kullanarak bu dosyayı yerel masaüstünüze kopyalamak ve bağlanmak için bu dosyayı OpenVPN istemcinize sağlamaktır (kurulumunuza göre iphone.ovpn ve root kullanıcı adını değiştirin):

Eğer scp komutunu root olarak çalıştıramıyorsanız, sunucunuzda normal bir kullanıcı olarak oturum açın. Örneğin:

Sunucudaki opvn dosyasının konumunu bulun:

```
sudo find / -type f -name "iphone.ovpn"
sudo find / -type f -name "*.ovpn" -ls
```

Dosyayı isterseniz SCP ile isterseniz FTP ile kendi cihazını üzerine çekebilirsiniz.

### Test

![image](https://github.com/user-attachments/assets/c2881490-6e1f-4ff9-913c-d7448e2d9b5d)

Sunucumuz başarılı bir şekilde çalıştı.
