# Network-Multiplexor
基于WinTAP和NPcap实现的一个小型虚拟交换机/虚拟路由器，在Windows系统上将本机流量重新路由至多个出口网卡进行多网络的链路聚合，最后实现多网络多线程下载的加速

## 工作原理

程序在用户空间可以通过WinTAP提供的接口从内核中获取本机数据链路层发出的流量，解析出地址、端口等信息后，根据出口网卡的实际物理信息重新封包（若为TCP流量则再记录下连接状态和出口网卡），再调用NPcap的NPF驱动接口直接驱动底层网卡转发数据包。

![image](https://github.com/user-attachments/assets/45b5bfb0-23b8-4204-b4d7-a2c6b46c1bb8)

## 测试效果

使用某个公共WiFi + 100M有线宽带 + 手机5G网络共享 三网卡叠加链路聚合测试：

![image](https://github.com/user-attachments/assets/225d55e4-bcea-490d-834b-cd8064026310)

![b5339fc7f9f0439494d5e15815dae08a](https://github.com/user-attachments/assets/49f5518e-a4dc-4057-a80e-a67c5ee59e64)


## 使用方式

### 0.自行编译软件或使用Release编译好的程序

### 1.安装TAP虚拟网卡，并将该虚拟网卡改名为 `mix-tap`

在`tap_driver`目录下运行`install.bat`创建一个tap虚拟网卡，转到控制面板网络连接页面，将新创建出来的某个TAP-Windows Adapter V9网卡重命名为`mix-tap`

![image](https://github.com/user-attachments/assets/fc52d102-a1aa-48fc-af17-703d3e3516c7)

### 2.安装NPcap驱动

https://npcap.com/dist/npcap-1.80.exe

安装成功后可以看到网络适配器多了个NPCAP的驱动

![image](https://github.com/user-attachments/assets/d50654a0-dd2b-4263-ae69-3cd17fde16b5)

### 3.设置出口网卡

命令行窗口中传入-s参数调用程序扫描可用的出口网卡：

![image](https://github.com/user-attachments/assets/f3ae29f0-fe64-4908-840c-93937617adcb)

![image](https://github.com/user-attachments/assets/8b9c83f3-6cf2-4058-9ebe-c39ee2d95db6)

编辑`config.ini`配置文件，该配置文件和程序本体放一起：

[outbound]字段中填写出口网卡的ID，自行按自己要使用的出口网卡的个数往后扩展dev数量。

[inbound]字段中ip为虚拟tap网卡的ip，gateway为虚拟路由器的ip，若这两个ip和现有物理网络上的ip发生冲突，需要自行修改。

一个`config.ini`例子如下

```
[inbound]
ip=192.168.57.123
gateway=192.168.57.0
mask=255.255.255.0

[outbound]
dev0={6DAF227D-8AF7-4F2D-B45C-AE1382CC8A35}
dev1={0A035B6A-A5E8-427A-A3F4-22292CDBA7E1}
dev2={4C15831D-D0B2-4F8D-ABEA-AD0F7F04254D}
```

### 4.启动程序

程序正常运行后会显示虚拟网卡和出口网卡的流量信息：

![fde49365d87068b9654c92bd2cd1776b](https://github.com/user-attachments/assets/3053a9bc-5a59-4419-a50e-f04909af122e)



