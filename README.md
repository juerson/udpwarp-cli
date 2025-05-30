# udpwarp-cli

基于UDP的Cloudflare WARP可用Endpoint扫描，支持WARP的WireGuard和Masque两种不同的隧道协议方式的扫描。

### CLI

执行命令：`udpwarp-cli-*.exe -h`

```bash
Usage of udpwarp-cli-*.exe:
  -f string
        输入文件，内容格式：IP、[IP]:PORT、IPv4 CIDR、IPv6 CIDR (default "ips-v4.txt")
  -ip string
        单独扫描指定IP地址(不带端口)的WireGuard或MASQUE情况
  -masque
        默认是WireGuard模式扫描，添加该参数就开启MASQUE模式扫描
  -o string
        输出文件 (default "result.csv")
  -randPort
        从内置的端口中随机选择一个端口，添加该参数就随机选择一个端口
  -randPorts int
        从内置的端口中随机一定数量的端口，randPort参数权限高于它(最大值：WireGuard协议为54/Masque协议为7) (default 10)
  -req int
        每个IP:PORT发送多少次请求 (default 4)
  -task int
        控制并发的任务数 (default 200)
  -timeout duration
        UDP响应的最大时间，必须带单位ms、s，不写单位就默认为ns(如：500ms、1s、2s、3s) (default 500ms)
  -v6Count int
        每个IPv6 CIDR最多取样多少个IPv6地址 (default 500)
```
### 特殊说明

###### 1、参数`-f`：

输入的文件支持**IPv4/IPv6、IPv4:PORT、[IPv6]:PORT、IPv4 CIDR、IPv6 CIDR**。

**注意：**

- IPv4 CIDR是**全部IP都生成**的。

- IPv6地址的扫描，需要自身**有IPv6地址的网络**才能使用。

- IPv6 CIDR生成IPv6地址的数量由`-v6Count`参数决定，默认是500个。

- 如果IPv6 CIDR的前缀长度比较小，可以选择性修改它，只随机后面几段（以免浪费扫描时间和无意义的扫描）。

  如下，只随机右边三段，前面的不变。

2606:4700:d1::/48 -> 2606:4700:d1::/80

```txt
2606:4700:d1::71ae:9fac:b719
2606:4700:d1::8d5a:bc5:856b
2606:4700:d1::c14f:6715:3fe1
```

###### 2、参数`-ip`：

该参数只能传入IPv4地址或IPv6地址，**不能带端口，也不能传入CIDR**。

###### 3、参数`-req`：

这个参数类似`ping 1.1.1.1 -n 5`，要发送的回显请求数5。

### 注意

扫描结果是否可用，还要实际使用。有的Endpoint，无丢包的无法使用，有丢包的可能可以使用，扫描的结果仅供参考。

**免责声明**： 本工具与 Cloudflare 无关，也未得到其认可。请负责任地使用并遵守其服务条款。
