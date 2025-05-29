package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type rttRecord struct {
	Index int
	RTT   time.Duration
	OK    bool
}

type udpStats struct {
	Address    string
	Protocol   string
	Sent       int
	Received   int
	AvgLatency time.Duration
	LossRate   float64
	Records    []rttRecord
}

type udpResponse struct {
	Success bool
	RTT     time.Duration
	Error   error
}

// Options命令行参数
type Options struct {
	InFilePath         string
	OutFilePath        string
	OnMasqueMode       bool
	RandomPort         bool
	RandomPortsCount   int
	RepeatSend         int
	Timeout            time.Duration
	MaxConcurrency     int
	maxCidrToIPv6Count int
	IpOnly             string
}

type ProtocolData struct {
	Protocol string // 隧道协议
	HexStr   string // 要发送的hex数据
	Ports    []int
}

var (
	wireguardData = ProtocolData{
		Protocol: "WireGuard",
		HexStr:   "c401d000328cf90176000000000000001e2ee647a260512c2a063d2e32a82d8c",
		Ports: []int{854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010,
			1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156,
			7281, 7559, 8319, 8742, 8854, 8886, 2408, 500, 4500, 1701}, // WireGuard协议的端口(54个)
	}

	masquedData = ProtocolData{
		Protocol: "MASQUE",
		HexStr:   "c000000001086d41723f02c9a2c3080f92a2662173e94a00020000",
		Ports:    []int{443, 500, 1701, 4500, 4443, 8443, 8095}, // Masque协议的端口(7个)
	}
)

func main() {
	start := time.Now()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	opts := parseFlags()

	var chooseData ProtocolData
	if opts.OnMasqueMode {
		chooseData = masquedData
	} else {
		chooseData = wireguardData
	}

	var addresses []string
	ipOnly := strings.TrimSpace(opts.IpOnly)
	if ipOnly != "" {
		ipOnly := net.ParseIP(ipOnly)
		if ipOnly != nil {
			addresses = append(addresses, genIPWithPorts(ipOnly, chooseData.Ports, false)...)
		}
	} else {
		// 读取文件的数据：[IP]:PORT、IP、CIDR
		fileData, err := ReadUniqueNonEmptyLines(opts.InFilePath)
		if err != nil {
			log.Fatal("Error reading file:", err)
		}
		// 转换成[IP]:PORT
		addresses, err = GenerateIPPortCombinations(fileData, chooseData.Ports, opts.RandomPort, opts.RandomPortsCount, opts.maxCidrToIPv6Count)
		if err != nil {
			log.Fatal("Error: ", err)
		}
	}

	fmt.Printf("读取到IP:PORT地址有 %v 个.\n", len(addresses))

	// 控制并发的信号量
	semaphore := make(chan struct{}, opts.MaxConcurrency)
	// 用于接收结果的通道
	results := make(chan udpStats, len(addresses))

	for _, addr := range addresses {
		addrCopy := addr
		semaphore <- struct{}{}

		go func() {
			defer func() { <-semaphore }()

			stats := udpStats{
				Address:  addrCopy,
				Protocol: chooseData.Protocol,
				Sent:     opts.RepeatSend,
			}

			var totalRTT time.Duration
			for i := 0; i < opts.RepeatSend; i++ {
				resp := sendUDPHex(chooseData.HexStr, addrCopy, opts.Timeout)
				rec := rttRecord{Index: i + 1, RTT: resp.RTT, OK: resp.Success}
				stats.Records = append(stats.Records, rec)

				if resp.Success {
					stats.Received++
					totalRTT += resp.RTT
					// log.Printf("INFO: %s The %vth scan was successful, Average Delay: %.0fms ✅\n", addrCopy, i+1, float64(resp.RTT.Microseconds())/1000)
				} else {
					log.Printf("WARN: %s The %vth scan failed. ❌\n", addrCopy, i+1)
				}
			}

			if stats.Received > 0 {
				stats.AvgLatency = totalRTT / time.Duration(stats.Received)
			}
			stats.LossRate = float64(stats.Sent-stats.Received) / float64(stats.Sent) * 100
			results <- stats
		}()
	}

	// 收集所有结果
	var allStats []udpStats
	for i := 0; i < len(addresses); i++ {
		stat := <-results
		allStats = append(allStats, stat)
		packageTag := "UDP"
		if strings.ToUpper(chooseData.Protocol) == "MASQUE" {
			packageTag = "QUIC"
		}
		if stat.Received > 0 {
			log.Printf("INFO: Received %v/%v %s Packets from %s, Average Delay: %.0fms ✅\n",
				stat.Received, stat.Sent, packageTag, stat.Address, float64(stat.AvgLatency.Microseconds())/1000)
		}
	}

	// 排序（先排序丢包率，然后排序延迟）
	sort.Slice(allStats, func(i, j int) bool {
		if allStats[i].LossRate == allStats[j].LossRate {
			return allStats[i].AvgLatency < allStats[j].AvgLatency
		}
		return allStats[i].LossRate < allStats[j].LossRate
	})

	// 导出 CSV
	err := ExportCSV(opts.OutFilePath, allStats, opts.RepeatSend)
	elapsed := time.Since(start)
	if err != nil {
		fmt.Printf("导出 CSV 失败: %v，耗时：%v\n", err, elapsed)
	} else {
		fmt.Printf("结果已导出到 %s，耗时：%v\n", opts.OutFilePath, elapsed)
	}
}

func parseFlags() *Options {
	opts := &Options{}
	randPorts := "randPorts"
	reqCount := "req"

	flag.StringVar(&opts.InFilePath, "f", "ips-v4.txt", "输入文件，内容格式：IP、[IP]:PORT、IPv4 CIDR、IPv6 CIDR")
	flag.StringVar(&opts.OutFilePath, "o", "result.csv", "输出文件")
	flag.BoolVar(&opts.OnMasqueMode, "masque", false, "默认是WireGuard模式扫描，添加该参数就开启MASQUE模式扫描")
	flag.BoolVar(&opts.RandomPort, "randPort", false, "从内置的端口中随机选择一个端口，添加该参数就随机选择一个端口")
	flag.IntVar(&opts.RandomPortsCount, randPorts, 10, "从内置的端口中随机一定数量的端口，randPort参数权限高于它(最大值：WireGuard协议为54/Masque协议为7)")
	flag.IntVar(&opts.RepeatSend, reqCount, 4, "每个IP:PORT发送多少次请求")
	flag.DurationVar(&opts.Timeout, "timeout", 500*time.Millisecond, "UDP响应的最大时间，必须带单位ms、s，不写单位就默认为ns(如：500ms、1s、2s、3s)")
	flag.IntVar(&opts.MaxConcurrency, "task", 200, "控制并发的任务数")
	flag.IntVar(&opts.maxCidrToIPv6Count, "v6Count", 500, "每个IPv6 CIDR最多取样多少个IPv6地址")
	flag.StringVar(&opts.IpOnly, "ip", "", "单独扫描指定IP地址(不带端口)的WireGuard或MASQUE情况")

	// 解析参数
	flag.Parse()

	if opts.RepeatSend < 1 || opts.RepeatSend > 4 {
		log.Fatalf("Error: -%s 发送次数在 [1, 4] 区间", reqCount)
	}

	return opts
}

// 用于读取ips-v4.txt文件的IPv4 CIDR、IPv6 CIDR、IP、[IP]:PORT
func ReadUniqueNonEmptyLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	uniqueLines := make(map[string]struct{})
	reader := bufio.NewScanner(file)

	for reader.Scan() {
		line := reader.Text()
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if _, exists := uniqueLines[line]; !exists {
			lines = append(lines, line)
			uniqueLines[line] = struct{}{}
		}
	}

	if err := reader.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func GenerateIPPortCombinations(cidrs []string, bigPorts []int, randomOne bool, randomMore int, maxCidrToIPv6Count int) ([]string, error) {
	ipPortRegex := regexp.MustCompile(`^((\d{1,3}\.){3}\d{1,3}:\d+|\[([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]:\d+)$`)
	var results []string

	for _, cidr := range cidrs {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			// （不需要添加端口）IPv4:PORT 或 [IPv6]:PORT
			if ipPortRegex.MatchString(cidr) {
				results = append(results, cidr)
				continue // 不要删掉它
			}
			// （需要添加端口）纯IPv4地址或纯IPv6地址
			ipOnly := net.ParseIP(cidr)
			if ipOnly != nil {
				ports := sample(bigPorts, randomMore)
				results = append(results, genIPWithPorts(ipOnly, ports, randomOne)...)
			}
			continue // 不要删掉它
		}

		if ip.To4() != nil {
			// IPv4 CIDR
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
				if isNetworkOrBroadcast(ip, ipnet) {
					continue
				}
				ports := sample(bigPorts, randomMore)
				ipCopy := cloneIP(ip) // 避免在循环中直接修改原始 IP 对象，如果不拷贝，会污染原始数据
				results = append(results, genIPWithPorts(ipCopy, ports, randomOne)...)
			}
		} else {
			// IPv6 CIDR
			base := ip.Mask(ipnet.Mask)
			prefixLen, _ := ipnet.Mask.Size()
			maskBits := 128 - prefixLen
			ipv6Set := make(map[string]struct{})
			for len(ipv6Set) < maxCidrToIPv6Count {
				randSuffix, err := randomIPv6Suffix(maskBits)

				if err != nil {
					return nil, fmt.Errorf("failed to generate random IPv6: %v", err)
				}
				randomIP := applySuffix(base, randSuffix)
				if !ipnet.Contains(randomIP) {
					continue
				}
				ipStr := randomIP.String()
				if _, exists := ipv6Set[ipStr]; exists {
					continue
				}
				ipv6Set[ipStr] = struct{}{}
				ports := sample(bigPorts, randomMore)
				randomIP = cloneIP(randomIP) // 防止底层数组被共享，污染原始数据
				results = append(results, genIPWithPorts(randomIP, ports, randomOne)...)
			}
		}
	}

	shuffle(results)
	return results, nil
}

// 拷贝数据，避免直接修改原始 IP 对象，污染原始数据
func cloneIP(ip net.IP) net.IP {
	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)
	return ipCopy
}

// IP 拼接逻辑
func formatIPPort(ip net.IP, port int) string {
	if ip.To4() != nil {
		return fmt.Sprintf("%s:%d", ip.String(), port)
	}
	return fmt.Sprintf("[%s]:%d", ip.String(), port)
}

func genIPWithPorts(ip net.IP, ports []int, randomOne bool) []string {
	var results []string
	if randomOne {
		port := ports[rand.Intn(len(ports))]
		results = append(results, formatIPPort(ip, port))
	} else {
		for _, port := range ports {
			results = append(results, formatIPPort(ip, port))
		}
	}
	return results
}

// 将 IPv4 地址加一
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 判断是否为网络地址或广播地址（适用于IPv4）
func isNetworkOrBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	mask := ipnet.Mask
	network := ip.Mask(mask)
	broadcast := make(net.IP, len(network))
	for i := range broadcast {
		broadcast[i] = network[i] | ^mask[i]
	}
	return ip.Equal(network) || ip.Equal(broadcast)
}

// 泛型 shuffle 函数，支持任何类型的切片
func shuffle[T any](slice []T) {
	for i := len(slice) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}

// 随机从切片中抽取 n 个（若不足 n 个就返回全部）
func sample(slice []int, n int) []int {
	if n >= len(slice) {
		return append([]int(nil), slice...)
	}
	shuffle(slice)
	perm := rand.Perm(len(slice))
	result := make([]int, n)
	for i := 0; i < n; i++ {
		result[i] = slice[perm[i]]
	}

	return result
}

// 生成一个指定长度的随机 IPv6 后缀（低 maskBits 位随机）
func randomIPv6Suffix(maskBits int) ([]byte, error) {
	numBytes := (maskBits + 7) / 8
	randBytes := make([]byte, 16)
	_, err := crand.Read(randBytes[16-numBytes:])
	if err != nil {
		return nil, err
	}
	return randBytes, nil
}

// 应用随机后缀到前缀上
func applySuffix(base net.IP, suffix []byte) net.IP {
	result := make(net.IP, 16)
	copy(result, base.To16())
	for i := 0; i < len(suffix); i++ {
		result[16-len(suffix)+i] |= suffix[i]
	}
	return result
}

// 发送单个 UDP 并记录 RTT
func sendUDPHex(hexStr string, addr string, timeout time.Duration) udpResponse {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return udpResponse{false, 0, fmt.Errorf("hex 解码失败: %v", err)}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return udpResponse{false, 0, fmt.Errorf("地址解析失败: %v", err)}
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return udpResponse{false, 0, fmt.Errorf("连接失败: %v", err)}
	}
	defer conn.Close()

	start := time.Now()

	_, err = conn.Write(data)
	if err != nil {
		return udpResponse{false, 0, fmt.Errorf("发送失败: %v", err)}
	}

	conn.SetReadDeadline(start.Add(timeout))

	buffer := make([]byte, 1024)
	_, _, err = conn.ReadFromUDP(buffer)
	if err != nil {
		return udpResponse{false, 0, nil} // 读取失败视为丢包
	}

	rtt := time.Since(start)
	return udpResponse{true, rtt, nil}
}

func ExportCSV(filename string, stats []udpStats, repeat int) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	header := []string{"IP地址", "隧道协议", "已发送", "已接收", "丢包率", "平均延迟(ms)"}
	for i := 1; i <= repeat; i++ {
		header = append(header, fmt.Sprintf("RTT%d(ms)", i))
	}
	writer.Write(header)

	// 写入每行数据
	for _, s := range stats {
		avgLatencyFloat := float64(s.AvgLatency.Microseconds()) / 1000
		avgLatency := fmt.Sprintf("%.0f", avgLatencyFloat)
		if avgLatency == "0" {
			avgLatency = "-1"
		}
		row := []string{
			s.Address,
			s.Protocol,
			strconv.Itoa(s.Sent),
			strconv.Itoa(s.Received),
			fmt.Sprintf("%.0f%%", s.LossRate),
			avgLatency,
		}
		for _, r := range s.Records {
			if r.OK {
				row = append(row, fmt.Sprintf("%.0f", float64(r.RTT.Microseconds())/1000))
			} else {
				row = append(row, "-1")
			}
		}
		writer.Write(row)
	}
	return nil
}
