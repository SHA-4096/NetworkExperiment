#!/usr/bin/env python3
from scapy.all import *

def send_dns_query(interface, domain, dns_server="8.8.8.8"):
    """
    发送DNS查询请求
    
    参数:
    interface: 使用的网络接口名称
    domain: 要查询的域名
    dns_server: DNS服务器IP地址（默认使用Google DNS 8.8.8.8）
    """
    
    # 构造DNS查询包
    dns_query = IP(dst=dns_server)/\
                UDP(dport=53)/\
                DNS(rd=1, qd=DNSQR(qname=domain))
    
    try:
        # 通过指定接口发送数据包并等待响应
        answer = sr1(dns_query, iface=interface, timeout=2, verbose=False)
        
        if answer:
            # 如果收到响应，解析并打印结果
            if answer.haslayer(DNS):
                dns_response = answer[DNS]
                print(f"\n查询结果 - {domain}:")
                
                # 遍历所有答案记录
                for i in range(dns_response.ancount):
                    rdata = dns_response.an[i].rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode()
                    print(f"IP地址: {rdata}")
        else:
            print("未收到响应")
            
    except Exception as e:
        print(f"发生错误: {e}")

if __name__ == "__main__":
    # 设置网络接口名称（在Linux中可能是eth0、wlan0等，在Windows中可能是Ethernet等）
    INTERFACE = "eth0"  # 根据实际情况修改接口名称
    
    # 要查询的域名
    DOMAIN = "example.com"
    
    # 发送DNS查询
    send_dns_query(INTERFACE, DOMAIN, dns_server="1.1.1.1")
