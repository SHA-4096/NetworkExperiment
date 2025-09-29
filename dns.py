from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
import sys
import sqlite3
import chardet

charset = None

# ================= 数据存储部分 =================

def init_db():
    conn = sqlite3.connect('dns_queries.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            query_name TEXT,
            query_type INTEGER
        )
    ''')
    conn.commit()
    conn.close()


def store_query(src_ip_in, dst_ip_in, query_name_in, query_type_in):
    print("[*] Storing query in database...")
    conn = sqlite3.connect('dns_queries.db')
    c = conn.cursor()
    c.execute(f'''
        INSERT INTO dns_queries (src_ip, dst_ip, query_name, query_type)
        VALUES (?, ?, ?, ?)
    ''', (src_ip_in, dst_ip_in, query_name_in, query_type_in))
    conn.commit()
    print("[*] Query stored successfully.")
    conn.close()

def count_query_by_dns_server():
    # 统计每个DNS服务器的查询次数，从高到低排序并输出
    conn = sqlite3.connect('dns_queries.db')
    c = conn.cursor()
    c.execute('''
        SELECT dst_ip, COUNT(*) as count
        FROM dns_queries
        GROUP BY dst_ip
        ORDER BY count DESC
    ''')
    results = c.fetchall()
    conn.close()
    print("\n[+] DNS Server Query Counts:")
    for row in results:
        print(f"    {row[0]}: {row[1]} times")
    print("-" * 50)

# ================= 数据包处理部分 =================

def packet_callback(packet):
    global charset
    # 检查包是否包含DNS层
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
    # 确保这是一个DNS查询
        if packet[DNS].qr == 0:  # qr=0表示这是一个查询
            # 获取查询的域名
            if charset is None:
                detected = chardet.detect(packet[DNSQR].qname)
                charset = detected['encoding'] if detected['encoding'] else 'utf-8'
                print(f"[*] Detected charset: {charset}")
            query_name = str(packet[DNSQR].qname.decode())
            # 获取查询类型
            query_type = str(packet[DNSQR].qtype)
            # 获取源IP和目标IP
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)

            print(f"[*] DNS Query:")
            print(f"    Source IP: {src_ip}")
            print(f"    Destination IP: {dst_ip}")
            print(f"    Query Name: {query_name}")
            print(f"    Query Type: {query_type}")
            print("-" * 50)
            # 存储查询到数据库并统计
            store_query(src_ip, dst_ip, query_name, query_type)
            count_query_by_dns_server()

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        print("Example: python script.py eth0")
        sys.exit(1)

    interface = sys.argv[1]
    print(f"[*] Starting DNS traffic capture on interface {interface}")
    print("[*] Press CTRL+C to stop")
    
    try:
        # 开始抓包，过滤DNS流量（端口53），并调用回调函数
        sniff(iface=interface,
              filter="port 53",
              prn=packet_callback,
              store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping DNS capture...")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    init_db()
    main()
