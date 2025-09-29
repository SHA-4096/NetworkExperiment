import time
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
import sys
import sqlite3
import chardet
import threading
import sys
import os

charset = None
global_conn = None
begin_time = time.strftime('%Y%m%d_%H%M%S', time.localtime())
db_name = f"{begin_time}_dns_queries.db"

capture_notification_interval = 5  # 每隔5秒输出一次统计信息

# ================ 信息输出部分 =================
# 单独开一个线程每隔一段时间输出统计信息
def thr_periodic_notification():
    while True:
        time.sleep(capture_notification_interval)
        # 清屏
        print("\033c", end="")
        print(f"[*] Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
        count_query_by_dns_server()

def periodic_notification():
    thread = threading.Thread(target=thr_periodic_notification, daemon=True)
    thread.start()

# ================= 数据存储部分 =================

def init_db():
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            query_type INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def open_connection():
    global global_conn
    print("[*] Opening database connection...")
    if global_conn is None:
        global_conn = sqlite3.connect(db_name)
    print("[*] Database connection opened.")

def close_connection():
    global global_conn
    print("[*] Closing database connection...")
    if global_conn is not None:
        global_conn.close()
        global_conn = None
    print("[*] Database connection closed.")

def store_query(src_ip_in, dst_ip_in, query_type_in):
    # print("[*] Storing query in database...")
    global global_conn
    c = global_conn.cursor()
    c.execute(f'''
        INSERT INTO dns_queries (src_ip, dst_ip, query_type)
        VALUES (?, ?, ?)
    ''', (src_ip_in, dst_ip_in,  query_type_in))
    global_conn.commit()
    # print("[*] Query stored successfully.")

def count_query_by_dns_server():
    # 统计每个DNS服务器的查询次数，从高到低排序并输出
    # 单独进程，新建个连接
    local_conn = sqlite3.connect(db_name)
    c = local_conn.cursor()
    c.execute('''
        SELECT dst_ip, COUNT(*) as count
        FROM dns_queries
        GROUP BY dst_ip
        ORDER BY count DESC
    ''')
    results = c.fetchall()
    print("[+] DNS Server Query Counts:")
    for row in results:
        print(f"    {row[0]}: {row[1]} times")
    print("-" * 50)
    local_conn.close()

# ================= 数据包处理部分 =================

def packet_callback(packet):
    global charset
    # 检查包是否包含DNS层
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
    # 确保这是一个DNS查询
        if packet[DNS].qr == 0:  # qr=0表示这是一个查询
            # 获取查询类型
            query_type = str(packet[DNSQR].qtype)
            # 获取源IP和目标IP
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)
            # 存储查询到数据库并统计
            store_query(src_ip, dst_ip, query_type)

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

# 在接收到程序终止信号时关闭数据库连接
    finally:
        close_connection()
        print("[*] DNS capture stopped.")
        end_time = time.strftime('%Y%m%d_%H%M%S', time.localtime())
        print(f"[*] Begin time(local): {begin_time} | End time(local): {end_time}")
        db_name_new = f"{begin_time}-{end_time}_dns_queries.db"
        # rename
        global db_name
        tmp_name = db_name
        db_name = db_name_new
        os.rename(tmp_name, db_name_new)
        print(f"[*] Database file: {db_name}")
        count_query_by_dns_server()

if __name__ == "__main__":
    init_db()
    open_connection()
    periodic_notification()
    main()
