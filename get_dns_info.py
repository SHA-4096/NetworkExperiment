import sqlite3
import sys

def count_query_by_dns_server(db_name):
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
        print(f"    {row[0]}: \t{row[1]} times")
    print("-" * 50)
    local_conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <database_file>")
        sys.exit(1)
    db_name = sys.argv[1]
    count_query_by_dns_server(db_name)