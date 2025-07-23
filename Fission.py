# 标准库
import os
import re
import random
import ipaddress
import subprocess
import concurrent.futures

# 第三方库
import requests
from lxml import etree
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 文件配置
ips = "Fission_ip.txt"
domains = "Fission_domain.txt"
dns_result = "dns_result.txt"

# 并发数配置
max_workers_request = 20   # 并发请求数量
max_workers_dns = 50       # 并发DNS查询数量

# 生成随机User-Agent
ua = UserAgent()

# 网站配置
sites_config = {
    "site_ip138": {
        "url": "https://site.ip138.com/",
        "xpath": '//ul[@id="list"]/li/a'
    },
    "dnsdblookup": {
        "url": "https://dnsdblookup.com/",
        "xpath": '//ul[@id="list"]/li/a'
    },
    "ipchaxun": {
        "url": "https://ipchaxun.com/",
        "xpath": '//div[@id="J_domain"]/p/a'
    }
}

# 设置会话
def setup_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# 生成请求头
def get_headers():
    return {
        'User-Agent': ua.random,
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }

# 查询域名的函数，自动重试和切换网站
def fetch_domains_for_ip(ip_address, session, attempts=0, used_sites=None):
    print(f"Fetching domains for {ip_address}...")
    if used_sites is None:
        used_sites = []
    if attempts >= 3:  # 如果已经尝试了3次，终止重试
        return []

    # 选择一个未使用的网站进行查询
    available_sites = {key: value for key, value in sites_config.items() if key not in used_sites}
    if not available_sites:
        return []  # 如果所有网站都尝试过，返回空结果

    site_key = random.choice(list(available_sites.keys()))
    site_info = available_sites[site_key]
    used_sites.append(site_key)

    try:
        url = f"{site_info['url']}{ip_address}/"
        headers = get_headers()
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        html_content = response.text

        parser = etree.HTMLParser()
        tree = etree.fromstring(html_content, parser)
        a_elements = tree.xpath(site_info['xpath'])
        domains = [a.text for a in a_elements if a.text]

        if domains:
            print(f"succeed to fetch domains for {ip_address} from {site_info['url']}")
            return domains
        else:
            raise Exception("No domains found")

    except Exception as e:
        print(f"Error fetching domains for {ip_address} from {site_info['url']}: {e}")
        return fetch_domains_for_ip(ip_address, session, attempts + 1, used_sites)

# 并发处理所有IP地址
def fetch_domains_concurrently(ip_addresses):
    session = setup_session()
    domains = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_request) as executor:
        future_to_ip = {executor.submit(fetch_domains_for_ip, ip, session): ip for ip in ip_addresses}
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result:
                domains.extend(result)

    return list(set(domains))

# DNS查询函数
def dns_lookup(domain):
    print(f"Performing DNS lookup for {domain}...")
    result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
    return domain, result.stdout

# 通过域名列表获取绑定过的所有ip
def perform_dns_lookups(domain_filename, result_filename, unique_ipv4_filename):
    try:
        # 读取域名列表
        with open(domain_filename, 'r') as file:
            domains = [d.strip() for d in file.readlines() if d.strip()]
        
        if not domains:
            print("No domains to perform DNS lookup")
            return

        # 创建一个线程池并执行DNS查询
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_dns) as executor:
            results = list(executor.map(dns_lookup, domains))

        # 写入查询结果到文件
        with open(result_filename, 'a') as output_file:  # 改为追加模式
            for domain, output in results:
                output_file.write(f"--- DNS Lookup for {domain} ---\n")
                output_file.write(output + "\n\n")

        # 从结果文件中提取所有IPv4地址
        ipv4_addresses = set()
        for _, output in results:
            ipv4_addresses.update(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', output))

        # 读取现有IP（避免重复）
        existing_ips = set()
        if os.path.exists(unique_ipv4_filename):
            with open(unique_ipv4_filename, 'r') as file:
                existing_ips = {ip.strip() for ip in file if ip.strip()}

        # 检查IP地址是否为公网IP
        new_ips = set()
        for ip in ipv4_addresses:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_global and ip not in existing_ips:
                    new_ips.add(ip)
            except ValueError:
                continue
        
        # 保存新发现的IPv4地址
        if new_ips:
            print(f"Found {len(new_ips)} new IP addresses")
            with open(unique_ipv4_filename, 'a') as output_file:  # 改为追加模式
                for address in new_ips:
                    output_file.write(address + '\n')
        else:
            print("No new IP addresses found")

    except Exception as e:
        print(f"Error performing DNS lookups: {e}")

# 主函数
def main():
    print("="*50)
    print("Starting Fission Asset Discovery")
    print("="*50)
    
    # 确保文件存在
    for filename in [ips, domains, dns_result]:
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                pass
    
    # IP反查域名
    with open(ips, 'r') as ips_txt:
        ip_list = [ip.strip() for ip in ips_txt if ip.strip()]
    
    if ip_list:
        print(f"Found {len(ip_list)} IPs for domain discovery")
        domain_list = fetch_domains_concurrently(ip_list)
        
        # 读取现有域名（避免重复）
        existing_domains = set()
        if os.path.exists(domains):
            with open(domains, 'r') as f:
                existing_domains = {d.strip() for d in f if d.strip()}
        
        # 过滤新域名
        new_domains = [d for d in domain_list if d not in existing_domains]
        
        # 追加新域名到文件
        if new_domains:
            print(f"Found {len(new_domains)} new domains")
            with open(domains, 'a') as output:  # 改为追加模式
                for domain in new_domains:
                    output.write(domain + "\n")
        else:
            print("No new domains found")
    else:
        print("No IPs available for domain discovery")
    
    print("IP -> 域名 已完成")

    # 域名解析IP
    perform_dns_lookups(domains, dns_result, ips)
    print("域名 -> IP 已完成")
    
    print("="*50)
    print("Discovery process completed")
    print("="*50)

# 程序入口
if __name__ == '__main__':
    main()
