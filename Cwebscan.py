#!/usr/bin/env python
# coding:utf-8
# Author: se55i0n
# c段web应用信息扫描工具

import IPy
import sys
import argparse
import time
import socket
import aiohttp
import importlib
import dns.resolver
import asyncio
import urllib3
from Tools.scripts.objgraph import ignore
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

importlib.reload(sys)
urllib3.disable_warnings(InsecureRequestWarning)

class Scanner(object):
    def __init__(self, target, threads, custom_ports):
        self.W = '\033[0m'
        self.G = '\033[1;32m'
        self.O = '\033[1;33m'
        self.R = '\033[1;31m'
        self.custom_ports = custom_ports
        self.server = target
        self.result = []
        self.ips = []
        self.time = time.time()
        self.threads = threads
        self.target = self.handle_target()
        self.get_ip_addr()

    def handle_target(self):
        # 处理给定扫描目标
        try:
            if int(self.server.split('.')[-1]) >= 0:
                return '.'.join(self.server.split('.')[:3]) + '.0/24'
        except:
            if not self.check_cdn():
                return '.'.join(i for i in socket.gethostbyname(self.server).split('.')[:3]) + '.0/24'
            else:
                print(u'{}[-] 目标使用了CDN, 停止扫描...{}'.format(self.R, self.W))
                sys.exit(1)

    def check_cdn(self):
        # cdn检测
        myResolver = dns.resolver.Resolver()
        myResolver.lifetime = myResolver.timeout = 2.0
        dnsserver = [['114.114.114.114'], ['8.8.8.8'], ['223.6.6.6']]
        try:
            for i in dnsserver:
                myResolver.nameservers = i
                record = myResolver.resolve(self.server)  # 使用 resolve 替换 query
                self.result.append(record[0].address)
        except Exception as e:
            pass
        finally:
            return True if len(set(list(self.result))) > 1 else False

    def get_ip_addr(self):
        # 获取目标c段ip地址
        for ip in IPy.IP(self.target):
            self.ips.append(ip)

    async def get_info(self, ip, port):
        try:
            url = f'http://{ip}:{port}'
            headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3)'}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=1, ssl=False) as res:
                    serv = res.headers.get('Server', '').split()[0] if 'Server' in res.headers else ''
                    content = await res.read()
                    title = BeautifulSoup(content, 'lxml').title.text.strip('\n').strip() if content else 'No title'
                    result = f'{self.G}[+] {url.ljust(28)} {str(res.status).ljust(6)} {serv.ljust(24)} {title}{self.W}'
                    print(result)
        except Exception:
            ignore

    async def start(self, ip):
        # 自定义扫描端口使用协程进行处理
        if self.custom_ports:
            tasks = []
            for port in self.custom_ports.split(','):
                tasks.append(self.get_info(ip, port))
            await asyncio.gather(*tasks)
        else:
            await self.get_info(ip, 80)

    async def run(self):
        # 使用 asyncio 来处理任务
        try:
            tasks = [self.start(ip) for ip in self.ips]  # 创建所有扫描任务
            print("Starting scan for all IPs...")
            await asyncio.gather(*tasks)  # 异步执行
            print('-' * 90)
            print(u'{}[-] 扫描完成耗时: {} 秒.{}'.format(self.O, time.time() - self.time, self.W))
        except Exception as e:
            print(f"Error in run: {e}")
        except KeyboardInterrupt:
            print(u'\n[-] 用户终止扫描...')
            sys.exit(1)

def banner():
    banner = '''
   ______              __
  / ____/      _____  / /_  ______________ _____  ____  ___  _____
 / /   | | /| / / _ \/ __ \/ ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /___ | |/ |/ /  __/ /_/ (__  ) /__/ /_/ / / / / / / /  __/ /
 \____/ |__/|__/\___/_.___/____/\___/\__,_/_/ /_/_/ /_/\___/_/
    '''
    print('\033[1;34m' + banner + '\033[0m')
    print('-' * 90)

def main():
    banner()
    parser = argparse.ArgumentParser(description='Example: python {} [ip|domain] [-p8080,9090] '.format(sys.argv[0]))
    parser.add_argument('target', help=u'192.168.1.1/www.baidu.com(默认扫描80端口)')
    parser.add_argument('-t', type=int, default=50, dest='threads', help=u'线程数(默认50)')
    parser.add_argument('-p', default=False, dest='custom_ports', help=u'自定义扫描端口(如-p8080,9090)')
    args = parser.parse_args()
    myscan = Scanner(args.target, args.threads, args.custom_ports)
    asyncio.run(myscan.run())

if __name__ == '__main__':
    main()
