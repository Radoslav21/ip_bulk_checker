# Visual Stidio Code Version
#
# Как се изпълнява:
#   1) install aiohttp(https://docs.aiohttp.org/en/stable/): python3 -m pip install aiohttp
#   2) How to start the script:
# 
# from menu <View> -> <Terminal>
# export ABUSEIPDB_KEY="api_key_from_abuseipdb"
# python3 ip_reputation.py --in ips.txt --out result.csv --max-parallel 10 --rps 1.0

from dotenv import load_dotenv
load_dotenv()
import os # работа с операционната системa
import csv # четене и запис в CSV файл
import time # rate limiting (a computer networking technique used to control the rate of requests sent or received by a network interface, often to prevent abuse or overload of a system)
import argparse # парсване на аргументи
import asyncio # асинхронизация
from typing import List, Dict, Any # типове анотации(не променя работата на програмата) 
# за по - ясен код

import aiohttp # HTTP клиент за изпращане на заявки

API_URL = "https://api.abuseipdb.com/api/v2/check" # URL към когото API ключа, ще изпраща заявки
UA = "ip-reputation-check/2.0" # HTTP header , който казва на сървъра , кой клиент прави заявката

def load_ips(path: str) -> List[str]: # чете входният файл (ips.txt)
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

class RateLimiter:
    """Прост rate limiter: гарантира <= rps заявки/секунда."""
    def __init__(self, rps: float):
        self.interval = 0.5 / max(0.01, rps)
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self):
        async with self._lock:
            now = time.monotonic()
            if now < self._next:
                await asyncio.sleep(self._next - now)
            self._next = max(now, self._next) + self.interval

async def fetch_ip(session: aiohttp.ClientSession, limiter: RateLimiter, ip: str, max_age: int) -> Dict[str, Any]:
    await limiter.wait()
    try:
        async with session.get(
            API_URL,
            params={"ipAddress": ip, "maxAgeInDays": str(max_age)},
            timeout=aiohttp.ClientTimeout(total=12),
            ssl=False
        ) as resp:
            if resp.status == 429:
                txt = (await resp.text())[:200].replace("\n", " ")
                return {"ip": ip, "ok": False, "error": f"rate_limited (429) {txt}"}
            if resp.status == 401:
                txt = (await resp.text())[:200].replace("\n", " ")
                return {"ip": ip, "ok": False, "error": f"unauthorized (401) {txt}"}
            if resp.status == 403:
                txt = (await resp.text())[:200].replace("\n", " ")
                return {"ip": ip, "ok": False, "error": f"http_403 {txt}"}
            if resp.status >= 400:
                txt = (await resp.text())[:200].replace("\n", " ")
                return {"ip": ip, "ok": False, "error": f"http_{resp.status} {txt}"}
            data = await resp.json()
    except asyncio.TimeoutError:
        return {"ip": ip, "ok": False, "error": "timeout"}
    except aiohttp.ClientError as e:
        return {"ip": ip, "ok": False, "error": f"client_error: {e}"}
    except Exception as e:
        return {"ip": ip, "ok": False, "error": f"error: {e}"}

    d = data.get("data", {}) if isinstance(data, dict) else {}
    return {
        "ip": ip,
        "ok": True,
        "country": d.get("countryCode", "") or "",
        "score": d.get("abuseConfidenceScore", 0),
        "total_reports": d.get("totalReports", 0),
    }

async def run_bulk(ips: List[str], api_key: str, max_parallel: int, rps: float, max_age: int) -> List[Dict[str, Any]]:
    headers = {"Key": api_key.strip(), "Accept": "application/json", "User-Agent": UA}
    limiter = RateLimiter(rps=rps)
    sem = asyncio.Semaphore(max_parallel)
    results: List[Dict[str, Any]] = []

    async with aiohttp.ClientSession(headers=headers) as session:
        async def worker(ip: str):
            async with sem:
                res = await fetch_ip(session, limiter, ip, max_age)
                results.append(res)
                print(f"{ip} -> {'OK' if res.get('ok') else 'ERR'}")

        await asyncio.gather(*(asyncio.create_task(worker(ip)) for ip in ips))

    # Сортиране по score (низходящо), но първо OK резултати
    results.sort(key=lambda r: (0 if r.get("ok") else 1, -(r.get("score") or 0)))
    return results

def save_csv(rows: List[Dict[str, Any]], out_path: str):
    fields = ["ip", "country", "score", "total_reports"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            if r.get("ok"):
                w.writerow({
                    "ip": r["ip"],
                    "country": r.get("country", ""),
                    "score": r.get("score", 0),
                    "total_reports": r.get("total_reports", 0),
                })

def print_table(rows: List[Dict[str, Any]]):
    print("\nIP".ljust(18), "Country".ljust(8), "Score(%)".ljust(9), "Reports")
    print("-" * 46)
    for r in rows:
        if r.get("ok"):
            print(
                str(r["ip"]).ljust(18),
                str(r.get("country", "") or "").ljust(8),
                str(r.get("score", 0)).ljust(9),
                str(r.get("total_reports", 0)),
            )
        else:
            print(str(r["ip"]).ljust(18), "-".ljust(8), "ERR".ljust(9), r.get("error", ""))

def main():
    ap = argparse.ArgumentParser(description='''AbuseIPDB bulk checker:


Трябва да имате .env файл, в който се съдържа API ключа на AbuseIPDB, по този начин: 
ABUSEIPDB_KEY=<your_key>''', formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="infile", required=True, help="Файл с IP адреси (по 1 на ред).")
    ap.add_argument("--out", dest="outfile", default="abuseipdb_results.csv", help="CSV изход.")
    ap.add_argument("--max-parallel", type=int, default=10, help="Макс. едновременни заявки (default: 10).")
    ap.add_argument("--rps", type=float, default=1.0, help="Макс. заявки/секунда (default: 1.0).")
    ap.add_argument("--max-age", type=int, default=365, help="maxAgeInDays (default: 365).")
    ap.add_argument("--api-key", dest="api_key", default="", help="API ключ (ако не ползваш ABUSEIPDB_KEY).")
    args = ap.parse_args()

    api_key = os.getenv("ABUSEIPDB_KEY")
    if not api_key:
        raise SystemExit("Липсва API ключ. Подай --api-key или задай ABUSEIPDB_KEY.")

    ips = load_ips(args.infile)
    if not ips:
        raise SystemExit("Няма валидни IP адреси във файла ips.txt.")

    results = asyncio.run(run_bulk(
        ips=ips,
        api_key=api_key,
        max_parallel=args.max_parallel,
        rps=args.rps,
        max_age=args.max_age
    ))

    save_csv(results, args.outfile)
    print_table(results)
    print(f"\nГотово. CSV: {args.outfile}")

if __name__ == "__main__":
    main()