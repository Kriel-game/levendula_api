import re
from typing import Optional, Dict, Any


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Feldolgoz egy Apache access log sort, és strukturált szótárrá alakítja.
    Ez egy tiszta (pure) függvény: nem olvas fájlt, nem ír adatbázisba, 
    kizárólag a bemeneti paraméterből állítja elő a kimenetet.
    """
    # Nevesített regex csoportokat (?P<nev>...) használunk a jobb olvashatóságért
    log_pattern = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>.*?) (?P<protocol>\S+)" (?P<status>\d{3})'
    )

    match = log_pattern.search(line)
    if not match:
        return None

    return {
        "ip": match.group("ip"),
        "timestamp": match.group("timestamp"),
        "method": match.group("method"),
        "url": match.group("url"),
        "status": int(match.group("status"))
    }


# --- Tesztelés a fiktív támadási adattal ---
teszt_sor = '89.134.55.12 - - [10/Sep/2026:16:05:12 +0200] "GET /foglalas.php?id=1%20OR%201=1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
feldolgozott_adat = parse_log_line(teszt_sor)

print(feldolgozott_adat)
# Kimenet: {'ip': '89.134.55.12', 'timestamp': '10/Sep/2026:16:05:12 +0200', 'method': 'GET', 'url': '/foglalas.php?id=1%20OR%201=1', 'status': 200}