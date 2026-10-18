import re
from typing import Optional, Dict, Any


# =====================================================================
# FUNKCIONÁLIS PARADIGMA: NYERS NAPLÓSOR FELDOLGOZÓ
# Szerepe: A nyers Apache/Nginx webszerver access log sorok szöveges
# elemzése (parsing) reguláris kifejezéssel.
# Kapcsolat: A main.py import_logs() végpontja hívja meg minden beérkező
# naplósorra, majd a kimenetét továbbadja a SecurityRuleEngine-nek.
# =====================================================================


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Feldolgoz egy Apache access log sort, és strukturált szótárrá alakítja.

    Tiszta (pure) függvény: nincsenek mellékhatásai (nem módosít globális
    állapotot, nem ír fájlba vagy adatbázisba), azonos bemenetre mindig
    garantáltan ugyanazt a szótárat adja vissza.
    """
    # Nevesített regex csoportok (?P<nev>...) használata:
    # - ip: A kliens IP-címe (szóközig tartó karakterek a sor elején)
    # - timestamp: A szögletes zárójelek közötti dátum és időbélyeg
    # - method: HTTP metódus (GET, POST, PUT, DELETE stb.)
    # - url: A lekérdezett útvonal és query paraméterek
    # - protocol: HTTP protokoll verziója (pl. HTTP/1.1)
    # - status: Háromjegyű HTTP válaszkód (pl. 200, 403, 404, 500)
    log_pattern = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>.*?) (?P<protocol>\S+)" (?P<status>\d{3})'
    )

    match = log_pattern.search(line)

    # Ha a sor formátuma sérült vagy nem illeszkedik a szabványra, None-t adunk vissza
    if not match:
        return None

    return {
        "ip": match.group("ip"),
        "timestamp": match.group("timestamp"),
        "method": match.group("method"),
        "url": match.group("url"),
        "status": int(match.group("status"))
    }