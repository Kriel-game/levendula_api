from typing import Dict, Any, List
import urllib.parse

# =====================================================================
# OBJEKTUMORIENTÁLT PARADIGMA (OOP): BIZTONSÁGI SZABÁLYMOTOR
# Szerepe: Ez az osztály végzi az üzleti logikát (támadásdetektálás).
# Megkapja a parse_log_line() által előállított szótárat, ellenőrzi az URL-t
# ismert sebezhetőségi minták (SQLi, XSS, Path Traversal) alapján, majd
# kiegészíti az adatot a riasztási szinttel (severity) és az indoklással (reason).
# =====================================================================


class SecurityRuleEngine:
    """
    Objektumorientált szabálymotor a webes kérések biztonsági elemzésére.
    Egységbe zárja (encapsulation) a támadási mintákat és az értékelő algoritmust.
    """

    def __init__(self) -> None:
        # Támadási szignatúrák nagybetűs formában.
        # Mivel az elemzés előtt a vizsgált URL-t is nagybetűssé alakítjuk,
        # a támadók nem tudják kijátszani a szűrőt kis- és nagybetűk keverésével (pl. <ScRiPt>).
        self.sqli_patterns: List[str] = ["1=1", "OR 1", "UNION SELECT", "'--"]
        self.xss_patterns: List[str] = ["<SCRIPT>", "JAVASCRIPT:", "<", ">"]
        self.traversal_patterns: List[str] = ["../", "/ETC/PASSWD"]

    def evaluate_request(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Kiértékeli a strukturált naplóadatot a biztonsági szabályok alapján.
        """
        # Védekező programozás: hibás vagy hiányos bemenet esetén azonnal visszatérünk
        if not log_data or "url" not in log_data:
            return self._generate_alert(log_data or {}, "Hiba", "Érvénytelen vagy hiányzó bemenet")

        # Előfeldolgozás:
        # 1. urllib.parse.unquote: Feloldja az URL-kódolást (pl. %20 -> szóköz, %3C -> <),
        #    így a kódolt támadási kísérleteket is felismeri a motor.
        # 2. .upper(): Nagybetűsítés a kis-/nagybetű érzéketlen (case-insensitive) kereséshez.
        url_upper = urllib.parse.unquote(log_data["url"]).upper()

        # 1. Szabály: SQL Injekció vizsgálata (Adatbázis manipulációs kísérletek)
        for pattern in self.sqli_patterns:
            if pattern in url_upper:
                return self._generate_alert(log_data, "Kritikus", "SQL Injekció gyanú")

        # 2. Szabály: XSS (Cross-Site Scripting) vizsgálata (Kliensoldali szkript befecskendezés)
        for pattern in self.xss_patterns:
            if pattern in url_upper:
                return self._generate_alert(log_data, "Magas", "XSS támadás gyanú")

        # 3. Szabály: Könyvtárbejárás (Path Traversal) vizsgálata (Rendszerfájlok elérése)
        for pattern in self.traversal_patterns:
            if pattern in url_upper:
                return self._generate_alert(log_data, "Kritikus", "Könyvtárbejárás gyanú")

        # Ha egyik veszélyes minta sem illeszkedett, a kérést biztonságosnak minősítjük
        return self._generate_alert(log_data, "Normál", "Tiszta kérés")

    def _generate_alert(self, log_data: Dict[str, Any], severity: str, reason: str) -> Dict[str, Any]:
        """
        Belső (privát) segédmetódus az eredeti szótár lemásolására és
        a kiértékelési eredmények hozzáfűzésére (az eredeti bemenet módosítása nélkül).
        """
        result = log_data.copy()
        result["severity"] = severity
        result["reason"] = reason
        return result