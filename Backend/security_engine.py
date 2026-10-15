from typing import Dict, Any, List
import urllib.parse

class SecurityRuleEngine:
    """
    Objektumorientált szabálymotor a webes kérések biztonsági elemzésére.
    Megvalósítja a témaspecifikus feldolgozási szabályt a gyanús minták alapján.
    """

    def __init__(self) -> None:
        # A szabályok bemeneti feltételei (CSAK NAGYBETŰVEL, mert a vizsgált URL is nagybetűs lesz!)
        self.sqli_patterns: List[str] = ["1=1", "OR 1", "UNION SELECT"]
        self.xss_patterns: List[str] = ["<SCRIPT>", "JAVASCRIPT:", "<", ">"]
        self.traversal_patterns: List[str] = ["../"]

    def evaluate_request(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Kiértékeli a strukturált naplóadatot.
        Bemenet: A parse_log_line() által visszaadott szótár.
        Kimenet: Egy bővített szótár a riasztási szinttel (severity) és az okkal (reason).
        """
        # Ha hibás vagy üres bemenetet kapunk, visszautasítjuk
        if not log_data or "url" not in log_data:
            return self._generate_alert(log_data or {}, "Hiba", "Érvénytelen vagy hiányzó bemenet")

        # 1. Dekódoljuk az URL-t (pl. %3C -> <), majd 2. nagybetűssé alakítjuk!
        url_upper = urllib.parse.unquote(log_data["url"]).upper()

        # 1. SQL Injekció vizsgálata
        for pattern in self.sqli_patterns:
            if pattern in url_upper:
                return self._generate_alert(log_data, "Kritikus", "SQL Injekció gyanú")

        # 2. XSS (Cross-Site Scripting) vizsgálata
        for pattern in self.xss_patterns:
            if pattern in url_upper:
                return self._generate_alert(log_data, "Magas", "XSS támadás gyanú")

        # 3. Könyvtárbejárás (Path Traversal) vizsgálata
        for pattern in self.traversal_patterns:
            if pattern in url_upper:
                return self._generate_alert(log_data, "Kritikus", "Könyvtárbejárás gyanú")

        # Ha semelyik támadási minta nem illeszkedik
        return self._generate_alert(log_data, "Normál", "Tiszta kérés")

    def _generate_alert(self, log_data: Dict[str, Any], severity: str, reason: str) -> Dict[str, Any]:
        """
        Belső (privát) segédmetódus a kimenet egységes formázására.
        """
        result = log_data.copy()
        result["severity"] = severity
        result["reason"] = reason
        return result