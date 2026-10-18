import streamlit as st
import requests
import pandas as pd

# =====================================================================
# STREAMLIT FRONTEND (INTERAKTÍV BIZTONSÁGI DASHBOARD)
# Szerepe: A rendszer vizuális megjelenítő rétege (prezentációs réteg).
# HTTP kérésekkel (REST API) kommunikál a Renderen futó FastAPI backenddel,
# az eredményeket pedig Pandas DataFrame-ek segítségével táblázatos és
# grafikus (oszlopdiagram) formában jeleníti meg az üzemeltetőnek.
# =====================================================================

API_BASE_URL = "https://levendula-backend.onrender.com/api"

# Egyedi User-Agent fejléc megadása:
# A Render előtti Cloudflare védelem (WAF) gyakran 403 Forbidden hibával
# blokkolja az alapértelmezett 'python-requests' fejlécű POST kéréseket,
# ha azok támadási mintákat (pl. SQLi/XSS) tartalmaznak. A böngésző fejléc ezt megoldja.
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

st.set_page_config(page_title="Levendula Biztonsági Monitor", layout="wide")

st.title("🛡️ Levendula Vendégház - Biztonsági Monitorozó")
st.write("A webszerver hozzáférési naplóinak elemzése és vizualizációja.")

# --- OLDALSÁV: Felhasználói műveletek és szűrések ---
st.sidebar.header("Műveletek és Szűrés")

# 1. Felhasználói művelet: Változatos fiktív logok importálása teszteléshez
if st.sidebar.button("Fiktív tesztadatok importálása"):
    test_logs = [
        '81.183.12.55 - - [18/Oct/2026:08:14:02 +0200] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0"',
        '81.183.12.55 - - [18/Oct/2026:08:14:05 +0200] "GET /szobak.php HTTP/1.1" 200 8120 "-" "Mozilla/5.0"',
        '195.56.78.12 - - [18/Oct/2026:09:20:11 +0200] "GET /galeria.php HTTP/1.1" 200 15420 "-" "Mozilla/5.0"',
        '89.134.55.12 - - [18/Oct/2026:10:05:12 +0200] "GET /foglalas.php?id=1%20OR%201=1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '89.134.55.12 - - [18/Oct/2026:10:06:00 +0200] "GET /admin/login.php?user=admin%27-- HTTP/1.1" 403 512 "-" "Mozilla/5.0"',
        '185.220.101.4 - - [18/Oct/2026:11:15:30 +0200] "GET /arak.php?kategoria=1%20UNION%20SELECT%201,2,3 HTTP/1.1" 500 256 "-" "sqlmap"',
        '112.45.67.89 - - [18/Oct/2026:12:10:45 +0200] "GET /kapcsolat.php?uzenet=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 403 512 "-" "Python"',
        '112.45.67.89 - - [18/Oct/2026:12:11:10 +0200] "GET /vendegkonyv.php?nev=javascript:alert(document.cookie) HTTP/1.1" 403 512 "-" "Mozilla/5.0"',
        '45.22.19.100 - - [18/Oct/2026:13:15:22 +0200] "GET /kepek/../../../../etc/passwd HTTP/1.1" 404 230 "-" "curl"',
        '45.22.19.100 - - [18/Oct/2026:13:16:05 +0200] "GET /letoltes.php?file=../../config.php HTTP/1.1" 403 128 "-" "curl"',
        '213.16.88.40 - - [18/Oct/2026:14:00:19 +0200] "POST /foglalas_kuld.php HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '91.82.44.19 - - [18/Oct/2026:14:12:00 +0200] "GET /kapcsolat.php HTTP/1.1" 200 3410 "-" "Mozilla/5.0"'
    ]
    try:
        response = requests.post(
            f"{API_BASE_URL}/logs/import",
            json={"logs": test_logs},
            headers=REQUEST_HEADERS,
            timeout=15
        )
        response.raise_for_status()
        st.sidebar.success("12 db tesztadat sikeresen beküldve!")
    except requests.exceptions.RequestException as e:
        st.sidebar.error(f"Hiba a backend elérésekor: {e}")

st.sidebar.divider()

# 2. Felhasználói művelet: Szűrési beállítások az oldalsávon
selected_severity = st.sidebar.selectbox(
    "Riasztási szint szűrése:",
    ["Összes", "Normál", "Magas", "Kritikus"]
)

search_ip = st.sidebar.text_input("Keresés IP-cím alapján (opcionális):")

# --- FŐOLDAL: Vizualizáció és Táblázatok ---

# 1. szekció: Statisztikai összesítés lekérése és ábrázolása
try:
    stats_response = requests.get(
        f"{API_BASE_URL}/stats/summary",
        headers=REQUEST_HEADERS,
        timeout=15
    )
    stats_response.raise_for_status()
    stats_data = stats_response.json()

    if stats_data:
        # A backendtől kapott JSON listát Pandas DataFrame-mé alakítjuk,
        # és a 'severity' oszlopot állítjuk be indexként (X tengely a diagramon).
        df_stats = pd.DataFrame(stats_data)
        df_stats.set_index("severity", inplace=True)

        st.subheader("📊 Riasztások eloszlása")
        st.bar_chart(df_stats)
    else:
        st.info("Még nincsenek adatok a statisztika megjelenítéséhez.")

except requests.exceptions.RequestException:
    st.error("Nem sikerült betölteni a statisztikákat. Ellenőrizd, hogy fut-e a backend!")

st.divider()

# 2. szekció: Részletes eseménylista lekérése a szűrőfeltételek alapján
st.subheader("📋 Biztonsági események naplója")

try:
    if search_ip:
        # Ha a felhasználó beírt egy IP-címet, az IP-alapú végpontot hívjuk meg
        events_response = requests.get(
            f"{API_BASE_URL}/events/{search_ip.strip()}",
            headers=REQUEST_HEADERS,
            timeout=15
        )
    else:
        # Egyébként az általános listázó végpontot hívjuk, opcionális severity szűrővel
        params = {}
        if selected_severity != "Összes":
            params["severity"] = selected_severity
        events_response = requests.get(
            f"{API_BASE_URL}/events",
            params=params,
            headers=REQUEST_HEADERS,
            timeout=15
        )

    # A 404-es státuszkód itt nem rendszerhibát, hanem üres találati listát jelent
    if events_response.status_code == 404:
        st.warning("Nem található a feltételeknek megfelelő esemény.")
    else:
        events_response.raise_for_status()
        events_data = events_response.json()

        if events_data:
            # Pandas DataFrame létrehozása és a releváns oszlopok kiválasztása
            df_events = pd.DataFrame(events_data)
            df_display = df_events[["timestamp", "ip_address", "http_method", "request_url", "severity", "reason"]]

            st.dataframe(df_display, use_container_width=True)
        else:
            st.info("Nincs megjeleníthető adat.")

except requests.exceptions.RequestException as e:
    st.error(f"Hálózati hiba az adatok lekérésekor: {e}")