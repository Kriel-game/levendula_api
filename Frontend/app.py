import streamlit as st
import requests
import pandas as pd

# A backend API címe (helyi futtatásnál)
#API_BASE_URL = "http://localhost:8000/api"
API_BASE_URL = "https://levendula-backend.onrender.com/api"

st.set_page_config(page_title="Levendula Biztonsági Monitor", layout="wide")

st.title("🛡️ Levendula Vendégház - Biztonsági Monitorozó")
st.write("A webszerver hozzáférési naplóinak elemzése és vizualizációja.")

# --- OLDALSÁV: Felhasználói műveletek és szűrések ---
st.sidebar.header("Műveletek és Szűrés")

# 1. Felhasználói művelet: Fiktív logok importálása teszteléshez
if st.sidebar.button("Fiktív tesztadatok importálása"):
    test_logs = [
        '81.183.12.55 - - [10/Sep/2026:08:14:02 +0200] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0"',
        '89.134.55.12 - - [10/Sep/2026:16:05:12 +0200] "GET /foglalas.php?id=1%20OR%201=1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '112.45.67.89 - - [10/Sep/2026:16:10:45 +0200] "GET /kapcsolat.php?uzenet=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 403 512 "-" "Python"',
        '45.22.19.100 - - [10/Sep/2026:16:15:22 +0200] "GET /kepek/../../../../etc/passwd HTTP/1.1" 404 230 "-" "curl"'
    ]
    try:
        response = requests.post(f"{API_BASE_URL}/logs/import", json={"logs": test_logs}, timeout=5)
        response.raise_for_status()
        st.sidebar.success("Tesztadatok sikeresen beküldve!")
    except requests.exceptions.RequestException as e:
        st.sidebar.error(f"Hiba a backend elérésekor: {e}")

st.sidebar.divider()

# 2. Felhasználói művelet: Szűrési beállítások
selected_severity = st.sidebar.selectbox(
    "Riasztási szint szűrése:",
    ["Összes", "Normál", "Magas", "Kritikus"]
)

search_ip = st.sidebar.text_input("Keresés IP-cím alapján (opcionális):")

# --- FŐOLDAL: Vizualizáció és Táblázatok ---

# Statisztikai összesítés lekérése diagramhoz
try:
    stats_response = requests.get(f"{API_BASE_URL}/stats/summary", timeout=5)
    stats_response.raise_for_status()
    stats_data = stats_response.json()

    if stats_data:
        # Pydantic JSON válasz Pandas DataFrame-mé alakítása a diagramhoz
        df_stats = pd.DataFrame(stats_data)
        df_stats.set_index("severity", inplace=True)

        st.subheader("📊 Riasztások eloszlása")
        # Beépített Streamlit diagram használata
        st.bar_chart(df_stats)
    else:
        st.info("Még nincsenek adatok a statisztika megjelenítéséhez.")

except requests.exceptions.RequestException:
    st.error("Nem sikerült betölteni a statisztikákat. Fut a backend?")

st.divider()

# Eseménylista lekérése a szűrőfeltételek alapján
st.subheader("📋 Biztonsági események naplója")

try:
    if search_ip:
        # Ha megadtak IP-címet, a részletes végpontot hívjuk
        events_response = requests.get(f"{API_BASE_URL}/events/{search_ip}", timeout=5)
    else:
        # Egyébként a listázó végpontot hívjuk, opcionális severity szűrővel
        params = {}
        if selected_severity != "Összes":
            params["severity"] = selected_severity
        events_response = requests.get(f"{API_BASE_URL}/events", params=params, timeout=5)

    # Ha a backend 404-et ad (nincs találat), a raise_for_status() kivételt dob,
    # kivéve ha ezt manuálisan kezeljük:
    if events_response.status_code == 404:
        st.warning("Nem található a feltételeknek megfelelő esemény.")
    else:
        events_response.raise_for_status()
        events_data = events_response.json()

        if events_data:
            # Pandas DataFrame használata a szebb táblázatos megjelenítéshez
            df_events = pd.DataFrame(events_data)
            # A megjelenítendő oszlopok sorrendjének és nevüknek finomítása
            df_display = df_events[["timestamp", "ip_address", "http_method", "request_url", "severity", "reason"]]

            # Táblázat kirajzolása (a puszta JSON kiírása helyett)
            st.dataframe(df_display, use_container_width=True)
        else:
            st.info("Nincs megjeleníthető adat.")

except requests.exceptions.RequestException as e:
    st.error(f"Hálózati hiba az adatok lekérésekor: {e}")