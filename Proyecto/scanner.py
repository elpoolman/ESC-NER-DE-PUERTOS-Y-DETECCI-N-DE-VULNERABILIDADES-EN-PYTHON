"""
scanner.py
Escáner TCP asíncrono + banner grabbing + consulta NVD (CVEs + CVSS)
Interfaz: consola interactiva (pide host y rango/puertos)
Incluye autodetección de IP local como valor por defecto.
Optimizado para empaquetar con PyInstaller.
"""

import asyncio
import aiohttp
import json
import csv
import time
import sys
import ctypes
import re
import socket
from typing import List

# -----------------------------
# CONFIG (ajusta si quieres)
# -----------------------------
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CONCURRENCY = 200        # nº máximo de conexiones TCP simultáneas
BANNER_TIMEOUT = 2       # segundos para banner grabbing
NVD_TIMEOUT = 10         # segundos para consulta NVD
NVD_DELAY_BETWEEN = 0.2  # pausa entre llamadas NVD (para evitar rate limits)

# -----------------------------
# UTILIDADES
# -----------------------------
def is_admin() -> bool:
    """Comprueba si el script se ejecuta como Administrador en Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def detect_local_ip(fallback: str = "127.0.0.1") -> str:
    """
    Intenta detectar la IP local utilizada para salir a Internet.
    Método: abrir un socket UDP hacia un IP pública (no envía datos),
    y leer la IP local asociada.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # no necesita que 8.8.8.8 sea alcanzable realmente; no se envía paquete
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            # validar formato simple
            socket.inet_aton(ip)
            return ip
    except Exception:
        return fallback

def parse_ports(ports_input: str) -> List[int]:
    """
    Acepta:
      - "20-1024"
      - "22,80,443"
      - "1-1024,8080,8443"
    Devuelve lista de puertos (sin duplicados, ordenada).
    """
    parts = re.split(r'\s*,\s*', ports_input.strip())
    ports = set()
    for p in parts:
        if '-' in p:
            a, b = p.split('-', 1)
            try:
                a_i = int(a); b_i = int(b)
                if 1 <= a_i <= 65535 and 1 <= b_i <= 65535:
                    for x in range(min(a_i,b_i), max(a_i,b_i)+1):
                        ports.add(x)
            except:
                continue
        else:
            try:
                v = int(p)
                if 1 <= v <= 65535:
                    ports.add(v)
            except:
                continue
    return sorted(ports)

# -----------------------------
# ESCANEO ASÍNCRONO
# -----------------------------
async def scan_port_tcp(host: str, port: int, sem: asyncio.Semaphore):
    """
    Intenta conectar TCP al host:port. Si se conecta, intenta banner grabbing.
    Devuelve dict o None.
    """
    async with sem:
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except Exception:
            return None

        banner = "N/A"
        try:
            # Enviar un pequeño payload genérico para provocar banner en HTTP/SMTP/FTP, etc.
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
            banner = data.decode(errors="ignore").strip()
            if len(banner) > 800:
                banner = banner[:800]
        except Exception:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=0.8)
                banner = data.decode(errors="ignore").strip() or "N/A"
            except Exception:
                banner = "N/A"
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        return {"port": port, "status": "open", "banner": banner}

# -----------------------------
# CONSULTA NVD ASÍNCRONA
# -----------------------------
async def query_nvd(session: aiohttp.ClientSession, keyword: str):
    """Consulta la NVD con keywordSearch (devuelve lista de vulnerabilidades resumidas)."""
    if not keyword or keyword.strip() == "" or keyword == "N/A":
        return []

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5
    }
    headers = {
        "User-Agent": "PyScanner/1.0 (contact: your-email@example.com)"
    }

    try:
        async with session.get(NVD_API_URL, params=params, headers=headers, timeout=NVD_TIMEOUT) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except Exception:
        return []

    vulns = []
    for item in data.get("vulnerabilities", []):
        try:
            cve = item["cve"]["id"]
            descriptions = item["cve"].get("descriptions", [])
            desc = ""
            if descriptions:
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                if not desc:
                    desc = descriptions[0].get("value", "")
            metrics = item["cve"].get("metrics", {})
            cvss_score = "N/A"
            cvss_severity = "N/A"
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                try:
                    cvss_info = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_info.get("baseScore", "N/A")
                    cvss_severity = cvss_info.get("baseSeverity", "N/A")
                except:
                    pass
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                try:
                    cvss_info = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score = cvss_info.get("baseScore", "N/A")
                    cvss_severity = cvss_info.get("baseSeverity", "N/A")
                except:
                    pass

            vulns.append({
                "cve": cve,
                "description": desc,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity
            })
        except Exception:
            continue

    return vulns

# -----------------------------
# GUARDAR RESULTADOS
# -----------------------------
def save_results_json_csv(target: str, results: List[dict], elapsed: float):
    out_json = {
        "target": target,
        "elapsed_time_seconds": round(elapsed, 3),
        "results": results
    }
    with open("scan_results.json", "w", encoding="utf-8") as jf:
        json.dump(out_json, jf, indent=2, ensure_ascii=False)

    with open("scan_results.csv", "w", newline="", encoding="utf-8") as cf:
        fieldnames = ["port", "status", "banner", "vulnerabilities_count", "vulnerabilities"]
        writer = csv.DictWriter(cf, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "port": r["port"],
                "status": r["status"],
                "banner": (r["banner"][:250] + "...") if len(r["banner"])>250 else r["banner"],
                "vulnerabilities_count": len(r.get("vulnerabilities", [])),
                "vulnerabilities": json.dumps(r.get("vulnerabilities", []), ensure_ascii=False)
            })

# -----------------------------
# FLUJO PRINCIPAL
# -----------------------------
async def main():
    print("\nPyScanner - Escáner TCP asíncrono + NVD CVSS\n")

    if not is_admin():
        print("⚠️ Aviso: No estás ejecutando como Administrador. Para mejores resultados abre el programa como Administrador.\n")

    # autodetección de IP local
    detected_ip = detect_local_ip()
    # mostrar y ofrecer como valor por defecto
    print(f"IP local detectada: {detected_ip}")
    target_input = input(f"Introduce IP o hostname objetivo (enter para usar '{detected_ip}'): ").strip()
    target = target_input if target_input else detected_ip
    if not target:
        print("Host vacío, saliendo.")
        sys.exit(1)

    ports_input = input("Introduce rango/puertos (ej: 20-1024  o 22,80,443) [por defecto 20-1024]: ").strip()
    if not ports_input:
        ports_input = "20-1024"
        print("Usando rango por defecto 20-1024")

    ports = parse_ports(ports_input)
    if not ports:
        print("No se han parseado puertos válidos. Salir.")
        sys.exit(1)

    print(f"\nEscaneando {target} -> {len(ports)} puertos (concurrency={CONCURRENCY})\n")

    start = time.perf_counter()

    sem = asyncio.Semaphore(CONCURRENCY)
    scan_tasks = [scan_port_tcp(target, p, sem) for p in ports]
    scan_results_raw = await asyncio.gather(*scan_tasks)

    open_ports = [r for r in scan_results_raw if r is not None]

    async with aiohttp.ClientSession() as session:
        results = []
        for idx, r in enumerate(open_ports, start=1):
            print(f"[{idx}/{len(open_ports)}] Puerto {r['port']} abierto. Banner: { (r['banner'][:80] + '...') if len(r['banner'])>80 else r['banner'] }")
            banner_key = r['banner'] if r['banner'] and r['banner'] != "N/A" else f"port {r['port']}"
            vulns = await query_nvd(session, banner_key)
            r["vulnerabilities"] = vulns
            results.append(r)
            await asyncio.sleep(NVD_DELAY_BETWEEN)

    elapsed = time.perf_counter() - start
    save_results_json_csv(target, results, elapsed)

    print(f"\n✅ Escaneo finalizado en {elapsed:.2f} segundos.")
    print(f"Resultados guardados: scan_results.json , scan_results.csv\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nEscaneo interrumpido por el usuario.")
        sys.exit(1)
