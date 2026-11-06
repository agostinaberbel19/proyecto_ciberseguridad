"""
 SIEM-LITE | logica.py  (LÓGICA DE NEGOCIO — capas 1 a 4)

Propósito:  Herramienta de auditoría defensiva para PyMEs. Ingiere logs de
            tráfico de red (CSV/TXT), los evalúa contra un motor de reglas
            de cumplimiento (blacklists de IP + catálogo de puertos
            vulnerables) y genera un reporte ejecutivo listo para un CISO.

Este archivo contiene TODO lo que no es visual:
    1. modelo de datos        -> LogEntry
    2. capa de ingesta        -> LogIngestor
    3. motor de reglas        -> ComplianceEngine
    4. capa de reporting      -> AuditReportBuilder


================================================================================
"""

import csv
import os
import random
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


# 1. MODELO DE DATOS


@dataclass
class LogEntry:
    """Representa una línea de tráfico de red normalizada."""
    ip_origen: str
    ip_destino: str
    puerto: int
    protocolo: str
    timestamp: str
    veredicto: str = field(default="Sin evaluar")   # Permitido / Anómalo / Bloqueado
    motivo: str = field(default="")


# 2. CAPA DE INGESTA (parser robusto de CSV/TXT + simulador)


class LogIngestor:
    """
    Encargada exclusivamente de leer archivos y transformarlos en objetos
    LogEntry. Aísla toda la gestión de errores de E/S y de formato, para que
    el motor de reglas nunca reciba datos corruptos o incompletos.

    """

    ALIAS_COLUMNAS = {
        "ip_origen": "ip_origen", "src_ip": "ip_origen", "origen": "ip_origen",
        "ip_destino": "ip_destino", "dst_ip": "ip_destino", "destino": "ip_destino",
        "puerto": "puerto", "port": "puerto",
        "protocolo": "protocolo", "protocol": "protocolo",
        "timestamp": "timestamp", "time": "timestamp", "fecha": "timestamp",
    }

    def cargar_desde_archivo(self, ruta: str) -> List[LogEntry]:
        
        if not os.path.exists(ruta):
            raise FileNotFoundError(f"No se encontró el archivo:\n{ruta}")

        if os.path.getsize(ruta) == 0:
            raise ValueError("El archivo está vacío. No hay tráfico que auditar.")

        entradas: List[LogEntry] = []
        errores_de_fila = 0

        try:
            with open(ruta, "r", encoding="utf-8-sig", newline="") as f:
                # Detectamos el delimitador (coma o tabulador) de forma segura
                muestra = f.read(2048)
                f.seek(0)
                try:
                    dialecto = csv.Sniffer().sniff(muestra, delimiters=",;\t")
                except csv.Error:
                    dialecto = csv.excel  # fallback: coma estándar

                lector = csv.DictReader(f, dialect=dialecto)

                if not lector.fieldnames:
                    raise ValueError("No se pudieron detectar encabezados en el archivo.")

                # Normalizamos encabezados usando el mapa de alias
                columnas_normalizadas = {
                    col: self.ALIAS_COLUMNAS.get(col.strip().lower())
                    for col in lector.fieldnames
                }

                requeridas = {"ip_origen", "puerto", "protocolo"}
                if not requeridas.issubset(set(columnas_normalizadas.values())):
                    raise ValueError(
                        "El archivo no contiene las columnas mínimas requeridas:\n"
                        "ip_origen, puerto, protocolo\n\n"
                        "Verifique el encabezado del CSV."
                    )

                for numero_fila, fila_cruda in enumerate(lector, start=2):
                    try:
                        fila = {
                            columnas_normalizadas[k]: v
                            for k, v in fila_cruda.items()
                            if columnas_normalizadas.get(k)
                        }
                        entradas.append(self._construir_entrada(fila))
                    except (ValueError, TypeError, KeyError):
                        # Una fila corrupta no debe abortar todo el reporte:
                        # se descarta y se contabiliza para informar al operador.
                        errores_de_fila += 1
                        continue

        except UnicodeDecodeError:
            raise ValueError(
                "El archivo no tiene una codificación de texto válida (¿es binario?)."
            )
        except csv.Error as e:
            raise ValueError(f"El archivo CSV está mal formateado: {e}")

        if not entradas:
            raise ValueError(
                "No se pudo extraer ningún registro válido del archivo "
                "(formato incorrecto o todas las filas estaban corruptas)."
            )

        if errores_de_fila:

            entradas[0].motivo = f"__ADVERTENCIA__:{errores_de_fila} filas descartadas por formato inválido"

        return entradas

    @staticmethod
    def _construir_entrada(fila: dict) -> LogEntry:
      
        ip_origen = (fila.get("ip_origen") or "").strip()
        ip_destino = (fila.get("ip_destino") or "0.0.0.0").strip()
        puerto_raw = (fila.get("puerto") or "").strip()
        protocolo = (fila.get("protocolo") or "N/A").strip().upper()
        timestamp = (fila.get("timestamp") or datetime.now().isoformat(timespec="seconds")).strip()

        if not LogIngestor._es_ip_valida(ip_origen):
            raise ValueError(f"IP de origen inválida: '{ip_origen}'")

        try:
            puerto = int(puerto_raw)
        except ValueError:
            raise ValueError(f"Puerto no numérico: '{puerto_raw}'")

        if not (0 <= puerto <= 65535):
            raise ValueError(f"Puerto fuera de rango: {puerto}")

        return LogEntry(
            ip_origen=ip_origen,
            ip_destino=ip_destino,
            puerto=puerto,
            protocolo=protocolo,
            timestamp=timestamp,
        )

    @staticmethod
    def _es_ip_valida(ip: str) -> bool:
        patron = re.compile(
            r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
        )
        m = patron.match(ip)
        if not m:
            return False
        return all(0 <= int(octeto) <= 255 for octeto in m.groups())

    
    def generar_lote_simulado(self, cantidad: int = 40) -> List[LogEntry]:
        """
        Genera tráfico sintético para demostraciones/pruebas 
        """
        protocolos = ["TCP", "UDP", "TCP", "TCP", "ICMP"]
        puertos_comunes = [80, 443, 22, 3389, 21, 23, 8080, 445, 3306, 5900]
        ips_sospechosas_demo = ["185.234.219.12", "45.155.205.87", "91.219.237.5"]

        lote = []
        for _ in range(cantidad):
            usar_sospechosa = random.random() < 0.15
            ip_origen = (
                random.choice(ips_sospechosas_demo)
                if usar_sospechosa
                else f"192.168.{random.randint(0, 5)}.{random.randint(2, 254)}"
            )
            entrada = LogEntry(
                ip_origen=ip_origen,
                ip_destino=f"10.0.{random.randint(0,3)}.{random.randint(1,254)}",
                puerto=random.choice(puertos_comunes),
                protocolo=random.choice(protocolos),
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            lote.append(entrada)
        return lote



# 3. MOTOR DE REGLAS DE CUMPLIMIENTO


class ComplianceEngine:
    """
    Motor configurable de evaluación de tráfico. Aplica, en orden de
    severidad, tres capas de reglas:
        1. Blacklist de IPs conocidas          -> Bloqueado
        2. Catálogo de puertos vulnerables     -> Anómalo
        3. Todo lo demás                        -> Permitido
   
    """

    PUERTOS_VULNERABLES = {
        21: "FTP (credenciales en texto plano)",
        22: "SSH (objetivo frecuente de fuerza bruta)",
        23: "Telnet (protocolo sin cifrado, obsoleto)",
        135: "RPC/DCOM (histórico vector de exploits, ej. Blaster)",
        139: "NetBIOS (superficie de ataque SMB legado)",
        445: "SMB (vector de ransomware, ej. WannaCry/EternalBlue)",
        1433: "MS-SQL (expuesto a inyección/fuerza bruta)",
        3306: "MySQL (no debería estar expuesto a Internet)",
        3389: "RDP (principal vector de ransomware vía fuerza bruta)",
        5900: "VNC (control remoto frecuentemente mal asegurado)",
    }

    def __init__(self, ips_bloqueadas: Optional[set] = None):
        # Blacklist por defecto (rangos/IPs de ejemplo documentados como
        # indicadores de amenaza en fuentes públicas de threat intel).
        self.ips_bloqueadas = ips_bloqueadas or {
            "185.234.219.12",
            "45.155.205.87",
            "91.219.237.5",
            "0.0.0.0",
        }

    def agregar_ip_bloqueada(self, ip: str) -> None:
        """Permite extender la blacklist en caliente desde la GUI."""
        self.ips_bloqueadas.add(ip.strip())

    def evaluar(self, entradas: List[LogEntry]) -> List[LogEntry]:
     
        for entrada in entradas:
            self._evaluar_una(entrada)
        return entradas

    def _evaluar_una(self, entrada: LogEntry) -> None:
        # Regla 1: Blacklist de IP (máxima severidad)
        if entrada.ip_origen in self.ips_bloqueadas:
            entrada.veredicto = "Bloqueado"
            entrada.motivo = "IP de origen presente en blacklist de amenazas conocidas"
            return

        # Regla 2: Puerto vulnerable / servicio sensible
        if entrada.puerto in self.PUERTOS_VULNERABLES:
            entrada.veredicto = "Anómalo"
            entrada.motivo = self.PUERTOS_VULNERABLES[entrada.puerto]
            return

        # Regla 3: Tráfico dentro de parámetros esperados
        entrada.veredicto = "Permitido"
        entrada.motivo = "Cumple con la política de acceso estándar"


# 4. CAPA DE REPORTING (resumen ejecutivo)


class AuditReportBuilder:

    def __init__(self, entradas: List[LogEntry], nombre_fuente: str):
        self.entradas = entradas
        self.nombre_fuente = nombre_fuente

    def _metricas(self) -> dict:
        total = len(self.entradas)
        bloqueados = [e for e in self.entradas if e.veredicto == "Bloqueado"]
        anomalos = [e for e in self.entradas if e.veredicto == "Anómalo"]
        permitidos = [e for e in self.entradas if e.veredicto == "Permitido"]
        return {
            "total": total,
            "bloqueados": bloqueados,
            "anomalos": anomalos,
            "permitidos": permitidos,
            "pct_riesgo": round(((len(bloqueados) + len(anomalos)) / total) * 100, 1) if total else 0,
        }

    def _nivel_riesgo(self, pct_riesgo: float) -> str:
        if pct_riesgo >= 30:
            return "CRÍTICO"
        if pct_riesgo >= 10:
            return "ELEVADO"
        if pct_riesgo > 0:
            return "MODERADO"
        return "BAJO"

    def generar_texto(self) -> str:
        m = self._metricas()
        ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        nivel = self._nivel_riesgo(m["pct_riesgo"])

        lineas = []
        lineas.append("=" * 78)
        lineas.append("REPORTE DE AUDITORÍA DE SEGURIDAD DE RED — SIEM-LITE")
        lineas.append("=" * 78)
        lineas.append(f"Fecha de generación   : {ahora}")
        lineas.append(f"Fuente de datos       : {self.nombre_fuente}")
        lineas.append(f"Registros analizados  : {m['total']}")
        lineas.append("-" * 78)
        lineas.append("RESUMEN EJECUTIVO (para CISO / Gerencia)")
        lineas.append("-" * 78)
        lineas.append(
            f"Nivel de riesgo global: {nivel}  "
            f"({m['pct_riesgo']}% del tráfico presenta hallazgos)"
        )
        lineas.append(f"  - Tráfico Permitido : {len(m['permitidos'])}")
        lineas.append(f"  - Tráfico Anómalo   : {len(m['anomalos'])}  (violación de política de puertos)")
        lineas.append(f"  - Tráfico Bloqueado : {len(m['bloqueados'])}  (origen en blacklist de amenazas)")
        lineas.append("")
        if m["bloqueados"]:
            lineas.append(
                "Se recomienda escalar de inmediato los eventos 'Bloqueado' al "
                "equipo de respuesta a incidentes (IR) y verificar reglas de "
                "firewall perimetral."
            )
        elif m["anomalos"]:
            lineas.append(
                "No se detectaron IPs en blacklist, pero existe exposición de "
                "servicios sensibles. Se recomienda revisar la segmentación de "
                "red y aplicar hardening a los puertos señalados."
            )
        else:
            lineas.append(
                "No se detectaron violaciones de política en el lote analizado. "
                "Se recomienda mantener el monitoreo continuo."
            )
        lineas.append("-" * 78)
        lineas.append("DETALLE DE HALLAZGOS (Bloqueado / Anómalo)")
        lineas.append("-" * 78)

        hallazgos = m["bloqueados"] + m["anomalos"]
        if not hallazgos:
            lineas.append("  (Sin hallazgos que reportar)")
        else:
            for e in hallazgos:
                lineas.append(
                    f"  [{e.veredicto.upper():9}] {e.timestamp}  "
                    f"{e.ip_origen} -> {e.ip_destino}:{e.puerto}/{e.protocolo}  "
                    f"| Motivo: {e.motivo}"
                )

        lineas.append("=" * 78)
        lineas.append("Fin del reporte — Generado automáticamente por SIEM-LITE")
        lineas.append("=" * 78)
        return "\n".join(lineas)