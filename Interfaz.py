"""
 SIEM-LITE | interfaz.py  (CAPA VISUAL — capa 5)

Este archivo contiene SOLO la parte visual: la ventana, los botones, los
colores y la reacción a cada clic. Está hecho con tkinter / customtkinter
(librerías gráficas de Python)

"""

import os
from datetime import datetime
from typing import List

import tkinter as tk
from tkinter import filedialog, messagebox

try:
    import customtkinter as ctk
    CTK_DISPONIBLE = True
except ImportError:
   
    CTK_DISPONIBLE = False


from logica import LogEntry, LogIngestor, ComplianceEngine, AuditReportBuilder



# 5. CAPA DE PRESENTACIÓN (GUI)

PALETA = {
    "fondo": "#111820",
    "panel": "#1B2530",
    "acento": "#2E86AB",
    "acento_hover": "#256d8a",
    "texto": "#E6EDF3",
    "texto_secundario": "#9AA7B4",
    "ok": "#3FB950",
    "warn": "#D29922",
    "crit": "#F85149",
}


class SiemAuditorApp:
   

    def __init__(self):
        self.ingestor = LogIngestor()
        self.motor = ComplianceEngine()
        self.entradas_actuales: List[LogEntry] = []
        self.nombre_fuente_actual = "N/A"
        self.ultimo_reporte_texto = ""

        if CTK_DISPONIBLE:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = tk.Tk()
            self._aplicar_tema_oscuro_tk()

        self.root.title("SIEM-LITE — Auditor de Cumplimiento de Red")
        self.root.geometry("1080x680")
        self.root.minsize(920, 600)

        self._construir_interfaz()


    def _construir_interfaz(self):
        frame_cls = ctk.CTkFrame if CTK_DISPONIBLE else tk.Frame
        label_cls = ctk.CTkLabel if CTK_DISPONIBLE else tk.Label
        boton_cls = ctk.CTkButton if CTK_DISPONIBLE else tk.Button

       
        header = frame_cls(self.root, fg_color=PALETA["panel"], corner_radius=0) \
            if CTK_DISPONIBLE else frame_cls(self.root, bg=PALETA["panel"])
        header.pack(fill="x", side="top")

        titulo = label_cls(
            header, text="🛡  SIEM-LITE", font=("Segoe UI", 22, "bold"),
            text_color=PALETA["texto"] if CTK_DISPONIBLE else None,
        ) if CTK_DISPONIBLE else label_cls(
            header, text="SIEM-LITE", font=("Segoe UI", 20, "bold"),
            bg=PALETA["panel"], fg=PALETA["texto"],
        )
        titulo.pack(side="left", padx=20, pady=14)

        subtitulo = label_cls(
            header, text="Auditor Automatizado de Logs y Cumplimiento de Red",
            font=("Segoe UI", 12),
            text_color=PALETA["texto_secundario"] if CTK_DISPONIBLE else None,
        ) if CTK_DISPONIBLE else label_cls(
            header, text="Auditor Automatizado de Logs y Cumplimiento de Red",
            font=("Segoe UI", 11), bg=PALETA["panel"], fg=PALETA["texto_secundario"],
        )
        subtitulo.pack(side="left", pady=14)

        
        cuerpo = frame_cls(self.root, fg_color=PALETA["fondo"]) if CTK_DISPONIBLE \
            else frame_cls(self.root, bg=PALETA["fondo"])
        cuerpo.pack(fill="both", expand=True, padx=16, pady=16)

        panel_izq = frame_cls(cuerpo, fg_color=PALETA["panel"], corner_radius=10, width=260) \
            if CTK_DISPONIBLE else frame_cls(cuerpo, bg=PALETA["panel"], width=260)
        panel_izq.pack(side="left", fill="y", padx=(0, 16))
        panel_izq.pack_propagate(False)

        label_cls(
            panel_izq, text="ACCIONES", font=("Segoe UI", 12, "bold"),
            **({"text_color": PALETA["texto_secundario"]} if CTK_DISPONIBLE
               else {"bg": PALETA["panel"], "fg": PALETA["texto_secundario"]})
        ).pack(anchor="w", padx=16, pady=(16, 8))

        self._crear_boton(panel_izq, "📂  Importar Log (CSV/TXT)", self.accion_importar_archivo)
        self._crear_boton(panel_izq, "🧪  Simular Lote de Tráfico", self.accion_simular_trafico)
        self._crear_boton(panel_izq, "⚙️  Ejecutar Auditoría", self.accion_ejecutar_auditoria, principal=True)
        self._crear_boton(panel_izq, "💾  Exportar Reporte", self.accion_exportar_reporte)
        self._crear_boton(panel_izq, "🧹  Limpiar", self.accion_limpiar)

        label_cls(
            panel_izq, text="ESTADO", font=("Segoe UI", 12, "bold"),
            **({"text_color": PALETA["texto_secundario"]} if CTK_DISPONIBLE
               else {"bg": PALETA["panel"], "fg": PALETA["texto_secundario"]})
        ).pack(anchor="w", padx=16, pady=(20, 8))

        self.label_estado = label_cls(
            panel_izq, text="Sin datos cargados.", wraplength=220, justify="left",
            font=("Segoe UI", 11),
            **({"text_color": PALETA["texto"]} if CTK_DISPONIBLE
               else {"bg": PALETA["panel"], "fg": PALETA["texto"]})
        )
        self.label_estado.pack(anchor="w", padx=16, pady=(0, 16))

        #  Panel derecho: salida del reporte 
        panel_der = frame_cls(cuerpo, fg_color=PALETA["panel"], corner_radius=10) \
            if CTK_DISPONIBLE else frame_cls(cuerpo, bg=PALETA["panel"])
        panel_der.pack(side="left", fill="both", expand=True)

        label_cls(
            panel_der, text="SALIDA DE AUDITORÍA", font=("Segoe UI", 12, "bold"),
            **({"text_color": PALETA["texto_secundario"]} if CTK_DISPONIBLE
               else {"bg": PALETA["panel"], "fg": PALETA["texto_secundario"]})
        ).pack(anchor="w", padx=16, pady=(16, 8))

        if CTK_DISPONIBLE:
            self.textbox = ctk.CTkTextbox(
                panel_der, font=("Consolas", 12), fg_color="#0D1218",
                text_color=PALETA["texto"], corner_radius=8,
            )
        else:
            self.textbox = tk.Text(
                panel_der, font=("Consolas", 11), bg="#0D1218", fg=PALETA["texto"],
                insertbackground=PALETA["texto"], relief="flat",
            )
        self.textbox.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._set_textbox("Bienvenido. Importe un archivo de logs o genere tráfico "
                           "simulado para comenzar la auditoría.\n")

    def _crear_boton(self, parent, texto, comando, principal=False):
        if CTK_DISPONIBLE:
            btn = ctk.CTkButton(
                parent, text=texto, command=comando,
                fg_color=PALETA["acento"] if principal else "#2A3644",
                hover_color=PALETA["acento_hover"] if principal else "#374556",
                text_color=PALETA["texto"], font=("Segoe UI", 12),
                height=38, corner_radius=8,
            )
        else:
            btn = tk.Button(
                parent, text=texto, command=comando,
                bg=PALETA["acento"] if principal else "#2A3644",
                fg=PALETA["texto"], activebackground=PALETA["acento_hover"],
                relief="flat", font=("Segoe UI", 10), pady=6,
            )
        btn.pack(fill="x", padx=16, pady=6)
        return btn

    def _aplicar_tema_oscuro_tk(self):
        self.root.configure(bg=PALETA["fondo"])

    def _set_textbox(self, contenido: str):
        self.textbox.delete("1.0", "end") if CTK_DISPONIBLE else self.textbox.delete("1.0", tk.END)
        self.textbox.insert("1.0" if CTK_DISPONIBLE else tk.END, contenido)

    # acciones (capturan errores)
    def accion_importar_archivo(self):
        ruta = filedialog.askopenfilename(
            title="Seleccionar archivo de logs",
            filetypes=[("Logs / CSV", "*.csv *.txt"), ("Todos los archivos", "*.*")],
        )
        if not ruta:
            return
        try:
            entradas = self.ingestor.cargar_desde_archivo(ruta)
        except (FileNotFoundError, ValueError) as e:
            messagebox.showerror("Error al importar el archivo", str(e))
            return
        except Exception as e:
            # Red de seguridad final: nunca debe colgarse la app por un
            # error no anticipado durante la lectura de un archivo externo.
            messagebox.showerror(
                "Error inesperado",
                f"Ocurrió un error inesperado al leer el archivo:\n{e}",
            )
            return

        advertencia = ""
        if entradas and entradas[0].motivo.startswith("__ADVERTENCIA__"):
            advertencia = entradas[0].motivo.split(":", 1)[1]
            entradas[0].motivo = ""

        self.entradas_actuales = entradas
        self.nombre_fuente_actual = os.path.basename(ruta)
        self.label_estado.configure(
            text=f"Cargado: {self.nombre_fuente_actual}\n{len(entradas)} registros listos."
        ) if CTK_DISPONIBLE else self.label_estado.config(
            text=f"Cargado: {self.nombre_fuente_actual}\n{len(entradas)} registros listos."
        )
        msg = f"Se importaron {len(entradas)} registros desde '{self.nombre_fuente_actual}'.\n"
        if advertencia:
            msg += f"⚠ Advertencia: {advertencia}\n"
        msg += "\nPresione 'Ejecutar Auditoría' para evaluarlos contra las políticas."
        self._set_textbox(msg)

    def accion_simular_trafico(self):
        try:
            entradas = self.ingestor.generar_lote_simulado(cantidad=50)
        except Exception as e:
            messagebox.showerror("Error al simular tráfico", str(e))
            return

        self.entradas_actuales = entradas
        self.nombre_fuente_actual = "Lote simulado (demo interna)"
        self.label_estado.configure(
            text=f"Simulación generada.\n{len(entradas)} registros listos."
        ) if CTK_DISPONIBLE else self.label_estado.config(
            text=f"Simulación generada.\n{len(entradas)} registros listos."
        )
        self._set_textbox(
            f"Se generaron {len(entradas)} registros de tráfico simulado.\n\n"
            "Presione 'Ejecutar Auditoría' para evaluarlos contra las políticas."
        )

    def accion_ejecutar_auditoria(self):
        if not self.entradas_actuales:
            messagebox.showwarning(
                "Sin datos",
                "No hay registros cargados. Importe un archivo o genere un "
                "lote simulado antes de ejecutar la auditoría.",
            )
            return
        try:
            self.motor.evaluar(self.entradas_actuales)
            constructor = AuditReportBuilder(self.entradas_actuales, self.nombre_fuente_actual)
            self.ultimo_reporte_texto = constructor.generar_texto()
        except Exception as e:
            messagebox.showerror(
                "Error durante la auditoría",
                f"No fue posible completar la evaluación:\n{e}",
            )
            return

        self._set_textbox(self.ultimo_reporte_texto)
        self.label_estado.configure(
            text="Auditoría completada.\nUse 'Exportar Reporte' para guardarla."
        ) if CTK_DISPONIBLE else self.label_estado.config(
            text="Auditoría completada.\nUse 'Exportar Reporte' para guardarla."
        )

    def accion_exportar_reporte(self):
        if not self.ultimo_reporte_texto:
            messagebox.showwarning(
                "Nada que exportar",
                "Primero ejecute una auditoría para generar el reporte.",
            )
            return
        ruta = filedialog.asksaveasfilename(
            title="Guardar reporte de auditoría",
            defaultextension=".txt",
            initialfile=f"reporte_auditoria_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            filetypes=[("Archivo de texto", "*.txt")],
        )
        if not ruta:
            return
        try:
            with open(ruta, "w", encoding="utf-8") as f:
                f.write(self.ultimo_reporte_texto)
        except OSError as e:
            messagebox.showerror("Error al guardar", f"No se pudo escribir el archivo:\n{e}")
            return
        messagebox.showinfo("Reporte exportado", f"Reporte guardado exitosamente en:\n{ruta}")

    def accion_limpiar(self):
        self.entradas_actuales = []
        self.nombre_fuente_actual = "N/A"
        self.ultimo_reporte_texto = ""
        self.label_estado.configure(text="Sin datos cargados.") if CTK_DISPONIBLE \
            else self.label_estado.config(text="Sin datos cargados.")
        self._set_textbox("Bienvenido. Importe un archivo de logs o genere tráfico "
                           "simulado para comenzar la auditoría.\n")

    def ejecutar(self):
        self.root.mainloop()



# PUNTO DE ENTRADA


if __name__ == "__main__":
    app = SiemAuditorApp()
    app.ejecutar()