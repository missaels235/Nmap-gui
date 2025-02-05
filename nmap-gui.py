import tkinter as tk
from tkinter import ttk, messagebox
import threading
import re
import subprocess
from xml.etree import ElementTree as ET

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Puertos Profesional")
        self.root.geometry("1000x700")
        
        # Variables
        self.target = tk.StringVar()
        self.ports = tk.StringVar(value="1-1000")
        self.scanning = False
        self.process = None
        self.xml_content = []
        
        # Configurar interfaz
        self.create_widgets()
        self.style = ttk.Style()
        self.style.configure("Treeview", rowheight=25, font=('Consolas', 10))
        self.style.configure("TButton", padding=6)
        
    def create_widgets(self):
        # Frame de configuración
        config_frame = ttk.Frame(self.root, padding=10)
        config_frame.pack(fill=tk.X)
        
        ttk.Label(config_frame, text="Target (IP o dominio):").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(config_frame, textvariable=self.target, width=30).grid(row=0, column=1, padx=5)
        
        ttk.Label(config_frame, text="Puertos (ej: 80, 1-1000):").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(config_frame, textvariable=self.ports).grid(row=1, column=1, padx=5)
        
        # Barra de progreso
        self.progress_frame = ttk.Frame(self.root, padding=10)
        self.progress_frame.pack(fill=tk.X)
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, orient="horizontal", length=200, mode="determinate")
        self.progress_bar.pack(fill=tk.X)
        
        self.lbl_progress = ttk.Label(self.progress_frame, text="0%")
        self.lbl_progress.pack(pady=5)
        
        # Botones
        btn_frame = ttk.Frame(self.root, padding=10)
        btn_frame.pack(fill=tk.X)
        
        self.start_btn = ttk.Button(btn_frame, text="Iniciar Escaneo", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        # Tabla de resultados
        results_frame = ttk.Frame(self.root)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.tree = ttk.Treeview(results_frame, columns=('Port', 'State', 'Service', 'Version'), show='headings')
        self.tree.heading('Port', text='PUERTO', anchor=tk.W)
        self.tree.heading('State', text='ESTADO', anchor=tk.W)
        self.tree.heading('Service', text='SERVICIO', anchor=tk.W)
        self.tree.heading('Version', text='VERSIÓN', anchor=tk.W)
        
        self.tree.column('Port', width=100)
        self.tree.column('State', width=150)
        self.tree.column('Service', width=200)
        self.tree.column('Version', width=400)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Etiqueta de resumen
        self.lbl_summary = ttk.Label(self.root, text="", font=('Arial', 10, 'bold'))
        self.lbl_summary.pack(pady=5)
        
    def start_scan(self):
        if not self.target.get():
            messagebox.showerror("Error", "¡Ingresa un objetivo válido!")
            return
            
        if not self.validate_ports():
            messagebox.showerror("Error", "Formato de puertos inválido. Usa: 80 o 1-1000 o 22,80,443")
            return
            
        self.scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.tree.delete(*self.tree.get_children())
        self.progress_bar["value"] = 0
        self.lbl_progress.config(text="0%")
        self.lbl_summary.config(text="")
        self.xml_content = []
        
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()
        
    def validate_ports(self):
        pattern = r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$'
        return re.match(pattern, self.ports.get()) is not None
        
    def run_scan(self):
        try:
            target = self.target.get()
            ports = self.ports.get()
            
            cmd = [
                "nmap",
                "-T4",
                "-p", ports,
                "-sV",
                "-v",
                "-oX", "-",
                target
            ]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            def read_output():
                while True:
                    line = self.process.stdout.readline()
                    if not line and self.process.poll() is not None:
                        break
                    if line:
                        self.xml_content.append(line)
                        self.parse_nmap_output(line)
                
                stderr = self.process.stderr.read()
                if stderr:
                    self.root.after(0, self.show_error, f"Error de Nmap:\n{stderr}")
                    return
                
                self.root.after(0, self.process_final_results)
            
            threading.Thread(target=read_output).start()
            
        except Exception as e:
            self.root.after(0, self.show_error, f"Error al iniciar escaneo: {str(e)}")

    def parse_nmap_output(self, line):
        progress_match = re.search(r'(\d+\.\d+)% done', line)
        if progress_match:
            progress = float(progress_match.group(1))
            self.root.after(0, self.update_progress, progress)

    def update_progress(self, value):
        self.progress_bar["value"] = value
        self.lbl_progress.config(text=f"{value:.1f}%")

    def process_final_results(self):
        try:
            xml_output = "".join(self.xml_content)
            
            if not xml_output.strip():
                self.show_error("Nmap no generó resultados válidos")
                return
                
            root = ET.fromstring(xml_output)
            
            total_ports = 0
            open_ports = 0
            closed_ports = 0
            filtered_ports = 0
            
            for host in root.findall("host"):
                ports = host.find("ports")
                if ports is not None:
                    # Procesar puertos individuales
                    for port in ports.findall("port"):
                        port_id = port.get("portid")
                        state = port.find("state").get("state").capitalize()
                        service = port.find("service").get("name", "desconocido") if port.find("service") is not None else "desconocido"
                        version = port.find("service").get("product", "") if port.find("service") is not None else ""
                        if port.find("service") is not None and port.find("service").get("version"):
                            version += " " + port.find("service").get("version")
                        
                        self.tree.insert('', 'end', values=(port_id, state, service, version.strip()))
                        total_ports +=1
                        if state == "Open": open_ports +=1
                        elif state == "Closed": closed_ports +=1
                        elif state == "Filtered": filtered_ports +=1
                    
                    # Procesar puertos agrupados
                    for extra in ports.findall("extraports"):
                        count = int(extra.get("count"))
                        state = extra.get("state").capitalize()
                        ports_range = extra.find("extrareasons").get("ports")
                        self.tree.insert('', 'end', values=(
                            f"{count} puertos", 
                            state, 
                            "Varios servicios", 
                            f"Rango: {ports_range}"
                        ))
                        total_ports += count
                        if state == "Closed": closed_ports += count
                        elif state == "Filtered": filtered_ports += count
            
            # Resumen
            summary_text = (
                f"Resumen: {total_ports} puertos escaneados | "
                f"Abiertos: {open_ports} | "
                f"Cerrados: {closed_ports} | "
                f"Filtrados: {filtered_ports}"
            )
            self.lbl_summary.config(text=summary_text)
            
            # Colorear filas
            self.style.configure('open.Treeview', background='#e6ffe6')
            self.style.configure('closed.Treeview', background='#ffe6e6')
            self.style.configure('filtered.Treeview', background='#ffffe6')
            
            for item in self.tree.get_children():
                values = self.tree.item(item)['values']
                if values[1] == "Open":
                    self.tree.item(item, tags=('open',))
                elif values[1] == "Closed":
                    self.tree.item(item, tags=('closed',))
                elif values[1] == "Filtered":
                    self.tree.item(item, tags=('filtered',))
        
        except ET.ParseError as e:
            self.show_error(f"Error en formato XML: {str(e)}")
        except Exception as e:
            self.show_error(f"Error crítico: {str(e)}")
        finally:
            self.root.after(0, self.reset_ui)

    def show_error(self, message):
        messagebox.showerror("Error", message)
        self.reset_ui()

    def reset_ui(self):
        self.scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.update_progress(100)

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()