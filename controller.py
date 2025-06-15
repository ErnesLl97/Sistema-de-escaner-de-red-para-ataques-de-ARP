from model import ARPSpooferModel
from view import ARPSpooferView

class ARPSpooferController:
    """
    Controlador en la arquitectura MVC.
    Conecta las interacciones de usuario de la Vista con la lógica del Modelo.
    """
    def __init__(self):
        self.model = ARPSpooferModel()
        self.view = ARPSpooferView(self)
        
        # Conectar señales del Modelo a slots de la Vista
        self.model.logMessage.connect(self.view.update_log_message)
        self.model.statusMessage.connect(self.view.update_status_message)
        self.model.devicesUpdated.connect(self.view.update_device_table)
        self.model.scanButtonState.connect(self.view.set_scan_button_state)
        self.model.startButtonState.connect(self.view.set_start_button_state)
        self.model.stopButtonState.connect(self.view.set_stop_button_state)

        # Configuración inicial de la GUI desde el modelo
        self.view.set_subnet_entry_text(self.model.subnet_to_set)
        self.view.set_start_button_state(True) # Habilitar por defecto si no hay errores de red
        self.view.set_scan_button_state(True) # Habilitar por defecto
        
        # Aplicar el zoom cargado al inicio (se hace en la vista al crearla, llamando a este método)
        self.apply_zoom(None)

    def start_spoofing(self, target_ip):
        """Inicia el ataque de spoofing a través del modelo."""
        self.model.start_arp_spoofing(target_ip)

    def stop_spoofing(self):
        """Detiene el ataque de spoofing a través del modelo."""
        self.model.stop_arp_spoofing()

    def start_scan(self, subnet):
        """Inicia el escaneo de red a través del modelo."""
        self.model.start_scan_network(subnet)

    def log_message(self, message, color):
        """Pasa un mensaje al log de la vista."""
        self.view.update_log_message(message, color)

    def apply_zoom(self, zoom_in_direction=None):
        """
        Aplica el zoom a la interfaz.
        zoom_in_direction: True para acercar, False para alejar, None para aplicar el actual.
        """
        if zoom_in_direction is True:
            self.model.zoom_in()
        elif zoom_in_direction is False:
            self.model.zoom_out()
        
        # Obtiene el porcentaje de zoom actual del modelo y lo aplica a la vista
        current_percentage = self.model.get_current_zoom_percentage()
        self.view.apply_zoom_factor(current_percentage)
        self.view.update_status_message(f"Estado: Zoom al {current_percentage}%", "blue")


    def show_view(self):
        """Muestra la ventana principal de la aplicación."""
        self.view.show()
        # Forzar una primera actualización del estado de los botones y el log inicial
        self.model.statusMessage.emit("Estado: Listo", "black")
        self.model.logMessage.emit("Aplicación iniciada. Verifique permisos de superusuario.", "blue")