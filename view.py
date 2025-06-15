from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QSizePolicy, QSpacerItem
)
from PyQt6.QtGui import QIcon, QPalette, QColor, QTextCharFormat, QTextCursor, QFont
from PyQt6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, QTimer, QCoreApplication
from PyQt6.QtWidgets import QStyle # Para obtener iconos del sistema

class ARPSpooferView(QMainWindow):
    """
    Vista en la arquitectura MVC. Define la interfaz gráfica de usuario (GUI).
    """
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.setWindowTitle("Herramienta de ARP Spoofing y Escáner de Red")
        self.setMinimumSize(800, 600) # Tamaño mínimo para el contenido

        self._apply_theme() # Aplicar tema visual
        self._setup_ui() # Configurar todos los widgets
        self._apply_initial_zoom() # Aplicar el zoom cargado al inicio

    def _apply_theme(self):
        """Aplica un tema visual básico a la aplicación."""
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240)) # Fondo claro
        palette.setColor(QPalette.ColorRole.WindowText, QColor(50, 50, 50)) # Texto oscuro
        palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255)) # Fondo de campos de entrada
        palette.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0)) # Texto de campos de entrada
        palette.setColor(QPalette.ColorRole.Button, QColor(200, 200, 200)) # Fondo de botones
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(0, 0, 0)) # Texto de botones
        self.setPalette(palette)

        # Estilo para los botones de acción
        self.setStyleSheet("""
            QPushButton {
                border: 2px solid #8f8f91;
                border-radius: 5px;
                padding: 8px 15px;
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #f6f7fa, stop: 1 #dadbde);
                font-size: 10pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #dadbde, stop: 1 #f6f7fa);
            }
            QPushButton:pressed {
                background: #c0c0c0;
            }
            QPushButton:disabled {
                background: #e0e0e0;
                color: #a0a0a0;
            }
            #startButton {
                background-color: #4CAF50;
                color: white;
            }
            #startButton:hover {
                background-color: #45a049;
            }
            #startButton:pressed {
                background-color: #3e8e41;
            }
            #stopButton {
                background-color: #f44336;
                color: white;
            }
            #stopButton:hover {
                background-color: #da190b;
            }
            #stopButton:pressed {
                background-color: #b71c1c;
            }
            #scanButton {
                background-color: #2196F3;
                color: white;
            }
            #scanButton:hover {
                background-color: #0b7dda;
            }
            #scanButton:pressed {
                background-color: #0a6cb7;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid gray;
                border-radius: 5px;
                margin-top: 1ex; /* space above text */
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center; /* position at top center */
                padding: 0 3px;
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                                  stop:0 #f0f0f0, stop:1 #e0e0e0);
            }
            QTableWidget {
                alternate-background-color: #f5f5f5;
                gridline-color: #ccc;
            }
            QTableWidget::item:selected {
                background-color: #a0c0e0; /* Blue for selection */
            }
            QHeaderView::section {
                background-color: #d0d0d0;
                padding: 4px;
                border-bottom: 1px solid #c0c0c0;
                font-weight: bold;
            }
        """)


    def _setup_ui(self):
        """Configura los widgets de la interfaz de usuario."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # --- Sección de ARP Spoofing ---
        spoof_group_box = QGroupBox("ARP Spoofing")
        spoof_layout = QVBoxLayout(spoof_group_box)
        main_layout.addWidget(spoof_group_box)

        target_ip_layout = QHBoxLayout()
        target_ip_label = QLabel("Ingrese la IP objetivo:")
        target_ip_label.setToolTip("Dirección IP del dispositivo que se desea atacar.")
        target_ip_layout.addWidget(target_ip_label)
        self.target_ip_entry = QLineEdit()
        self.target_ip_entry.setPlaceholderText("Ej: 192.168.1.100")
        self.target_ip_entry.setToolTip("Campo para introducir la dirección IP del objetivo.")
        target_ip_layout.addWidget(self.target_ip_entry)
        spoof_layout.addLayout(target_ip_layout)

        spoof_buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("Iniciar ARP Spoofing")
        self.start_button.setObjectName("startButton") # Para CSS
        self.start_button.setToolTip("Inicia el ataque de ARP Spoofing contra la IP objetivo.")
        self.start_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton)) # Icono de sistema
        self.start_button.clicked.connect(self._on_start_button_clicked)
        spoof_buttons_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Cancelar ARP Spoofing")
        self.stop_button.setObjectName("stopButton") # Para CSS
        self.stop_button.setToolTip("Detiene el ataque de ARP Spoofing en curso.")
        self.stop_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton)) # Icono de sistema
        self.stop_button.clicked.connect(self._on_stop_button_clicked)
        self.stop_button.setEnabled(False) # Deshabilitado al inicio
        spoof_buttons_layout.addWidget(self.stop_button)
        spoof_layout.addLayout(spoof_buttons_layout)

        # --- Sección de Escáner de Red ---
        scanner_group_box = QGroupBox("Escáner de Red")
        scanner_layout = QVBoxLayout(scanner_group_box)
        main_layout.addWidget(scanner_group_box)

        subnet_scan_layout = QHBoxLayout()
        subnet_label = QLabel("Subred a escanear:")
        subnet_label.setToolTip("Subred en formato CIDR (ej. 192.168.1.0/24).")
        subnet_scan_layout.addWidget(subnet_label)
        self.subnet_entry = QLineEdit()
        self.subnet_entry.setPlaceholderText("Ej: 192.168.1.0/24")
        self.subnet_entry.setToolTip("Campo para introducir la subred a escanear.")
        subnet_scan_layout.addWidget(self.subnet_entry)

        self.scan_button = QPushButton("Escanear Red")
        self.scan_button.setObjectName("scanButton") # Para CSS
        self.scan_button.setToolTip("Inicia un escaneo ARP de la subred especificada.")
        self.scan_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload)) # Icono de sistema
        self.scan_button.clicked.connect(self._on_scan_button_clicked)
        subnet_scan_layout.addWidget(self.scan_button)
        scanner_layout.addLayout(subnet_scan_layout)

        # Tabla para dispositivos descubiertos (QTableWidget es más simple que QTreeView con Model para este caso)
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(4) # IP, MAC, Hostname, Fabricante
        self.device_table.setHorizontalHeaderLabels(["Dirección IP", "Dirección MAC", "Hostname", "Fabricante"])
        self.device_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch) # IP
        self.device_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch) # MAC
        self.device_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch) # Hostname
        self.device_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch) # Fabricante
        self.device_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.device_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.device_table.itemSelectionChanged.connect(self._on_device_selected)
        scanner_layout.addWidget(self.device_table)

        # --- Sección de Salida y Estado ---
        output_group_box = QGroupBox("Salida y Estado")
        output_layout = QVBoxLayout(output_group_box)
        main_layout.addWidget(output_group_box)

        self.output_text_edit = QTextEdit()
        self.output_text_edit.setReadOnly(True)
        self.output_text_edit.setToolTip("Muestra los logs de la aplicación y el progreso de las operaciones.")
        output_layout.addWidget(self.output_text_edit)

        # Barra de estado personalizada con color
        self.status_label = QLabel("Estado: Listo")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-weight: bold; padding: 5px; border: 1px solid #ccc; border-radius: 3px;")
        self.status_label.setToolTip("Muestra el estado actual de la aplicación.")
        output_layout.addWidget(self.status_label)
        
        # --- Controles de Zoom ---
        zoom_layout = QHBoxLayout()
        zoom_layout.addStretch(1) # Empuja los botones a la derecha

        self.zoom_out_button = QPushButton("[-]")
        self.zoom_out_button.setFixedSize(QSize(40, 25))
        self.zoom_out_button.setToolTip("Reduce el tamaño de la interfaz (zoom out).")
        self.zoom_out_button.clicked.connect(self._on_zoom_out_clicked)
        zoom_layout.addWidget(self.zoom_out_button)

        self.zoom_in_button = QPushButton("[+]")
        self.zoom_in_button.setFixedSize(QSize(40, 25))
        self.zoom_in_button.setToolTip("Aumenta el tamaño de la interfaz (zoom in).")
        self.zoom_in_button.clicked.connect(self._on_zoom_in_clicked)
        zoom_layout.addWidget(self.zoom_in_button)
        zoom_layout.addSpacing(10) # Espacio al final

        main_layout.addLayout(zoom_layout)

        # Mensaje de advertencia de privilegios
        warning_label = QLabel("Advertencia: Este programa requiere privilegios de superusuario (root/administrador) para funcionar correctamente.")
        warning_label.setStyleSheet("color: red; font-style: italic; font-size: 8pt;")
        warning_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning_label.setWordWrap(True)
        main_layout.addWidget(warning_label)

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
            ip_item = self.device_table.item(row, 0) # Columna IP
            if ip_item:
                selected_ip = ip_item.text()
                self.target_ip_entry.setText(selected_ip)
                self.controller.log_message(f"IP objetivo seleccionada de la tabla: {selected_ip}", "blue")

    def _on_zoom_in_clicked(self):
        self.controller.apply_zoom(True)

    def _on_zoom_out_clicked(self):
        self.controller.apply_zoom(False)

    def _apply_initial_zoom(self):
        """Aplica el zoom cargado al iniciar la vista."""
        self.controller.apply_zoom(None) # Pasa None para que el controlador aplique el valor actual

    def update_log_message(self, message, color_name):
        """Actualiza el widget de salida con un mensaje de color."""
        color_map = {
            "black": QColor(0, 0, 0),
            "red": QColor(200, 0, 0),
            "green": QColor(0, 150, 0),
            "blue": QColor(0, 0, 200),
            "purple": QColor(128, 0, 128),
            "orange": QColor(255, 128, 0)
        }
        color = color_map.get(color_name, QColor(0, 0, 0)) # Default a negro

        cursor = self.output_text_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        format = QTextCharFormat()
        format.setForeground(color)
        cursor.insertText(message + "\n", format)
        self.output_text_edit.setTextCursor(cursor)
        self.output_text_edit.ensureCursorVisible()

    def update_status_message(self, text, color_name):
        """Actualiza la etiqueta de estado con un mensaje y color."""
        color_map = {
            "black": "black",
            "red": "red",
            "green": "green",
            "blue": "blue",
            "orange": "orange"
        }
        text_color = color_map.get(color_name, "black")
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"font-weight: bold; padding: 5px; border: 1px solid #ccc; border-radius: 3px; color: {text_color};")

    def update_device_table(self, devices):
        """Actualiza la tabla de dispositivos descubiertos."""
        self.device_table.setRowCount(0) # Limpiar tabla
        for row_idx, device in enumerate(devices):
            self.device_table.insertRow(row_idx)
            self.device_table.setItem(row_idx, 0, QTableWidgetItem(device.get('ip', 'N/A')))
            self.device_table.setItem(row_idx, 1, QTableWidgetItem(device.get('mac', 'N/A')))
            self.device_table.setItem(row_idx, 2, QTableWidgetItem(device.get('hostname', 'N/A')))
            self.device_table.setItem(row_idx, 3, QTableWidgetItem(device.get('vendor', 'Desconocido'))) # Nueva columna

    def set_scan_button_state(self, enabled):
        """Habilita/deshabilita el botón de escaneo."""
        self.scan_button.setEnabled(enabled)

    def set_start_button_state(self, enabled):
        """Habilita/deshabilita el botón de inicio de spoofing."""
        self.start_button.setEnabled(enabled)

    def set_stop_button_state(self, enabled):
        """Habilita/deshabilita el botón de detención de spoofing."""
        self.stop_button.setEnabled(enabled)

    def set_subnet_entry_text(self, text):
        """Establece el texto en el campo de entrada de subred."""
        self.subnet_entry.setText(text)

    def apply_zoom_factor(self, percentage):
        """Aplica el factor de zoom a la fuente de la aplicación."""
        # Se obtiene la fuente actual de la aplicación
        current_font = QCoreApplication.font()
        
        # Se calcula el nuevo tamaño de fuente en base al porcentaje
        # Asumimos un tamaño de fuente base para que el zoom funcione de manera consistente
        # Si la fuente base de la aplicación es 10pt, entonces:
        # 75% -> 7.5pt, 100% -> 10pt, 200% -> 20pt
        base_font_size = 10 # Define un tamaño de fuente base en puntos
        new_font_size = base_font_size * (percentage / 100.0)
        
        # Se crea una nueva fuente con el tamaño ajustado
        new_font = QFont(current_font.family(), int(new_font_size))
        
        # Se aplica la nueva fuente a toda la aplicación
        QCoreApplication.setFont(new_font)
        self.update_log_message(f"Tamaño de fuente aplicado: {int(new_font_size)}pt", "blue")
        # Nota: Ajustar el tamaño de la ventana o los widgets individualmente
        # para un responsive perfecto a veces requiere más lógica,
        # pero cambiar la fuente global es un buen punto de partida para el zoom.