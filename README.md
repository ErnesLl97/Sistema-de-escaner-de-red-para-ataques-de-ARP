
# 🛡️ Herramienta de ARP Spoofing y Escáner de Red 📡

Este proyecto implementa una herramienta para realizar ataques de ARP Spoofing y escanear redes locales, diseñada con una arquitectura Modelo-Vista-Controlador (MVC) para una mejor organización y mantenibilidad del código. La aplicación proporciona una interfaz gráfica de usuario (GUI) que facilita su uso.




## 💻 Tecnologías Utilizadas

Las siguientes tecnologías y librerías clave han sido empleadas en el desarrollo de este proyecto:

[![My Skills](https://skillicons.dev/icons?i=py,qt,linux)](https://skillicons.dev)

* **Python**: Lenguaje de programación principal del proyecto.
* **PyQt6**: Framework utilizado para la creación de la interfaz gráfica de usuario (GUI).
* **Scapy**: Librería potente para la manipulación y el envío de paquetes de red, fundamental para las funcionalidades de escaneo y spoofing ARP.
* **Módulos estándar de Python**: `os`, `sys`, `re`, `socket`, `ipaddress`, `time`, `threading`, `uuid`, `json` para operaciones de sistema, manejo de datos, expresiones regulares, y concurrencia.

## 📂 Estructura del Proyecto

El proyecto sigue una estructura de carpetas clara y modular, facilitando la comprensión y el desarrollo:

```
├── 📁 __pycache__
│   ├── 📄 controller.cpython-313.pyc
│   ├── 📄 model.cpython-313.pyc
│   └── 📄 view.cpython-313.pyc
├── 📁 data
│   ├── 📄 ou.txt
│   └── 📄 oui.txt
├── 📁 images         <-- ¡Nueva carpeta para tus imágenes!
│   └── 📄 interfaz.png  <-- ¡Aquí va tu captura de pantalla!
├── 📄 controller.py
├── 📄 main.py
├── 📄 model.py
└── 📄 view.py
```
**Descripción de Archivos y Carpetas:**
* `__pycache__`: Contiene los archivos bytecode compilados de Python.
* `data`: Almacena archivos de datos utilizados por la aplicación.
    * `ou.txt`: Probablemente almacena una lista de dispositivos o resultados de escaneos anteriores.
    * `oui.txt`: Base de datos de identificadores únicos de organización (OUI) para resolver fabricantes a partir de direcciones MAC.
* `images`: Carpeta para almacenar imágenes y capturas de pantalla del proyecto (como la interfaz).
* `controller.py`: Implementa el controlador en la arquitectura MVC, manejando la lógica de interacción entre la vista y el modelo.
* `main.py`: Punto de entrada principal de la aplicación, inicializa la GUI y el controlador.
* `model.py`: Contiene la lógica de negocio, las operaciones de red (escaneo, spoofing ARP) y la gestión de datos.
* `view.py`: Define la interfaz gráfica de usuario (GUI) de la aplicación.

## ✨ Ventajas

* **Interfaz Gráfica Intuitiva**: Facilita la interacción con la herramienta para usuarios de diferentes niveles de experiencia.
* **Diseño Modular (MVC)**: La separación de responsabilidades en Modelo, Vista y Controlador mejora la claridad, la mantenibilidad y la escalabilidad del código.
* **Funcionalidades Claras**: Permite tanto el escaneo de la red para descubrir dispositivos como la ejecución de ataques de ARP spoofing.
* **Gestión de Dispositivos**: Posiblemente mantiene un registro de dispositivos escaneados, lo cual es útil para la persistencia.

## 🚧 Desventajas

* **Requisitos de Permisos**: Requiere permisos de superusuario (root en Linux) para ejecutar operaciones de red como el escaneo y el spoofing ARP, lo que puede ser una limitación en ciertos entornos.
* **Uso Ético**: Si bien es una herramienta poderosa para pruebas de seguridad y auditorías, su uso indebido puede tener implicaciones éticas y legales.
* **Detección**: Los ataques de ARP spoofing pueden ser detectados por soluciones de seguridad de red avanzadas.

## 🚫 Limitaciones

* **Dependencia de `scapy`**: La aplicación depende fundamentalmente de la librería `scapy`. Si `scapy` no está instalada o presenta problemas, la aplicación no funcionará, mostrando un mensaje de error crítico.
* **Base de Datos OUI Local**: La resolución de fabricantes de dispositivos se basa en un archivo `oui.txt` local, lo que podría resultar en información desactualizada si no se mantiene al día.
* **Alcance Específico**: La herramienta está enfocada en ARP spoofing y escaneo de red, lo que significa que no ofrece un conjunto completo de funcionalidades para análisis de seguridad de red más amplios.

## 🎯 Uso Laboral y Cotidiano

Esta herramienta puede ser útil en varios escenarios:

* **Laboral (Ciberseguridad / IT)**:
    * **Auditorías de Seguridad**: Realizar pruebas de penetración para identificar vulnerabilidades en la red corporativa.
    * **Análisis Forense**: Investigar incidentes de red y la actividad de dispositivos.
    * **Desarrollo y Pruebas**: Simular ataques ARP para probar la robustez de las defensas de red.
    * **Inventario de Red**: Escanear rápidamente la red para identificar dispositivos conectados y sus direcciones MAC/IP.
* **Cotidiano y Básico (Educación / Hogar)**:
    * **Aprendizaje de Redes**: Entender cómo funcionan los protocolos ARP y los ataques Man-in-the-Middle en un entorno controlado.
    * **Diagnóstico de Red Doméstica**: Identificar todos los dispositivos conectados a tu red Wi-Fi y sus direcciones IP/MAC, útil para solucionar problemas o asegurar tu red.
    * **Detección de Dispositivos Desconocidos**: Verificar si hay dispositivos no autorizados conectados a tu red.

