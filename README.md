# Nmap-gui

# Escáner de Puertos Profesional

Este es un escáner de puertos profesional desarrollado en Python con una interfaz gráfica creada con `tkinter`. Utiliza `nmap` para realizar escaneos detallados de puertos y servicios en redes.

## Características
- Interfaz amigable con `tkinter` y `ttk`.
- Escaneo de puertos personalizados (rango o individuales).
- Detección de servicios y versiones.
- Barra de progreso para indicar el estado del escaneo.
- Resultados detallados en una tabla interactiva.
- Resumen de puertos abiertos, cerrados y filtrados.

## Requisitos
### Dependencias
- Python 3.x
- `tkinter` (incluido en la mayoría de las distribuciones de Python)
- `nmap`

### Instalación de Nmap
Debes tener `nmap` instalado en tu sistema. Si no lo tienes, instálalo con:
- **Windows**: [Descargar Nmap](https://nmap.org/download.html)

## Ejecución

1. Ejecuta el programa:

   python escanner.py


## Uso
1. Ingresa la IP o dominio a escanear.
2. Especifica los puertos (ejemplo: `80` o `1-1000`).
3. Presiona "Iniciar Escaneo" y observa los resultados en la tabla.


## Contribuciones
Si deseas mejorar este proyecto, siéntete libre de enviar un PR o abrir un issue.

## Licencia
Este proyecto está bajo la licencia MIT.


