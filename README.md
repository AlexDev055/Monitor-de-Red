# Monitor de Red con Análisis de Anomalías

Este proyecto es una herramienta avanzada de monitoreo de red diseñada para analizar el tráfico de red en tiempo real utilizando Python y la librería **Scapy**. El sistema incluye detección de anomalías y un dashboard interactivo que permite visualizar la actividad de la red en tiempo real.

## Características

### Monitoreo Básico
- Captura y análisis de paquetes en tiempo real
- Identificación de dispositivos y protocolos activos en la red
- Análisis detallado de paquetes TCP/IP
- Seguimiento de conexiones y puertos

### Detección de Anomalías
- Análisis estadístico del tráfico de red
- Detección de escaneos de puertos
- Identificación de patrones de tráfico anormales
- Sistema de alertas para comportamientos sospechosos

### Dashboard en Tiempo Real
- Visualización interactiva del tráfico de red
- Gráficos de actividad por IP
- Distribución de protocolos
- Lista de IPs sospechosas
- Actualizaciones automáticas

## Tecnologías

- **Python**: Lenguaje de programación principal
- **Scapy**: Análisis y captura de paquetes de red
- **Dash**: Framework para el dashboard web
- **Plotly**: Visualización de datos
- **Pandas**: Procesamiento y análisis de datos
- **NumPy**: Cálculos estadísticos

## Requisitos

### Dependencias Principales
- Python 3.x
- Librerías necesarias:
  ```bash
  pip install scapy dash pandas numpy plotly
  ```

### Requisitos del Sistema
- Acceso root/administrador para la captura de paquetes
- Sistema operativo compatible con Scapy (Linux/Windows/MacOS)
- Conexión de red activa

## Instalación

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/tuusuario/monitor-red.git
   cd monitor-red
   ```

2. Instalar las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## Uso

1. Iniciar el monitor de red (requiere privilegios de administrador):
   ```bash
   sudo python3 network_monitor.py
   ```

2. Acceder al dashboard:
   - Abrir un navegador web
   - Ir a `http://localhost:8050`

## Características del Dashboard

### Panel Principal
- Gráfico de barras mostrando tráfico por IP
- Gráfico circular de distribución de protocolos
- Lista de IPs sospechosas
- Actualizaciones en tiempo real

### Detección de Anomalías
- Monitoreo estadístico usando Z-scores
- Alertas de comportamientos sospechosos
- Registro de eventos anómalos

## Estructura del Proyecto

```
monitor-red/
├── network_monitor.py     # Script principal
├── requirements.txt       # Dependencias del proyecto
├── README.md             # Documentación
└── dashboard/            # Componentes del dashboard
    └── assets/          # Recursos estáticos
```

## Contribución

Las contribuciones son bienvenidas. Por favor, sigue estos pasos:

1. Fork el proyecto
2. Crea una nueva rama (`git checkout -b feature/nueva-caracteristica`)
3. Realiza tus cambios y commit (`git commit -am 'Añade nueva característica'`)
4. Push a la rama (`git push origin feature/nueva-caracteristica`)
5. Crea un Pull Request

## Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo `LICENSE` para más detalles.

## Contacto

- Nombre del Desarrollador - [@tutwitter](https://twitter.com/tutwitter)
- Email - tu@email.com

## Reconocimientos

- Scapy - [Documentación oficial](https://scapy.net/)
- Dash - [Documentación oficial](https://dash.plotly.com/)
- Plotly - [Documentación oficial](https://plotly.com/)
