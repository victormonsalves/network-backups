# Network Backups

Suite de respaldos automatizados de infraestructura de red: extrae la configuración de cada dispositivo, la guarda versionada y registra el resultado. Pensada para correr en un servidor Windows con el Programador de tareas, sin Docker.

Admite cuatro fabricantes, cada uno en su carpeta:

| Vendor | Qué respalda | Método | Fichero principal |
|:--|:--|:--|:--|
| **F5** | Configuración del Big-IP | iControl REST + SCP | `vendors/f5/` |
| **Checkpoint** | Policy y objetos | API Management + SFTP | `vendors/checkpoint/` |
| **Palo Alto** | Configuración XML | XML API + SCP | `vendors/paloalto/` |
| **Fortinet** | Configuración del FortiGate | REST API + SCP | `vendors/fortinet/` |

## Patrón común

Aunque cada fabricante tiene su API, todas las implementaciones siguen el mismo ciclo:

1. **Inventario**: se lee un CSV con los equipos (`grupo`, `host`, credenciales).
2. **Conexión**: login por API o SSH/SFTP con las credenciales del inventario.
3. **Extracción**: se pide la configuración al dispositivo (REST, `show`/`export`, XML API).
4. **Almacenamiento**: se escribe en el repositorio de respaldos con sello de fecha.
5. **Registro**: se anota el resultado en ServiceNow y, si falla, se avisa por correo.

## Estructura

```
.
├── vendors/
│   ├── f5/              Big-IP
│   ├── checkpoint/      Gaia / Management
│   ├── paloalto/        PAN-OS
│   └── fortinet/        FortiGate
├── docs/                notas de cada integración
├── LICENSE
└── README.md
```

## Puesta en marcha

```bash
cd vendors/<vendor>
cp .env.example .env      # rellena host, usuario y clave
python main.py            # pasada manual
```

Para programarlo cada noche, cada carpeta incluye el `.bat`/`.ps1` que registra la tarea en el Programador de tareas de Windows.

## Convenciones

- **Credenciales por entorno**: nunca en el código. `.env` está ignorado por git; solo existe `.env.example`.
- **Inventario aparte**: el CSV de equipos es el único sitio donde viven host y claves.
- **Datos ficticios**: este repositorio es una versión sanitizada; los ejemplos usan valores de prueba.

## Licencia

MIT — ver [`LICENSE`](LICENSE).
