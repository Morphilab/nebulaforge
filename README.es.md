# NebulaForge

[English](README.md) | **Español**

**Forja entornos Conda seguros y auditables**

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Tests](https://github.com/Morphilab/nebulaforge/actions/workflows/tests.yml/badge.svg)](https://github.com/Morphilab/nebulaforge/actions)
[![codecov](https://codecov.io/gh/Morphilab/nebulaforge/branch/main/graph/badge.svg)](https://codecov.io/gh/Morphilab/nebulaforge)
[![Version](https://img.shields.io/badge/version-2.0.0-blue)](https://github.com/Morphilab/nebulaforge/releases)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow)](https://github.com/PyCQA/bandit)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000)](https://github.com/astral-sh/ruff)
[![Mypy checked](https://img.shields.io/badge/mypy-checked-blue)](http://mypy-lang.org/)
[![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen)](https://github.com/Morphilab/nebulaforge/graphs/commit-activity)

---

## ¿Por qué NebulaForge?

Gestionar entornos Conda de forma segura y reproducible es complicado. NebulaForge lo resuelve con
**controles de seguridad por capas**, registros de auditoría con integridad de cadena SHA-256,
copias de seguridad verificadas, análisis de vulnerabilidades y una interfaz de terminal moderna
basada en Rich, todo en una herramienta extensible.

Tanto si eres un desarrollador individual que valora la reproducibilidad, como un equipo de ciencia
de datos que necesita auditoría, o una organización concienciada con la seguridad que requiere
aislamiento estricto de entornos, NebulaForge tiene un perfil de seguridad para ti.

---

## Características principales

- **Tres interfaces**: TUI basada en Rich, CLI interactiva paso a paso y CLI tradicional con argparse
- **Cuatro perfiles de seguridad**: Low, Medium, High y Paranoid, con controles progresivamente más estrictos
- **Auditoría**: cadena de hash SHA-256 en cada entrada del registro
- **Copias de seguridad seguras**: copias automáticas antes de borrar y antes de restaurar, con verificación de checksum SHA-256
- **Restauración atómica**: la restauración crea un entorno temporal y lo intercambia con rollback; una restauración fallida nunca borra el entorno activo
- **Escáner de vulnerabilidades**: detección integrada de 20 paquetes vulnerables conocidos (con CVEs)
- **Sistema de plugins**: arquitectura extensible con `SecurityScanner` y `HealthCheck` integrados
- **Almacenamiento cifrado**: Fernet (AES-128-CBC + HMAC-SHA256) con PBKDF2 (600k iteraciones) para credenciales y secretos
- **Gestión de sesiones**: tokens criptográficamente seguros con TTL y límite máximo de sesiones
- **Validación estricta**: bloqueo de palabras clave maliciosas, detección de patrones peligrosos y rigor según el perfil
- **Python 3.12**: fijado con uv (`uv.lock` + `.python-version`)

---

## ⚠️ Divulgación de IA / AI Disclosure

**Español:**  
Este proyecto fue desarrollado con asistencia de herramientas de inteligencia artificial. Dada la
naturaleza automatizada de algunos componentes, se recomienda que los usuarios revisen y prueben el
código de forma independiente antes de integrarlo en sus propios sistemas.

**English:**  
This project was developed with assistance from artificial intelligence tools. Given the automated
nature of some components, users are advised to review and test the code independently before
integrating it into their own systems.

---

## Inicio rápido

```bash
# Clonar e instalar (uv, Python 3.12 fijado)
git clone https://github.com/Morphilab/nebulaforge.git
cd nebulaforge
uv sync
uv run nebulaforge --help

# Abrir la TUI (recomendado para nuevos usuarios)
nebulaforge

# O usar la CLI interactiva paso a paso
nebulaforge interactive

# O ejecutar un comando puntual
nebulaforge list
nebulaforge create my-project --python 3.11
nebulaforge diagnostics
```

---

## Ejemplo de uso

```bash
# Crear un entorno con Python 3.11 y paquetes científicos
$ nebulaforge create data-science --python 3.11 --packages numpy pandas scikit-learn

# Instalar un paquete en un entorno existente
$ nebulaforge install data-science matplotlib

# Ejecutar un análisis de seguridad completo
$ nebulaforge diagnostics
🔧 Running security diagnostics...
🔧 Security Diagnostics Report
============================================================
📊 General Status: EXCELLENT (Score: 100/100)
🔐 Profile: Medium Security (medium)

# Crear una copia de seguridad de un entorno
$ nebulaforge backup --create data-science
✅ Backup created successfully: backup_data-science_20260607_101530.yaml

# Cambiar a un perfil de seguridad más estricto
$ nebulaforge config --security-level high
✅ Security level changed to: high

# Activar el modo producción (solo lectura total)
$ nebulaforge config --production-mode on
✅ Production mode enabled

# Los perfiles Medium y superiores exigen confirmación explícita para mutaciones
$ nebulaforge create my-project --python 3.11 --yes
$ nebulaforge remove my-project --yes
```

---

## Comandos disponibles

| Comando                        | Descripción                              |
|--------------------------------|------------------------------------------|
| `nebulaforge`                  | Abrir la interfaz TUI                    |
| `nebulaforge interactive`      | CLI interactiva paso a paso              |
| `nebulaforge list`             | Listar todos los entornos                |
| `nebulaforge create <name>`    | Crear un entorno seguro (`--yes` en Medium o superior) |
| `nebulaforge install <env>`    | Instalar paquetes en un entorno (`--yes` en Medium o superior) |
| `nebulaforge remove <env>`     | Eliminar un entorno, con copia de seguridad (`--yes` en Medium o superior) |
| `nebulaforge info <env>`       | Mostrar detalles del entorno             |
| `nebulaforge update <env>`     | Actualizar paquetes de un entorno (`--yes` en Medium o superior) |
| `nebulaforge backup`           | Gestionar copias (`--create <env>`, `--list`, `--restore <file> --yes`) |
| `nebulaforge diagnostics`      | Ejecutar diagnósticos de seguridad completos |
| `nebulaforge audit`            | Ver el registro de auditoría             |
| `nebulaforge config`           | Cambiar el nivel de seguridad (`--security-level`) o el modo producción (`--production-mode on/off`) |

---

## Perfiles de seguridad

| Perfil    | Comandos permitidos    | Entornos protegidos¹     | Confirmación³ | Timeout máximo | Nombres reservados bloqueados al crear² |
|-----------|------------------------|--------------------------|---------------|----------------|------------------------------------------|
| Low       | conda, mamba, pip      | base, root               | No            | 600s           | base, root                               |
| Medium    | conda, mamba, pip      | base, root, prod         | Sí            | 300s           | + system, conda                          |
| High      | conda, mamba           | base, root, prod         | Sí            | 180s           | + prod                                   |
| Paranoid  | solo conda             | base, root, prod         | Sí            | 120s           | + env, venv                              |

¹ Los *entornos protegidos* no se pueden borrar ni modificar. El conjunto exacto depende del perfil:
Low protege `base` y `root`; Medium y superiores protegen además `prod`. Se rechazan operaciones de
escritura como install, update, clone target, import, restore o la creación con un nombre protegido.
Las operaciones de solo lectura, como backup y export, siguen disponibles.
² Nombres rechazados al crear un entorno nuevo; cada fila acumula los de las filas anteriores (lo aplica `SecurityValidator` mediante el `validation_strictness` de cada perfil).
³ El flag de política `require_confirmation` del perfil. Medium y los perfiles más estrictos exigen confirmación explícita: la TUI y la CLI interactiva la piden, y la CLI de un solo comando requiere `--yes` (sale con código `2` si falta). Los entornos protegidos y el modo producción son denegaciones duras y no se pueden saltar con confirmación.

Cada perfil también ajusta `validation_strictness` para nombres de entorno, nombres de paquete y
nombres de fichero: los perfiles más estrictos rechazan patrones más permisivos y bloquean más
palabras clave reservadas.

---

## Aspectos destacados de seguridad

- **Entornos protegidos** (como mínimo `base` y `root`; `prod` desde Medium) no se pueden borrar ni modificar; nombres reservados como `system` o `conda` se bloquean además al crear, según el perfil
- **Modo producción** desactivado por defecto; cuando se activa, todas las operaciones mutantes pasan a solo lectura (create, install, update, delete, clone target, import y restore). Se cambia con `nebulaforge config --production-mode on|off`
- **Política de confirmación**: los perfiles medium, high y paranoid exigen confirmación explícita para mutaciones. La TUI y la CLI interactiva preguntan; la CLI de un solo comando requiere `--yes` y sale con código `2` si falta
- **Validación estricta de nombres de paquete** con bloqueo progresivo de palabras clave maliciosas (9 términos en Medium, 18 en High, 27 en Paranoid)
- **Endurecimiento del ejecutor de comandos**: `shell=False`, detección de patrones peligrosos a nivel de argumento y bloqueo de flags de conda según el perfil
- **Protección contra path traversal** en nombres de backup/export y rutas de restore. Las importaciones de entornos están estrictamente confinadas al directorio de backups configurado; los symlinks y segmentos `..` que resuelven fuera se rechazan y se registran en auditoría
- **Restauración atómica**: se crea un entorno temporal y se intercambia; el entorno activo se mueve a un nombre de cuarentena único y se hace rollback ante cualquier fallo, de modo que una restauración rota nunca destruye un entorno
- **Integridad de cadena** en cada entrada de auditoría (cadena SHA-256)
- **Integridad de backups** verificada mediante ficheros sidecar `.sha256` separados
- **Almacenes de credenciales y datos cifrados** con derivación de clave PBKDF2 (600.000 iteraciones)
- **Tokens de sesión** generados con `secrets.token_urlsafe(32)` y enmascarados en el estado y los listados
- **Permisos de fichero seguros** (`0o600` para configuración, logs, backups y datos cifrados; `0o700` para directorios)
- **Análisis de dependencias** en CI con Bandit (SAST) y Safety (CVE), ambos bloqueantes; las excepciones documentadas de Safety viven en `.safety-policy.yml` con fecha de caducidad

---

## Arquitectura

NebulaForge se apoya en un modelo de seguridad por capas. El flujo de alto nivel es:

```
TUI / CLI / Interactive CLI
        |
        v
   EnvironmentService   <-- única fuente de verdad para las operaciones
        |
        v
   SecurityManager      <-- orquestador central
        |
   +----+----+----+----+----+----+----+
   |    |    |    |    |    |    |    |
Config Audit Backup Deps Validator Crypto Session
```

`EnvironmentService` es la única API pública que exponen las interfaces; `SecurityManager`
orquesta todos los subcomponentes; cada subcomponente tiene una responsabilidad única y bien
definida.

---

## Pruebas y calidad

```bash
# Ejecutar la suite completa
uv run --no-sync pytest tests/ -v

# Con cobertura (falla por debajo del umbral del 60%)
uv run --no-sync pytest tests/ -v --cov=nebulaforge --cov-report=term-missing

# Linting y comprobación de tipos
uv run --no-sync flake8 nebulaforge/ --count --select=E9,F63,F7,F82 --show-source --statistics
uv run --no-sync ruff check nebulaforge/
uv run --no-sync mypy nebulaforge/ --ignore-missing-imports
uv run --with bandit bandit -r nebulaforge/

# Smoke test con Conda real (se omite por defecto; entornos y pkgs aislados, sin paquetes de red)
NEBULAFORGE_RUN_CONDA_INTEGRATION=1 uv run --no-sync pytest tests/test_conda_integration.py -v
```

CI aplica las comprobaciones críticas de `flake8` (`E9,F63,F7,F82`), `mypy`, la suite completa en
Python 3.12, un umbral de cobertura del 60 % (`--cov-fail-under=60`) y análisis bloqueantes de
Bandit/Safety. La subida a Codecov es opcional: se ejecuta cuando el secreto de repositorio
`CODECOV_TOKEN` está configurado y usa el objetivo de patch de `codecov.yml` (80 %). `ruff`
(configurado en `pyproject.toml`) es el linter de estilo recomendado para desarrollo local. El
smoke test con Conda real se ejecuta en el workflow manual `Conda Integration`
(`.github/workflows/integration.yml`) y forma parte de la lista de comprobación de release.

---

## Estructura del proyecto

```
nebulaforge/                # raíz del repositorio
├── nebulaforge/            # paquete instalable
│   ├── core/               # lógica de seguridad principal
│   │   ├── security_manager.py
│   │   ├── security_validator.py
│   │   ├── security_models.py
│   │   ├── config_manager.py
│   │   ├── audit_logger.py    # integridad de cadena SHA-256
│   │   ├── backup_manager.py  # backups verificados con SHA-256
│   │   ├── encrypted_store.py # Fernet + PBKDF2
│   │   ├── secure_store.py    # almacén cifrado clave-valor con TTL
│   │   ├── secrets.py         # almacén cifrado de credenciales
│   │   ├── session.py         # tokens de sesión criptográficos
│   │   ├── dependency_checker.py
│   │   ├── environment_service.py
│   │   ├── error_handler.py
│   │   ├── interactive_cli.py
│   │   ├── cli_helpers.py
│   │   └── secure_diagnostics.py
│   ├── interfaces/         # capas de usuario
│   │   ├── tui.py          # TUI basada en Rich
│   │   └── cli.py          # CLI con argparse
│   ├── plugins/            # sistema de plugins extensible
│   │   ├── base_plugin.py
│   │   ├── security_scanner.py
│   │   └── health_check.py
│   ├── utils/              # utilidades transversales
│   │   ├── command_runner.py  # wrapper endurecido de subprocess
│   │   ├── formatters.py
│   │   ├── helpers.py
│   │   ├── version_utils.py
│   │   └── vulnerability_db.py
│   └── config/             # definiciones de perfiles de seguridad
│       └── security_profiles.py
├── tests/                  # 27 ficheros de test, 318 tests (el test de Conda real se omite por defecto)
├── .github/workflows/      # CI, integración manual con Conda y análisis de seguridad
├── .safety-policy.yml      # excepciones documentadas y con caducidad de Safety
├── pyproject.toml
├── uv.lock
├── .python-version
├── README.md               # inglés (por defecto)
├── README.es.md            # español
└── SECURITY.md             # política de reporte de vulnerabilidades
```

---

## Contribuir

Las contribuciones son bienvenidas. Abre un issue para comentar cambios importantes antes de enviar
un pull request. En resumen:

1. Haz un fork del repositorio
2. Crea una rama de trabajo (`git checkout -b feat/your-feature`)
3. Instala las dependencias de desarrollo (`uv sync --extra dev`)
4. Haz tus cambios y añade tests
5. Ejecuta la suite (`uv run --no-sync pytest tests/ -v`)
6. Ejecuta los linters (`uv run --no-sync flake8 nebulaforge/ --select=E9,F63,F7,F82`, `uv run --no-sync ruff check nebulaforge/` y `uv run --no-sync mypy nebulaforge/ --ignore-missing-imports`)
7. Abre un Pull Request

---

## Seguridad

Reporta las vulnerabilidades de forma privada siguiendo [SECURITY.md](SECURITY.md). No abras un
issue público para una vulnerabilidad de seguridad.

---

## Licencia

Licencia MIT; consulta [LICENSE](LICENSE).

---

## Autor

**Morphilab**  
[GitHub](https://github.com/Morphilab)
