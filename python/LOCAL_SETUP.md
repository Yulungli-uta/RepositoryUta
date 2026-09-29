# RepositoryUta Python — Estructura y configuración local

Guía de referencia para saber **dónde está cada cosa** y **qué archivo tocar**
cuando haga falta cambiar una configuración o un secreto. No duplica valores
reales de secretos — esos viven solo en `python/secrets/*.txt` y en
`VariablesEntorno.txt` (raíz del repo), ambos ignorados por git.

## Cómo levantar el servidor

```bash
cd D:\Git_repository\RepositoryUta\python
./.venv/Scripts/python.exe run_dev.py
```

Arranca en `http://localhost:5010` (puerto fijo, el mismo registrado como
`redirect_uri` de Azure AD) con `--reload` activado. Verificar con:
- `http://localhost:5010/health/ready` → `{"status":"ready"}` si la BD conecta
- `http://localhost:5010/docs` → Swagger UI con todas las rutas

`run_dev.py` (raíz de `python/`) es solo un wrapper de
`uvicorn.run("repositoryuta.main:app", port=5010, reload=True, app_dir="src")` —
si necesitas otro puerto o quitar el reload, edita ese archivo o usa el comando
largo del `README.md`.

## Estructura del proyecto

```
python/
├── run_dev.py              # arranque local, ver arriba
├── .env                    # config real de este entorno (NO se commitea)
├── secrets/                # archivos de secretos referenciados por .env (NO se commitea)
├── pyproject.toml          # dependencias, ruff, pytest, coverage
├── README.md               # instrucciones de desarrollo generales
├── src/repositoryuta/
│   ├── main.py              # arma la FastAPI app, registra TODOS los routers aquí
│   ├── config.py            # Settings — única fuente de verdad de configuración
│   ├── database.py          # engine SQLAlchemy + Session factory
│   ├── logging.py / middleware.py
│   ├── core/                # jwt, exceptions, pagination, rate_limit, ttl_cache, schema_base
│   ├── models/       (12)   # entidades SQLAlchemy (1:1 con las tablas .NET/EF)
│   ├── schemas/      (16)   # DTOs Pydantic (request/response), heredan de ApiModel (camelCase)
│   ├── repositories/ (16)   # acceso a datos puro, sin lógica de negocio
│   ├── services/     (20)   # lógica de negocio — espejo de los *Service.cs del .NET
│   └── routers/      (37)   # endpoints HTTP — espejo de los *Controller.cs del .NET
└── tests/                   # pytest + SQLite en memoria (no toca la BD real)
```

Patrón de cada feature: `models/` (tabla) → `schemas/` (contrato HTTP) →
`repositories/` (queries) → `services/` (reglas de negocio) → `routers/`
(HTTP). Un router nuevo casi siempre implica los 5 archivos.

## Mapa de routers (prefijo → archivo)

| Prefijo | Archivo |
|---|---|
| `/health` | `routers/health.py` |
| `/api/auth` | `routers/auth.py` (login local + Azure PKCE) |
| `/api/app-auth` | `routers/app_auth.py` (auth app-a-app) |
| `/api/menu`, `/api/menu-items` | `routers/menu.py`, `routers/menu_items.py` |
| `/api/users`, `/api/roles`, `/api/permissions` | `routers/users.py`, `roles.py`, `permissions.py` |
| `/api/role-menu-items`, `/api/role-permissions`, `/api/user-roles` | routers RBAC |
| `/api/access-profiles`, `/api/access-profile-roles`, `/api/user-access-profiles` | perfiles de acceso |
| `/api/session-management`, `/api/sessions` | sesiones activas / gestión admin |
| `/api/security-tokens`, `/api/local-credentials` | tokens de reset, credenciales locales |
| `/api/audit-log`, `/api/login-history`, `/api/failed-logins` | auditoría (solo lectura) |
| `/api/user-activity`, `/api/azure-sync-log`, `/api/hr-sync-log` | logs (solo lectura) |
| `/api/app-params` | parámetros de configuración en BD (`auth.tbl_AppParams`) |
| `/api/user-employees` | vínculo usuario ↔ empleado HR |
| `/api/local-ad` | CRUD AD Local (LDAP) |
| `/api/azure-management` | CRUD Microsoft Graph (usuarios/grupos/roles) |
| `/api/licenses` | licencias Office 365 (Graph) |
| `/api/provisioning` | orquesta AD Local + Graph + Licencias para empleados |
| `/api/academic/student-provisioning` | AD Local para estudiantes (sin persistencia propia) |
| `/api/notifications` | CRUD de suscripciones + entrega de webhooks salientes |

## Configuración: cómo funciona

Todo pasa por `src/repositoryuta/config.py::Settings` (pydantic-settings).
Se carga una sola vez por proceso (`@lru_cache`) desde, en este orden:
variables de entorno del sistema → archivo `.env` en el directorio desde
donde se ejecuta uvicorn (normalmente `python/`).

- Las secciones anidadas usan `__` como separador: `AZURE_AD__CLIENT_ID`,
  `LOCAL_AD__SERVER`, `PROVISIONING__DEFAULT_ROLE_NAMES` (misma convención
  `Section__Key` que ya usa el .NET con `dotnet user-secrets`).
- Los **secretos reales** (contraseñas, connection strings, client secrets)
  nunca van directo en `.env` — se declara `..._FILE` apuntando a un archivo
  de texto plano, y `Settings` lo lee y hace `.strip()` al arrancar. Esto es
  igual al patrón `DATABASE_URL_FILE` que ya trae el proyecto.

### Dónde cambiar cada cosa

Todo vive en **un solo archivo**, `python/.env` (salvo los 3 secretos, que van en
archivos aparte por convención de seguridad) — nada de esto está hardcodeado
en el código:

| Quiero cambiar... | Variable en `.env` |
|---|---|
| Password/connection string de la BD | `DATABASE_URL_FILE` → apunta a `python/secrets/database_url.txt` (formato SQLAlchemy, no el de .NET — ver nota abajo) |
| Client secret de Azure AD | `AZURE_AD__CLIENT_SECRET_FILE` → `python/secrets/azure_client_secret.txt` |
| Password de la cuenta de servicio LDAP (`ut4segad`) | `LOCAL_AD__SERVICE_ACCOUNT_PASSWORD_FILE` → `python/secrets/local_ad_password.txt` |
| Llave privada JWT (firma de tokens) | `JWT__PRIVATE_KEY_PATH` → `python/secrets/jwt-private-dev.pem` — **generada solo para desarrollo local**, no es la llave de producción del .NET. Sin esta variable, cada reinicio del proceso genera una llave RSA efímera nueva (mismo `kid`, distinta llave real) y cualquier token ya emitido antes del reinicio deja de validar en HrBackend/HrFrontend (`IDX10511: Signature validation failed`) |
| Tenant/Client ID de Azure, dominio permitido, redirect_uri | `AZURE_AD__*` |
| Servidor/BaseDN/OUs de AD Local | `LOCAL_AD__*` |
| **Orígenes permitidos por CORS** (para que un navegador pueda llamar la API) | `CORS__ORIGINS` (lista JSON, ej. `["http://localhost:5173"]`) — vacío = ningún origen permitido, igual que el .NET si no se configura |
| Headers/métodos permitidos por CORS, credenciales, cache de preflight | `CORS__ALLOWED_HEADERS` / `CORS__ALLOWED_METHODS` / `CORS__ALLOW_CREDENTIALS` / `CORS__PREFLIGHT_MAX_AGE_SECONDS` |
| Puerto del servidor local | `DEV_SERVER_PORT` (lo lee `run_dev.py`, no hay que tocar ese archivo) |
| Ambiente (`development`/`validation`/`production`) | `APP_ENV` — afecta si Swagger (`/docs`) está activo y si los secretos son obligatorios |
| Roles/grupos por defecto al aprovisionar empleados | `PROVISIONING__*` |
| Nivel de log | `LOG_LEVEL` |

**Nota sobre `database_url.txt`**: el `.NET` usa el formato ADO.NET
(`Server=...;Database=...;User Id=...;Password=...`), pero SQLAlchemy
necesita una URL propia:
```
mssql+pyodbc://USUARIO:PASSWORD@HOST:PUERTO/BASE?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes
```
Si la contraseña de BD cambia en `VariablesEntorno.txt`, hay que reconstruir
esta URL a mano en `database_url.txt`, no copiar el string de .NET tal cual.

### Fuente de verdad de los valores reales

Los valores reales (dev y producción comparten las mismas credenciales, no
hay ambiente de prueba separado) están en `VariablesEntorno.txt` (raíz del
repo, ignorado por git). Cuando algo cambie ahí (ej. password de AD rotada),
hay que actualizar el archivo correspondiente en `python/secrets/` a mano —
no se sincronizan solos.

## Troubleshooting

- **Cambiaste código y no ves el efecto**: el `--reload` de uvicorn (WatchFiles)
  a veces no recarga limpio tras varios cambios seguidos en `main.py`/`config.py`.
  Si algo no refleja tu cambio, mata el proceso (`Get-Process python | Stop-Process
  -Force` en PowerShell) y vuelve a correr `run_dev.py` desde cero — no confíes
  ciegamente en el reload automático para cambios de configuración/middleware.
- **Un `.env` local rompe los tests**: `pytest` ignora `python/.env` a propósito
  (`tests/conftest.py` fuerza `Settings.model_config["env_file"] = None` en un
  fixture autouse) — las pruebas nunca deberían depender de lo que haya en el
  filesystem del desarrollador. Si agregas una prueba que instancia `Settings()`
  directamente, no necesitas hacer nada extra, ya queda cubierta.

## Seguridad

- `python/.env` y `python/secrets/` están en `.gitignore` (raíz del repo) —
  nunca deberían aparecer en `git status` como "nuevo archivo". Si aparecen,
  revisar el `.gitignore` antes de hacer `git add`.
- Estas credenciales son las de la BD/Azure/AD **reales**, compartidas con el
  .NET en producción — cualquier prueba de escritura (crear, aprovisionar,
  cambiar password) desde el servidor local toca datos reales.
- `docs_enabled` (Swagger) se apaga solo en `production` — no depende de este
  archivo, es una decisión de `config.py`.
