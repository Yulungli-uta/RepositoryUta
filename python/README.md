# RepositoryUta Python

Base de migracion progresiva del servicio de seguridad RepositoryUta. Convive
con la implementacion .NET y no cambia sus contratos productivos.

## Desarrollo

Requiere Python 3.13 y `uv`.

```bash
uv sync --frozen
uv run uvicorn repositoryuta.main:app --app-dir src --reload
uv run pytest --cov
uv run ruff check .
```

El modo predeterminado es `validation`: permite probar imagen, health checks y
proxy sin credenciales. `APP_ENV=production` exige una cadena SQL Server desde
`DATABASE_URL_FILE` y falla de forma segura si no esta configurada.

No se debe publicar este bootstrap en la URL productiva hasta completar la
migracion funcional y las pruebas de compatibilidad de JWT/JWKS.

## Configuracion

Las variables anidadas usan `__` como separador (misma convencion `Section__Key`
que ya usa el .NET), por ejemplo `JWT__ISSUER`, `AZURE_AD__CLIENT_ID`,
`LOCAL_AD__SERVER`.

Los secretos reales (no solo rutas/IDs) se leen siempre desde un archivo, nunca
desde el valor directo de la variable de entorno — mismo patron que
`DATABASE_URL_FILE`:

| Variable de entorno | Contenido del archivo |
|---|---|
| `DATABASE_URL_FILE` | connection string completa |
| `AZURE_AD__CLIENT_SECRET_FILE` | client secret de Azure AD |
| `LOCAL_AD__SERVICE_ACCOUNT_PASSWORD_FILE` | password de la cuenta de servicio LDAP |

Estos dos ultimos todavia no los usa ningun router ni servicio (eso llega en la
Fase 4 de la migracion), por lo que su ausencia no bloquea el arranque ni en
`production` — solo se valida que, si se declaran, el archivo sea legible.

`JWT__PRIVATE_KEY_PATH` sigue el mismo patron que ya usa el .NET: no es un
secreto en variable de entorno, ya es una ruta a un archivo de clave.
