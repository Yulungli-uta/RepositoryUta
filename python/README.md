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
