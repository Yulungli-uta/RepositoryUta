# Instrucciones de Migración - Centralizador de Autenticación

## ❗ Aclaración Importante sobre "AddCentralizadorEntities"

**"AddCentralizadorEntities" NO es algo que ya existe** - es el **nombre que TÚ debes dar** a la nueva migración cuando la crees.

## 🔧 Pasos Correctos para la Migración

### Opción 1: Usar Entity Framework Migrations (Recomendado)

```bash
# 1. Navegar al directorio del proyecto
cd /ruta/a/tu/proyecto/WsSeguUta.AuthSystem.API

# 2. Crear la migración (puedes usar cualquier nombre descriptivo)
dotnet ef migrations add AgregarTablasParaCentralizador

# 3. Aplicar la migración a la base de datos
dotnet ef database update
```

### Opción 2: Ejecutar Script SQL Directamente

Si prefieres ejecutar el SQL manualmente:

```sql
-- Ejecutar el archivo: Database/centralizador_auth_changes.sql
-- En SQL Server Management Studio o tu herramienta preferida
```

## ⚠️ Importante

- **Si usas Opción 1:** Entity Framework creará automáticamente las tablas basándose en las nuevas entidades
- **Si usas Opción 2:** Debes ejecutar el script SQL que ya creé para ti
- **NO hagas ambas** - elige una sola opción para evitar conflictos

## 🔍 Verificar que Funcionó

Después de cualquier opción, verifica que se crearon estas tablas:
- `auth.tbl_Applications`
- `auth.tbl_ApplicationTokens` 
- `auth.tbl_LegacyAuthLog`

## 🚨 Si Tienes Problemas

1. **Error de conexión:** Verifica tu connection string en `appsettings.json`
2. **Permisos:** Asegúrate que tu usuario de BD tiene permisos para crear tablas
3. **Conflictos:** Si ya ejecutaste el SQL, no uses EF migrations para las mismas tablas

