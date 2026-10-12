# Makako Tool: login y administración en Vercel

Esta versión incorpora acceso privado y un panel de administrador en `/admin`. No hay registro público. Cada cuenta usa exclusivamente las claves asignadas por el administrador. Las cuentas normales no pueden acceder al panel ni leer las claves guardadas.

## 1. Crear PostgreSQL desde Vercel

Abre el proyecto **makakotool** en Vercel y entra en **Storage** o en el **Marketplace** de Vercel. Selecciona **Neon (PostgreSQL)**, crea una base de datos en una región europea y conéctala al proyecto. Revisa el plan y las condiciones antes de confirmar la contratación.

Comprueba que la integración ha añadido **DATABASE_URL** al proyecto. Debe ser la conexión PostgreSQL con pooling, normalmente con `-pooler` en el hostname, y mantener `sslmode=require`. No utilices una URL HTTP de API. Si la variable tiene otro nombre, copia la conexión PostgreSQL a `DATABASE_URL` desde Settings → Environment Variables.

Para probar una rama Preview, utiliza una base o rama de Neon distinta de Production: no conectes una Preview a los datos de producción. Las cuentas y claves se guardan en esta base externa; no se utilizan archivos locales de Vercel.

## 2. Preparar un entorno local o Codespaces

Descarga o cambia a la rama de este cambio antes de fusionarla. Desde la raíz del repositorio:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

En Windows la activación es `.venv\Scripts\activate`.

Edita `.env` en un editor e introduce `DATABASE_URL`. No pegues la conexión ni contraseñas en el chat, en commits o en argumentos de comandos. `.env` está excluido de Git.

Genera estos dos valores **en tu propio terminal**:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Guarda el primer resultado como **SECRET_KEY** y el segundo como **API_KEYS_ENCRYPTION_KEY**, tanto en `.env` como en **Settings → Environment Variables** de Vercel. Utiliza valores distintos para pruebas y producción. No los marques como variables públicas.

| Variable | Uso |
| --- | --- |
| DATABASE_URL | Conexión PostgreSQL externa con TLS y pooling |
| SECRET_KEY | Firma las cookies de sesión |
| API_KEYS_ENCRYPTION_KEY | Cifra y descifra las claves de los usuarios |

Conserva una copia privada de `API_KEYS_ENCRYPTION_KEY`: cambiarla sin migrar los datos impide descifrar las claves guardadas. Cambiar `SECRET_KEY` cierra las sesiones existentes.

## 3. Crear las tablas y el primer administrador

Con `.env` configurado, ejecuta una vez desde la raíz:

```bash
python -m flask --app app init-db
python -m flask --app app create-admin
```

El segundo comando solicita usuario y contraseña sin mostrar la contraseña mientras la escribes. Usa un nombre en minúsculas y una contraseña de entre 12 y 128 caracteres. No existe una cuenta ni contraseña predeterminada. `init-db` crea las tablas que falten y no elimina usuarios existentes.

Los comandos se ejecutan en tu equipo o Codespaces contra la base externa. No necesitas una terminal dentro de Vercel. No se crea ningún administrador automáticamente al visitar la web.

## 4. Revisar y desplegar

Después de configurar las variables y crear las tablas, prueba la rama en Preview con su propia base. Cuando termine la revisión, fusiona el PR a `main`; Vercel desplegará Production. Las tablas y el administrador deben existir también en la base de Production.

Se conserva el `vercel.json` que ya sirve las imágenes, el fondo y el botón de copiar. No hace falta cambiar las rutas estáticas. La página de análisis y los POST quedan protegidos en el servidor. Si faltan variables, la aplicación muestra un error de servicio y no permite analizar IP.

## 5. Administrar cuentas y claves

1. Entra en `/login` con tu cuenta de administrador.
2. Pulsa **Administración**.
3. Crea el usuario y su contraseña inicial.
4. En la tarjeta de ese usuario, introduce sus claves de VirusTotal, AbuseIPDB, AlienVault OTX e IPQualityScore y pulsa **Guardar claves API**.
5. Entrega las credenciales de acceso al usuario por un canal privado.

Un campo de API vacío conserva su valor. Para quitarlo, marca **Eliminar clave**. La página muestra únicamente «Configurada» o «Sin configurar»; no devuelve las claves ya guardadas al navegador. Cada administrador puede configurar también sus propias claves.

Si falta una clave, esa fuente se omite y se indica «Sin configurar». No se utiliza una clave compartida de respaldo. RDAP y S2Grupo siguen siendo fuentes comunes. Las claves no se verifican al guardarlas; el siguiente análisis informa de un rechazo HTTP o falta de cuota del proveedor.

**Desactivar acceso** invalida las sesiones existentes. **Restablecer contraseña** también las invalida. Las cuentas de administrador no se desactivan desde este panel.

## Protección incluida

- Contraseñas con hash scrypt y claves API con cifrado Fernet.
- Claves únicamente en la base cifradas; la cookie contiene ID y versión de sesión, nunca claves API.
- Cookies Secure, HttpOnly y SameSite; sesión de duración fija de 8 horas.
- Tokens CSRF en login, análisis y operaciones de administración; logout únicamente por POST.
- Límite de 10 intentos por usuario en 15 minutos, almacenado en PostgreSQL y compartido entre instancias de Vercel.
- Respuestas privadas sin caché, límite de tamaño de formularios y eliminación de la ruta de diagnóstico.
- Mensajes de fallo de proveedores sin URLs que puedan contener las claves.

`APIKEYS.env` se elimina de esta rama y pasa a estar excluido de Git. Esa eliminación no lo borra del historial. Si contenía claves reales, revócalas y emite nuevas antes de asignarlas a cuentas. Para la CLI se pueden configurar variables en `.env`; la web nunca recurre a esas claves globales.

## Pruebas y límites

```bash
python -m pip install pytest
python -m pytest -q tests
```

Las pruebas locales utilizan SQLite en memoria únicamente como doble de la base y no consultan proveedores reales. Comprueban permisos, CSRF, cifrado, aislamiento de claves, invalidación de sesiones, logout y límite de intentos. La ruta PostgreSQL de concurrencia y las consultas reales requieren validar la Preview con Neon conectado.

Se conserva el análisis síncrono existente, con un máximo de 5 IP por solicitud. El tiempo de consulta depende de las fuentes y del límite de ejecución de tu plan de Vercel; para grandes lotes se necesitará una cola de trabajos. No se almacenan informes ni historial de análisis en esta versión.

Si aparece «Servicio no disponible», comprueba las tres variables y que has ejecutado `init-db`. Si CSRF devuelve 400, recarga la página para renovar el formulario. No expongas las variables ni logs con credenciales al pedir ayuda.
