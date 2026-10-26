# ESCUDO IA

Prototipo de protección antifraude para Android. El APK debug se genera en GitHub Actions, sección Artifacts, cuando la compilación finaliza correctamente.

**Importante:** configurar `BuildConfig.API_BASE_URL` en `android/app/build.gradle.kts` con un backend HTTPS real. El dominio `api.example.invalid` es un marcador de posición. No se incluye lectura de SMS ni conversaciones de terceros.

Backend: `docker compose up -d`, después `cd backend && npm install && npm run dev`.
