[ 🇺🇸 English ](README.md) | [ 🇪🇸 Español ](README.es.md) | [ 🇧🇷 Português ](README.pt.md)

---

# 🛡️ Analizador de Cabeceras de Correo y Phishing (PHP/HTML5)

Una herramienta web de Threat Intel desarrollada en PHP y HTML5 que analiza cabeceras de correo en bruto (*raw headers*), extrae Indicadores de Compromiso (IoCs), evalúa autenticaciones SPF/DKIM/DMARC y calcula un nivel de riesgo de Phishing.

![Project Preview](preview.png)

## 🎯 Propósito y Alcance
Inspirado en flujos reales de respuesta a incidentes corporativos (triaje de correos y mitigación de ingeniería social), este sistema automatiza la extracción de datos mediante expresiones regulares (Regex) para detectar *spoofing* e IPs de origen sospechosas.

## 🛡️ Funcionalidades de Análisis
* **Parsing mediante Regex:** Extrae campos claves como `From:`, `Return-Path:`, `IP` de origen y resultados `spf=`, `dkim=`, `dmarc=`.
* **Detección de Discordancia de Dominios:** Identifica diferencias entre el dominio del remitente (`From`) y el camino de retorno (`Return-Path`).
* **Motor de Evaluación de Riesgo:** Suma puntuaciones basadas en fallos de autenticación para clasificar la amenaza en **BAJO**, **MEDIO** o **ALTO**.

---
*Desarrollado como parte del Portafolio de Ciberseguridad para roles internacionales.*