[ 🇺🇸 English ](README.md) | [ 🇪🇸 Español ](README.es.md) | [ 🇧🇷 Português ](README.pt.md)

---

# Analizador de Phishing y Cabeceras de Correo (PHP)

![PHP](https://img.shields.io/badge/PHP-8.0+-777BB4?logo=php&logoColor=white)
![Tema](https://img.shields.io/badge/tema-Triaje%20de%20Phishing-orange)
![Enfoque](https://img.shields.io/badge/enfoque-Seguridad%20de%20Correo-0284c7)

Una herramienta de triaje para correos sospechosos: pega las cabeceras en bruto y obtén los indicadores del remitente, los resultados de SPF / DKIM / DMARC, verificaciones de alineación de dominio y un puntaje de riesgo de 0 a 100 con la explicación de cada punto.

Nace de mi trabajo diario en concientización y prevención de phishing: convierte el "este correo se ve raro" en evidencia concreta y explicable.

![Vista previa del analizador](preview.png)

## Qué se verifica

| Indicador | Por qué importa | Puntos |
|---|---|---|
| `DMARC=fail` | El dominio del `From` falló la política de su propio dueño. La señal más fuerte de spoofing. | +30 |
| `SPF=fail` | La IP de envío no está autorizada por el dominio | +25 |
| `SPF=softfail / none / permerror` | Autorización del remitente débil o ausente | +15 |
| `DKIM=fail` | La firma no coincide: mensaje alterado o falsificado | +25 |
| `DKIM=none / permerror` | Mensaje sin firma | +10 |
| Dominio del `Reply-To` ≠ dominio del `From` | Las respuestas se desvían al atacante. Táctica clásica de BEC / phishing. | +20 |
| Dominio del `Return-Path` ≠ dominio del `From` | Posible spoofing. Peso menor: los newsletters legítimos (SendGrid, Mailchimp…) también lo hacen. | +15 |

Puntaje ≥ 60 → **ALTO**, ≥ 30 → **MEDIO**, si no **BAJO**. Los subdominios del mismo dominio (`mail.empresa.com` / `empresa.com`) se consideran alineados.

## Decisiones de parsing

- **Solo se confía en el `Authentication-Results` superior.** Lo agrega *tu* servidor de correo. El atacante puede escribir `spf=pass` en cualquier otra parte de las cabeceras que controla.
- **Las cabeceras se buscan al inicio de la línea** (`^From:`), así `X-Original-From:` no se confunde con `From:`.
- **Las cabeceras plegadas se despliegan** (RFC 5322): los valores largos que continúan en la línea siguiente se leen correctamente.
- **IP de origen** = la IPv4 de la **última** cabecera `Received`, ya que cada servidor agrega su línea arriba.
- **La entrada se analiza en bruto y se escapa solo en la salida.** Una versión anterior escapaba antes del parsing, lo que rompía los regex y mostraba `&lt;` en pantalla.

## Seguridad de la propia herramienta

La herramienta procesa texto controlado por el atacante, así que también está protegida: cada valor se codifica en HTML al mostrarse, la entrada está limitada a 64 KB y una Content-Security-Policy estricta bloquea cualquier script que intente pasar.

## Pruébalo

```text
Return-Path: <billing@secure-pay-update.ru>
Authentication-Results: mx.empresa.com;
       spf=fail smtp.mailfrom=secure-pay-update.ru;
       dkim=none;
       dmarc=fail header.from=paypal.com
Received: from mail.secure-pay-update.ru ([185.220.101.4])
From: "PayPal" <service@paypal.com>
Reply-To: support@secure-pay-update.ru
Subject: Your account has been limited
```

Resultado esperado: riesgo **ALTO** (puntaje 100), con alertas de SPF, DKIM, DMARC, Reply-To y Return-Path.

## Cómo ejecutar

Requisito: PHP 8.0+.

```bash
git clone https://github.com/MattheusAlfonso/email-header-analyzer.git
cd email-header-analyzer
php -S localhost:8000
```

Abre <http://localhost:8000>.

## Próximos pasos

- [ ] Extraer URLs del cuerpo y consultarlas en feeds de threat intel (VirusTotal, URLhaus)
- [ ] Soporte para IPv6 y detección de IPs privadas en los saltos `Received`
- [ ] Detección de dominios parecidos (`paypa1.com`, punycode)
- [ ] Subir archivos `.eml` directamente

---
*Parte de mi [portafolio de ciberseguridad](https://mattheusalfonso.github.io).*
