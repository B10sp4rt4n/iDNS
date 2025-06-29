# iDNS: Asesor Estratégico de Dominio (Etapa de Crecimiento - Fase 1)

## Descripción General

**iDNS** (antes conocido como `scan_app.py`) es una solución en evolución diseñada para ir más allá de la validación básica de correos y dominios. En esta **Etapa de Crecimiento: "El Perfeccionamiento y la Adaptación a Diversos Materiales"**, hemos enfocado la Fase 1 en el **Enriquecimiento del Análisis de Dominio ("Cortador de Alta Precisión")**.

El objetivo de iDNS es proporcionar una **inteligencia de dominio accionable**, transformando datos técnicos en insights de valor para equipos de marketing, ventas, y ciberseguridad. No solo verifica la existencia de un dominio, sino que profundiza en su configuración y postura de seguridad para perfilar "dolores" técnicos, identificar oportunidades de negocio o evaluar riesgos.

## ¿Por qué iDNS? (Complementariedad con soluciones DDI)

Mientras que las soluciones DDI (DNS, DHCP, IPAM) como Infoblox son la columna vertebral para la seguridad y gestión de la red **interna** de una organización (protegiendo a sus usuarios de interactuar con el exterior malicioso), **iDNS opera en el ecosistema digital EXTERNO**.

**iDNS es un complemento estratégico** que ofrece:
* **Inteligencia de Prospección:** Analiza dominios de terceros (clientes potenciales, socios) para identificar vulnerabilidades o configuraciones específicas que revelen una necesidad de tu solución.
* **Higiene de Comunicaciones Externas:** Mejora la entregabilidad de campañas de email marketing y prospección al asegurar la validez y la postura de seguridad de los dominios destino.
* **Monitoreo y Protección de Marca:** Evalúa la configuración de tus propios dominios desde una perspectiva externa (ej. DMARC, SSL) y ayuda a identificar intentos de suplantación.
* **Análisis de Ecosistema:** Permite analizar tendencias y posturas de seguridad en grandes conjuntos de dominios (por sector, región, etc.).

No venimos a reemplazar tu DDI, sino a **potenciarlo** con una visión profunda del "campo de batalla exterior", detectando amenazas y oportunidades que van más allá del perímetro de tu red.

## Características Clave (Fase 1: Enriquecimiento del Análisis)

La versión actual de `idns_app.py` incluye un análisis enriquecido de dominios, proporcionando las siguientes métricas y datos:

* **Validación de Email:** Determina si un email es válido y si pertenece a un dominio personal o corporativo.
* **Registros SPF:** Verifica la política de remitente (Spam Policy Framework) del dominio.
* **Registros DMARC:** Analiza la política de autenticación, informes y conformidad de mensajes basada en dominio.
* **Estado SSL/TLS:** Comprueba la validez y fecha de expiración del certificado SSL del dominio.
* **WHOIS (Fecha de Creación):** Extrae la fecha de creación del dominio para contexto.
* **Detección de Proveedor de Correo (MX):** Identifica servicios como Microsoft 365, Google Workspace, Proofpoint, Mimecast, etc.
* **Registros NS (Servidores de Nombres):** Identifica los servidores DNS autoritativos del dominio.
* **Registros A/AAAA (Direcciones IP):** Resuelve las direcciones IPv4 e IPv6 asociadas al dominio.
* **Detección de WAF/CDN:** Intenta identificar servicios como Cloudflare, Akamai, Sucuri, etc., a través de encabezados HTTP.
* **Análisis de Encabezados de Seguridad HTTP:** Verifica la presencia de encabezados como HSTS (Strict-Transport-Security), CSP (Content-Security-Policy), X-Frame-Options y X-Content-Type-Options.
* **Geolocalización de IP (Placeholder):** Indica dónde se integraría la información geográfica de la IP (requiere API externa).

## Requisitos

Para ejecutar `idns_app.py`, necesitas tener Python 3.x y las siguientes librerías instaladas:

* `pandas`
* `dnspython`
* `streamlit`
* `socket`
* `unicodedata`
* `re`
* `ssl`
* `whois`
* `concurrent.futures`
* `requests`

Puedes instalar todas las dependencias usando pip y el archivo `requirements.txt`:

```bash
pip install -r requirements.txt
