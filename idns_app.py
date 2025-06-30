import pandas as pd
import dns.resolver
import streamlit as st
import socket
import unicodedata
import re
import ssl
import whois
import concurrent.futures
import time
from functools import lru_cache
import requests
import dateutil.parser

st.set_page_config(page_title="Analizador de Correos", layout="wide")
st.title("📬 Analizador de Correos – Proveedor y Perfil Comercial")

# Constantes globales
PERSONALES = ["gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "protonmail.com"]
SERVICIOS = [
    {"Identificador": r'include:sendgrid\.net', "Servicio": "SendGrid", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": r'include:mailgun\.org', "Servicio": "Mailgun", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": r'spf\.protection\.outlook\.com', "Servicio": "Microsoft 365", "Categoría": "Productividad / Colaboración"},
    {"Identificador": r'spf\.google\.com', "Servicio": "Google Workspace", "Categoría": "Productividad / Colaboración"},
    {"Identificador": r'servers\.mcsv\.net', "Servicio": "Mailchimp", "Categoría": "Email Marketing"},
    {"Identificador": r'activecampaign\.com', "Servicio": "ActiveCampaign", "Categoría": "CRM / Email Marketing"},
    {"Identificador": r'kaspcloud\.com', "Servicio": "Kaspersky Cloud", "Categoría": "Seguridad de Correo"},
    {"Identificador": r'proofpoint\.com', "Servicio": "Proofpoint", "Categoría": "Seguridad de Correo"},
    {"Identificador": r'mimecast\.com', "Servicio": "Mimecast", "Categoría": "Seguridad de Correo"},
    {"Identificador": r'pphosted\.com', "Servicio": "Proofpoint", "Categoría": "Seguridad de Correo"},
    {"Identificador": r'sureserver\.com', "Servicio": "GoDaddy", "Categoría": "Hosting / Correo"},
    {"Identificador": r'spf\.messaging\.microsoft\.com', "Servicio": "Microsoft 365", "Categoría": "Productividad / Colaboración"},
    {"Identificador": r'zoho\.com', "Servicio": "Zoho Mail", "Categoría": "Productividad / Colaboración"},
    {"Identificador": r'sendinblue\.com', "Servicio": "Sendinblue", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": r'sparkpostmail\.com', "Servicio": "SparkPost", "Categoría": "Email Transaccional"},
    {"Identificador": r'mta-cluster\.net', "Servicio": "Amazon SES", "Categoría": "Email Transaccional"},
    {"Identificador": r'elasticemail\.com', "Servicio": "Elastic Email", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": r'mailjet\.com', "Servicio": "Mailjet", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": r'mandrillapp\.com', "Servicio": "Mandrill (Mailchimp)", "Categoría": "Email Transaccional"},
    {"Identificador": r'net-spf\.com', "Servicio": "Rackspace", "Categoría": "Hosting / Correo"},
    {"Identificador": r'transip\.email', "Servicio": "TransIP", "Categoría": "Hosting / Correo"},
    {"Identificador": r'ovh\.net', "Servicio": "OVHcloud", "Categoría": "Hosting / Correo"},
    {"Identificador": r'secureserver\.net', "Servicio": "GoDaddy", "Categoría": "Hosting / Correo"}
]
SERVICIOS_DICT = {svc['Identificador']: (svc['Servicio'], svc['Categoría']) for svc in SERVICIOS}
DNS_TIMEOUT = 5
MAX_WORKERS = 15

# Funciones optimizadas con cache y paralelismo
@lru_cache(maxsize=1024)
def obtener_spf(dominio):
    try:
        respuestas = dns.resolver.resolve(dominio, 'TXT', lifetime=DNS_TIMEOUT)
        for r in respuestas:
            txt_record = b''.join(r.strings).decode()
            if "v=spf1" in txt_record:
                return txt_record
    except dns.resolver.NoAnswer:
        return "Sin registros SPF"
    except dns.resolver.Timeout:
        return "Timeout DNS"
    except dns.resolver.NXDOMAIN:
        return "Dominio inexistente"
    except Exception:
        return "Error DNS"
    return "No encontrado"

@lru_cache(maxsize=1024)
def obtener_dmarc(dominio):
    try:
        respuestas = dns.resolver.resolve(f"_dmarc.{dominio}", 'TXT', lifetime=DNS_TIMEOUT)
        for r in respuestas:
            txt_record = b''.join(r.strings).decode()
            if "v=DMARC1" in txt_record:
                return txt_record
        return "Registro DMARC no encontrado"
    except dns.resolver.NXDOMAIN:
        return "Dominio DMARC inexistente"
    except dns.resolver.NoAnswer:
        return "Sin registros DMARC"
    except dns.resolver.Timeout:
        return "Timeout DNS"
    except Exception:
        return "Error DNS"

@lru_cache(maxsize=1024)
def verificar_ssl(dominio):
    try:
        contexto = ssl.create_default_context()
        contexto.check_hostname = True
        contexto.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((dominio, 443), timeout=3) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                
                # Obtener la fecha de expiración directamente del certificado
                not_after_str = cert['notAfter']
                exp_date = dateutil.parser.parse(not_after_str)
                
                from datetime import datetime
                if exp_date < datetime.now():
                    return "Certificado expirado"
                return "Válido"
    except ssl.SSLCertVerificationError:
        return "Error de verificación"
    except socket.timeout:
        return "Timeout conexión"
    except Exception as e:
        return f"Error: {str(e)}"

# Función extraer_whois mejorada
@lru_cache(maxsize=512)
def extraer_whois(dominio):
    try:
        info = whois.whois(dominio, ignore_returncode=1, timeout=15)
        
        creation = info.creation_date
        expiration = info.expiration_date
        updated = info.updated_date

        # Handle lists of dates
        creation = creation[0] if isinstance(creation, list) else creation
        expiration = expiration[0] if isinstance(expiration, list) else expiration
        updated = updated[0] if isinstance(updated, list) else updated

        # Format dates
        creation_str = creation.strftime("%Y-%m-%d") if creation else "N/D"
        expiration_str = expiration.strftime("%Y-%m-%d") if expiration else "N/D"
        updated_str = updated.strftime("%Y-%m-%d") if updated else "N/D"
        
        return {
            "creation_date": creation_str,
            "expiration_date": expiration_str,
            "updated_date": updated_str,
            "status": "OK"
        }
    except whois.parser.WhoisParseError:
        return {"creation_date": "Error", "expiration_date": "Error", "updated_date": "Error", "status": "Error de parseo"}
    except whois.exceptions.WhoisCommandFailed:
        return {"creation_date": "Error", "expiration_date": "Error", "updated_date": "Error", "status": "Comando WHOIS falló"}
    except socket.timeout:
        return {"creation_date": "Error", "expiration_date": "Error", "updated_date": "Error", "status": "Timeout WHOIS"}
    except Exception as e:
        if "rate limit" in str(e).lower():
             return {"creation_date": "Error", "expiration_date": "Error", "updated_date": "Error", "status": "Límite de tasa WHOIS"}
        
        # Check for privacy
        whois_output_str = str(info) if 'info' in locals() and info else ""
        if "privacy" in whois_output_str.lower() or "redacted for privacy" in whois_output_str.lower():
             return {"creation_date": "Privado", "expiration_date": "Privado", "updated_date": "Privado", "status": "Privado/No disponible"}

        return {"creation_date": "Error", "expiration_date": "Error", "updated_date": "Error", "status": f"Error inesperado: {type(e).__name__}"}

@lru_cache(maxsize=1024)
def detectar_proveedor_avanzado(dominio):
    try:
        respuesta = dns.resolver.resolve(dominio, 'MX', lifetime=DNS_TIMEOUT)
        registros = [r.exchange.to_text().rstrip('.') for r in respuesta]
        
        proveedores = {
            r'proofpoint|pphosted': "Proofpoint",
            r'iphmx': "Cisco IronPort",
            r'mimecast': "Mimecast",
            r'barracuda': "Barracuda",
            r'outlook|protection\.outlook': "Microsoft 365",
            r'google|googlemail': "Google Workspace",
            r'zoho': "Zoho Mail",
            r'secureserver': "GoDaddy",
            r'mailgun': "Mailgun",
            r'sendgrid': "SendGrid",
            r'mxlogic': "McAfee Email Protection",
            r'trendmicro': "Trend Micro Email Security"
        }
        
        for registro in registros:
            for patron, proveedor in proveedores.items():
                if re.search(patron, registro, re.IGNORECASE):
                    return proveedor
        return f"Otro ({registros[0]})"
    except dns.resolver.NoAnswer:
        return "Sin registros MX"
    except dns.resolver.Timeout:
        return "Timeout DNS"
    except dns.resolver.NXDOMAIN:
        return "Dominio inexistente"
    except Exception:
        return "Error DNS"

def validar_email(email):
    if not isinstance(email, str):
        return False
    return bool(re.match(r'^[\w\.-]+@[a-zA-Z\d\.-]+\.[a-zA-Z]{2,}$', email))

def limpiar_texto(texto):
    if not isinstance(texto, str):
        return texto
    texto = texto.replace("ñ", "n").replace("Ñ", "N")
    return unicodedata.normalize("NFKD", texto).encode("ASCII", "ignore").decode("utf-8")

def detectar_servicio_y_categoria(spf):
    if not spf or not isinstance(spf, str):
        return "No identificado", "No clasificado"
    
    for patron, (servicio, categoria) in SERVICIOS_DICT.items():
        if re.search(patron, spf):
            return servicio, categoria
    return "No identificado", "No clasificado"

# Funciones de análisis profundo
@lru_cache(maxsize=1024)
def detectar_waf_cdn(dominio):
    try:
        # Intentar HTTPS primero
        try:
            response = requests.get(f"https://{dominio}", timeout=5, verify=False)
        except requests.exceptions.SSLError:
            # Fallback a HTTP si HTTPS falla por SSL
            response = requests.get(f"http://{dominio}", timeout=5)
            
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Patrones comunes de WAF/CDN en encabezados
        if "server" in headers:
            if "cloudflare" in headers["server"] or "cf-ray" in headers:
                return "Cloudflare"
            if "akamai" in headers["server"] or "x-akamai-transformed" in headers:
                return "Akamai"
            if "incapsula" in headers["server"] or "x-iinfo" in headers:
                return "Imperva Incapsula"
            if "sucuri" in headers["server"] or "x-sucuri-id" in headers:
                return "Sucuri"
            if "amazon" in headers["server"] or "x-amz-cf-id" in headers:
                return "Amazon CloudFront"
            if "azure" in headers["server"] or "x-azure-fdid" in headers:
                return "Azure Front Door"
            if "varnish" in headers["server"]:
                return "Varnish Cache (CDN/Proxy)"
            
        # Comprobar CNAME para CDN/WAF
        try:
            cname_answers = dns.resolver.resolve(dominio, 'CNAME', lifetime=DNS_TIMEOUT)
            for r in cname_answers:
                cname_target = r.target.to_text().lower()
                if "cloudflare.com" in cname_target: return "Cloudflare"
                if "akamai.net" in cname_target: return "Akamai"
                if "incapsula.net" in cname_target: return "Imperva Incapsula"
                if "sucuri.net" in cname_target: return "Sucuri"
                if "cloudfront.net" in cname_target: return "Amazon CloudFront"
                if "azureedge.net" in cname_target: return "Azure CDN"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass

        return "No detectado"
    except requests.exceptions.RequestException:
        return "Error HTTP/Conexión"
    except Exception as e:
        return f"Error: {str(e)}"

@lru_cache(maxsize=1024)
def obtener_dns_provider(dominio):
    try:
        ns_answers = dns.resolver.resolve(dominio, 'NS', lifetime=DNS_TIMEOUT)
        ns_records = [str(r.target).lower() for r in ns_answers]

        known_providers = {
            "cloudflare.com": "Cloudflare DNS",
            "google.com": "Google Cloud DNS",
            "awsdns": "AWS Route 53",
            "godaddy.com": "GoDaddy DNS",
            "dnspark.com": "DNS Park",
            "dynect.net": "Dyn (Oracle)",
            "easydns.com": "EasyDNS",
            "namecheap.com": "Namecheap DNS",
            "digitalocean.com": "DigitalOcean DNS",
            "microsoft.com": "Azure DNS (Microsoft)",
            "domaincontrol.com": "GoDaddy DNS",
            "hostgator.com": "HostGator DNS",
            "bluehost.com": "Bluehost DNS",
            "dreamhost.com": "DreamHost DNS",
            "nsone.net": "NS1",
            "dnsmadeeasy.com": "DNS Made Easy"
        }

        detected = []
        for ns in ns_records:
            for pattern, provider_name in known_providers.items():
                if pattern in ns:
                    detected.append(provider_name)
        
        if detected:
            return ", ".join(sorted(list(set(detected))))
        
        return f"Otro ({ns_records[0].split('.')[-2] if ns_records else 'N/D'})"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return "Sin registros NS"
    except Exception as e:
        return f"Error: {str(e)}"

@lru_cache(maxsize=1024)
def detectar_email_security_gateway_profundo(dominio):
    # Reutilizar lógica de detectar_proveedor_avanzado
    mx_provider = detectar_proveedor_avanzado(dominio)

    # Análisis adicional basado en includes de SPF
    spf_record = obtener_spf(dominio)
    if "proofpoint.net" in spf_record.lower():
        return "Proofpoint"
    if "mimecast.com" in spf_record.lower():
        return "Mimecast"
    if "pphosted.com" in spf_record.lower():
        return "Proofpoint"
    if "barracudanetworks.com" in spf_record.lower():
        return "Barracuda"
    if "cisco.com" in spf_record.lower() or "ironport.com" in spf_record.lower():
        return "Cisco Email Security"
    if "trendmicro.com" in spf_record.lower():
        return "Trend Micro Email Security"

    if "Otro" in mx_provider:
        return "No detectado (o ISP/Host genérico)"
    return mx_provider

# Procesamiento para fase inicial
def procesar_dominio_inicial(dominio):
    spf = obtener_spf(dominio)
    dmarc = obtener_dmarc(dominio)
    ssl_status = verificar_ssl(dominio)
    whois_info = extraer_whois(dominio)
    proveedor_mx = detectar_proveedor_avanzado(dominio)
    servicio, categoria = detectar_servicio_y_categoria(spf)
    
    return {
        "Dominio": dominio,
        "SPF": spf,
        "DMARC": dmarc,
        "SSL": ssl_status,
        "WHOIS Creación": whois_info["creation_date"],
        "WHOIS Expiración": whois_info["expiration_date"],
        "WHOIS Actualización": whois_info["updated_date"],
        "WHOIS Estado": whois_info["status"],
        "Proveedor de Correo": proveedor_mx,
        "Servicio Detectado": servicio,
        "Categoría Funcional": categoria
    }

# Procesamiento para análisis profundo
def procesar_dominio_profundo(dominio):
    waf_cdn = detectar_waf_cdn(dominio)
    email_sec_gateway = detectar_email_security_gateway_profundo(dominio)
    dns_provider = obtener_dns_provider(dominio)
    
    return {
        "Dominio": dominio,
        "WAF/CDN": waf_cdn,
        "Email Security Gateway": email_sec_gateway,
        "DNS Provider": dns_provider,
    }

# Interfaz Streamlit
archivo = st.file_uploader("Sube tu archivo CSV de contactos", type="csv")

if archivo:
    try:
        df = pd.read_csv(archivo).rename(columns=lambda x: x.strip())
        
        # Detectar columna de email
        email_cols = [col for col in df.columns if 'email' in col.lower()]
        if not email_cols:
            st.error("No se encontró columna de correo electrónico")
            st.stop()
        
        df["Email"] = df[email_cols[0]]
        df["Dominio"] = df["Email"].apply(lambda x: x.split("@")[-1].lower() if validar_email(x) else "")
        df["Tipo de Correo"] = df["Dominio"].apply(lambda d: "Personal" if d in PERSONALES else "Corporativo" if d else "Desconocido")
        
        dominios_unicos = [d for d in df["Dominio"].dropna().unique() if d]
        
        if not dominios_unicos:
            st.warning("No se encontraron dominios válidos para analizar")
            st.stop()
            
        # PROCESO 1: Extracción Inicial y Diagnóstico Básico
        st.info(f"Analizando {len(dominios_unicos)} dominios únicos (Extracción Inicial)...")
        progreso_raw = st.progress(0)
        diagnostico_raw = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futuros_raw = {executor.submit(procesar_dominio_inicial, dom): dom for dom in dominios_unicos}
            for i, futuro in enumerate(concurrent.futures.as_completed(futuros_raw)):
                try:
                    result = futuro.result()
                    diagnostico_raw.append(result)
                except Exception as e:
                    domain_in_error = futuros_raw[futuro]
                    st.warning(f"Error en escaneo inicial de '{domain_in_error}': {e}")
                    diagnostico_raw.append({
                        "Dominio": domain_in_error, 
                        "SPF": "Error", "DMARC": "Error", "SSL": "Error", 
                        "WHOIS Creación": "Error", "WHOIS Expiración": "Error", 
                        "WHOIS Actualización": "Error", "WHOIS Estado": "Error",
                        "Proveedor de Correo": "Error", "Servicio Detectado": "Error", "Categoría Funcional": "Error"
                    })
                progreso_raw.progress((i + 1) / len(dominios_unicos))

        df_diagnostico_raw = pd.DataFrame(diagnostico_raw)

        # SEGUNDA PASADA WHOIS: Reintento en dominios con errores
        st.info("Realizando segunda pasada WHOIS en dominios con error o información incompleta...")
        
        # Identificar dominios con problemas en WHOIS
        dominios_con_whois_error = df_diagnostico_raw[
            (df_diagnostico_raw["WHOIS Estado"].str.contains("Error|Timeout|Límite|Privado|N/D", case=False, na=False, regex=True)) |
            (df_diagnostico_raw["WHOIS Creación"].isin(["Error", "N/D", "Privado"]))
        ]["Dominio"].unique().tolist()
        
        st.write(f"🔍 Dominios a reintentar WHOIS: {len(dominios_con_whois_error)} encontrados")
        
        if dominios_con_whois_error:
            progreso_whois_retry = st.progress(0)
            resultados_whois_retry = {}
            
            # Procesar reintentos en paralelo
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futuros_whois = {executor.submit(extraer_whois, dom): dom for dom in dominios_con_whois_error}
                for i, futuro in enumerate(concurrent.futures.as_completed(futuros_whois)):
                    dominio = futuros_whois[futuro]
                    try:
                        resultado = futuro.result()
                        resultados_whois_retry[dominio] = resultado
                    except Exception as e:
                        st.warning(f"Error en reintento WHOIS para '{dominio}': {e}")
                        resultados_whois_retry[dominio] = {
                            "creation_date": "Error persistente", 
                            "expiration_date": "Error persistente",
                            "updated_date": "Error persistente",
                            "status": f"Error: {type(e).__name__}"
                        }
                    progreso_whois_retry.progress((i + 1) / len(dominios_con_whois_error))
            
            # Actualizar DataFrame con nuevos datos WHOIS
            for dominio, datos in resultados_whois_retry.items():
                mask = df_diagnostico_raw["Dominio"] == dominio
                df_diagnostico_raw.loc[mask, "WHOIS Creación"] = datos.get("creation_date", "N/D")
                df_diagnostico_raw.loc[mask, "WHOIS Expiración"] = datos.get("expiration_date", "N/D")
                df_diagnostico_raw.loc[mask, "WHOIS Actualización"] = datos.get("updated_date", "N/D")
                df_diagnostico_raw.loc[mask, "WHOIS Estado"] = datos.get("status", "N/D")
            
            st.success("✅ Segunda pasada WHOIS finalizada")
        else:
            st.info("✅ No se encontraron dominios que requieran reintento WHOIS")

        # PROCESO 2: Mejora de Contexto y Análisis Profundo
        st.info(f"Realizando análisis profundo para {len(dominios_unicos)} dominios (Mejora de Contexto)...")
        progreso_deep = st.progress(0)
        diagnostico_deep = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futuros_deep = {executor.submit(procesar_dominio_profundo, dom): dom for dom in dominios_unicos}
            for i, futuro in enumerate(concurrent.futures.as_completed(futuros_deep)):
                try:
                    result_deep = futuro.result()
                    diagnostico_deep.append(result_deep)
                except Exception as e:
                    domain_in_error = futuros_deep[futuro]
                    st.warning(f"Error en análisis profundo de '{domain_in_error}': {e}")
                    diagnostico_deep.append({
                        "Dominio": domain_in_error,
                        "WAF/CDN": "Error", "Email Security Gateway": "Error", 
                        "DNS Provider": "Error"
                    })
                progreso_deep.progress((i + 1) / len(dominios_unicos))

        df_diagnostico_deep = pd.DataFrame(diagnostico_deep)

        # Fusionar y mostrar resultados
        df_final_merged = pd.merge(df_diagnostico_raw, df_diagnostico_deep, on="Dominio", how="left")
        
        st.subheader("📊 Resumen de Análisis Completo")
        st.dataframe(df_final_merged)
        
        csv_final = df_final_merged.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Descargar Análisis Completo", csv_final, "analisis_profundo_correos.csv", "text/csv")
        
    except Exception as e:
        st.error(f"Error crítico al procesar el archivo: {str(e)}")