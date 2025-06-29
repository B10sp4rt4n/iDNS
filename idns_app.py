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

st.set_page_config(page_title="Analizador de Correos", layout="wide")
st.title("📬 Analizador de Correos – Proveedor y Perfil Comercial")

# Constantes globales
PERSONALES = ["gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "protonmail.com"]
SERVICIOS = [
    {"Identificador": r'include:sendgrid\.net', "Servicio": "SendGrid", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": r'include:mailgun\.org', "Servicio": "Mailgun", "Categoría": "Email Transaccional / Marketing"},
    # ... (otros servicios con regex)
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
                # Verificar expiración
                not_after = dict(x[0] for x in cert['notAfter'])
                exp_date = time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                if time.mktime(exp_date) < time.time():
                    return "Certificado expirado"
                return "Válido"
    except ssl.SSLCertVerificationError:
        return "Error de verificación"
    except socket.timeout:
        return "Timeout conexión"
    except Exception as e:
        return f"Error: {str(e)}"

@lru_cache(maxsize=512)
def extraer_whois(dominio):
    try:
        info = whois.whois(dominio, ignore_returncode=1, timeout=10)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        return creation.strftime("%Y-%m-%d") if creation else "N/D"
    except Exception:
        return "Error/Privado"

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
            r'secureserver': "GoDaddy"
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

# Procesamiento paralelo
def procesar_dominio(dominio):
    spf = obtener_spf(dominio)
    dmarc = obtener_dmarc(dominio)
    ssl = verificar_ssl(dominio)
    whois = extraer_whois(dominio)
    proveedor_mx = detectar_proveedor_avanzado(dominio)
    servicio, categoria = detectar_servicio_y_categoria(spf)
    
    return {
        "Dominio": dominio,
        "SPF": spf,
        "DMARC": dmarc,
        "SSL": ssl,
        "WHOIS (Creación)": whois,
        "Proveedor de Correo": proveedor_mx,
        "Servicio Detectado": servicio,
        "Categoría Funcional": categoria
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
            
        st.info(f"Analizando {len(dominios_unicos)} dominios...")
        progreso = st.progress(0)
        diagnostico = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futuros = {executor.submit(procesar_dominio, dom): dom for dom in dominios_unicos}
            for i, futuro in enumerate(concurrent.futures.as_completed(futuros)):
                diagnostico.append(futuro.result())
                progreso.progress((i + 1) / len(dominios_unicos))
        
        df_diagnostico = pd.DataFrame(diagnostico)
        
        st.subheader("🧠 Diagnóstico Técnico")
        st.dataframe(df_diagnostico)
        
        csv_diag = df_diagnostico.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Descargar diagnóstico", csv_diag, "diagnostico_correos.csv", "text/csv")
        
    except Exception as e:
        st.error(f"Error crítico: {str(e)}")