"""
🔪 Divisor de PDF PRO v2.0 - Aplicação Web Completa
16 operações | Preview de páginas | Histórico | Metadados | Marca d'água | +
"""

from flask import Flask, render_template, request, send_file, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import os, shutil, base64, io, zipfile, uuid, sqlite3, threading, re
from datetime import datetime
from PyPDF2 import PdfReader, PdfWriter, PdfMerger
try:
    import requests as req_lib
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'outputs'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf'}

# ─── Registo seguro de sessões (server-side) ─────────────────────────────────
_SESSION_FILES = {}
_SESSION_LOCK  = threading.Lock()

def session_set(session_id, filepath):
    with _SESSION_LOCK:
        _SESSION_FILES[session_id] = os.path.abspath(filepath)

def session_get(session_id):
    with _SESSION_LOCK:
        return _SESSION_FILES.get(session_id)

def session_delete(session_id):
    with _SESSION_LOCK:
        _SESSION_FILES.pop(session_id, None)

# ─── Auditoria (SQLite) ───────────────────────────────────────────────────────
AUDIT_DB = 'auditoria.db'
AUDIT_PASSWORD = os.environ.get('AUDIT_PASSWORD', 'admin123')

def get_db():
    conn = sqlite3.connect(AUDIT_DB, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    return conn

def init_audit_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS acessos (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ts               TEXT NOT NULL,
            ip               TEXT,
            pais             TEXT,
            pais_code        TEXT,
            regiao           TEXT,
            cidade           TEXT,
            zip_geo          TEXT,
            lat              REAL,
            lon              REAL,
            timezone_geo     TEXT,
            isp              TEXT,
            org              TEXT,
            asn              TEXT,
            proxy            INTEGER DEFAULT 0,
            vpn              INTEGER DEFAULT 0,
            hosting          INTEGER DEFAULT 0,
            user_agent       TEXT,
            browser          TEXT,
            browser_version  TEXT,
            browser_engine   TEXT,
            os_name          TEXT,
            os_version       TEXT,
            device_type      TEXT,
            is_bot           INTEGER DEFAULT 0,
            screen_res       TEXT,
            viewport         TEXT,
            color_depth      INTEGER,
            lang_browser     TEXT,
            timezone_browser TEXT,
            referrer         TEXT,
            touch_support    INTEGER DEFAULT 0,
            connection_type  TEXT,
            rota             TEXT,
            metodo           TEXT,
            operacao         TEXT,
            filename         TEXT,
            status           INTEGER
        )
    ''')
    cols_needed = [
        ('pais_code','TEXT'), ('zip_geo','TEXT'), ('timezone_geo','TEXT'),
        ('org','TEXT'), ('asn','TEXT'), ('proxy','INTEGER'),
        ('vpn','INTEGER'), ('hosting','INTEGER'),
        ('browser','TEXT'), ('browser_version','TEXT'), ('browser_engine','TEXT'),
        ('os_name','TEXT'), ('os_version','TEXT'), ('device_type','TEXT'),
        ('is_bot','INTEGER'), ('screen_res','TEXT'), ('viewport','TEXT'),
        ('color_depth','INTEGER'), ('lang_browser','TEXT'),
        ('timezone_browser','TEXT'), ('referrer','TEXT'),
        ('touch_support','INTEGER'), ('connection_type','TEXT'),
    ]
    existing = {r[1] for r in conn.execute('PRAGMA table_info(acessos)').fetchall()}
    for col, typ in cols_needed:
        if col not in existing:
            conn.execute(f'ALTER TABLE acessos ADD COLUMN {col} {typ}')
    conn.commit(); conn.close()

init_audit_db()

def get_real_ip():
    for h in ('X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'):
        v = request.headers.get(h)
        if v:
            return v.split(',')[0].strip()
    return request.remote_addr

def parse_ua(ua_str):
    ua = ua_str or ''
    result = {'browser':'Desconhecido','browser_version':'','browser_engine':'',
              'os_name':'Desconhecido','os_version':'','device_type':'Desktop','is_bot':0}
    ul = ua.lower()
    bots = ['bot','crawl','spider','slurp','mediapartners','adsbot','facebookexternalhit',
            'twitterbot','linkedinbot','whatsapp','telegram','pinterest','slack','discord']
    if any(b in ul for b in bots):
        result['is_bot'] = 1
        result['device_type'] = 'Bot'
        result['browser'] = 'Bot'
        return result
    if any(x in ul for x in ['mobile','android','iphone','ipod','blackberry','windows phone']):
        result['device_type'] = 'Mobile'
    elif any(x in ul for x in ['ipad','tablet']):
        result['device_type'] = 'Tablet'
    def _v(pattern):
        m = re.search(pattern, ua, re.I)
        return m.group(1) if m else ''
    if 'Edg/' in ua or 'EdgA/' in ua:
        result['browser'] = 'Edge'; result['browser_version'] = _v(r'Edg[A-Z]?/([\d.]+)'); result['browser_engine'] = 'Blink'
    elif 'OPR/' in ua or 'Opera' in ua:
        result['browser'] = 'Opera'; result['browser_version'] = _v(r'OPR/([\d.]+)') or _v(r'Opera/([\d.]+)'); result['browser_engine'] = 'Blink'
    elif 'Chrome/' in ua and 'Safari' in ua:
        result['browser'] = 'Chrome'; result['browser_version'] = _v(r'Chrome/([\d.]+)'); result['browser_engine'] = 'Blink'
    elif 'Firefox/' in ua:
        result['browser'] = 'Firefox'; result['browser_version'] = _v(r'Firefox/([\d.]+)'); result['browser_engine'] = 'Gecko'
    elif 'Safari/' in ua and 'Chrome' not in ua:
        result['browser'] = 'Safari'; result['browser_version'] = _v(r'Version/([\d.]+)'); result['browser_engine'] = 'WebKit'
    elif 'MSIE' in ua or 'Trident' in ua:
        result['browser'] = 'Internet Explorer'; result['browser_version'] = _v(r'(?:MSIE |rv:)([\d.]+)'); result['browser_engine'] = 'Trident'
    elif 'SamsungBrowser/' in ua:
        result['browser'] = 'Samsung Browser'; result['browser_version'] = _v(r'SamsungBrowser/([\d.]+)'); result['browser_engine'] = 'Blink'
    if 'Windows NT' in ua:
        result['os_name'] = 'Windows'
        nt_map = {'10.0':'10/11','6.3':'8.1','6.2':'8','6.1':'7','6.0':'Vista','5.1':'XP'}
        nt = _v(r'Windows NT ([\d.]+)')
        result['os_version'] = nt_map.get(nt, nt)
    elif 'Android' in ua:
        result['os_name'] = 'Android'; result['os_version'] = _v(r'Android ([\d._]+)')
    elif 'iPhone OS' in ua or 'CPU OS' in ua:
        result['os_name'] = 'iOS'; result['os_version'] = _v(r'(?:iPhone OS|CPU OS) ([\d_]+)').replace('_','.')
    elif 'Mac OS X' in ua:
        result['os_name'] = 'macOS'; result['os_version'] = _v(r'Mac OS X ([\d_.]+)').replace('_','.')
    elif 'Linux' in ua:
        result['os_name'] = 'Linux'
    elif 'CrOS' in ua:
        result['os_name'] = 'ChromeOS'
    return result

def geo_lookup_async(ip, row_id):
    if not REQUESTS_AVAILABLE or ip in ('127.0.0.1', '::1', 'localhost', ''):
        return
    try:
        fields = 'status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting'
        r = req_lib.get(f'https://ip-api.com/json/{ip}?fields={fields}', timeout=5)
        d = r.json()
        if d.get('status') == 'success':
            asn_raw = d.get('as', '')
            asn_num = asn_raw.split(' ')[0] if asn_raw else ''
            conn = get_db()
            conn.execute('''UPDATE acessos SET
                pais=?,pais_code=?,regiao=?,cidade=?,zip_geo=?,
                lat=?,lon=?,timezone_geo=?,isp=?,org=?,asn=?,
                proxy=?,hosting=?
                WHERE id=?''',
                (d.get('country'), d.get('countryCode'), d.get('regionName'),
                 d.get('city'), d.get('zip'), d.get('lat'), d.get('lon'),
                 d.get('timezone'), d.get('isp'), d.get('org'), asn_num,
                 int(d.get('proxy', False)), int(d.get('hosting', False)),
                 row_id))
            conn.commit(); conn.close()
    except Exception:
        pass

def log_access(operacao=None, filename=None, status=200, client_data=None):
    ip = get_real_ip()
    ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    ua_str = request.headers.get('User-Agent', '')[:300]
    ua_parsed = parse_ua(ua_str)
    cd = client_data or {}
    conn = get_db()
    cur = conn.execute('''
        INSERT INTO acessos
          (ts,ip,rota,metodo,operacao,filename,status,user_agent,
           browser,browser_version,browser_engine,os_name,os_version,device_type,is_bot,
           screen_res,viewport,color_depth,lang_browser,timezone_browser,
           referrer,touch_support,connection_type)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (ts, ip, request.path, request.method, operacao, filename, status, ua_str,
         ua_parsed['browser'], ua_parsed['browser_version'], ua_parsed['browser_engine'],
         ua_parsed['os_name'], ua_parsed['os_version'], ua_parsed['device_type'], ua_parsed['is_bot'],
         cd.get('screen_res'), cd.get('viewport'), cd.get('color_depth'),
         cd.get('lang'), cd.get('timezone'), cd.get('referrer','')[:200],
         int(cd.get('touch', 0)), cd.get('connection_type','')))
    row_id = cur.lastrowid
    conn.commit(); conn.close()
    threading.Thread(target=geo_lookup_async, args=(ip, row_id), daemon=True).start()
    return row_id

# ─── Dependências opcionais ───────────────────────────────────────────────────
try:
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.lib.colors import Color
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import fitz  # pymupdf
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

try:
    import pytesseract
    from PIL import Image as PILImage
    _tess_paths = [
        r'C:\Program Files\Tesseract-OCR\tesseract.exe',
        r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
    ]
    import os as _os
    for _p in _tess_paths:
        if _os.path.exists(_p):
            pytesseract.pytesseract.tesseract_cmd = _p
            break
    pytesseract.get_tesseract_version()
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

try:
    from docx2pdf import convert as docx2pdf_convert
    DOCX2PDF_AVAILABLE = True
except ImportError:
    DOCX2PDF_AVAILABLE = False

try:
    from PIL import Image as PILImage2
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ─── Helpers ─────────────────────────────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_pdf_info(filepath):
    reader = PdfReader(filepath)
    meta = reader.metadata or {}
    marcadores = []
    def walk_outline(outline, d=0):
        for item in outline:
            if isinstance(item, list):
                walk_outline(item, d + 1)
            else:
                try:
                    pg = reader.get_destination_page_number(item) + 1
                    marcadores.append({'titulo': str(item.title), 'pagina': pg, 'nivel': d})
                except:
                    pass
    try:
        if reader.outline:
            walk_outline(reader.outline)
    except:
        pass
    return {
        'total_paginas': len(reader.pages),
        'titulo': getattr(meta, 'title', '') or '',
        'autor': getattr(meta, 'author', '') or '',
        'assunto': getattr(meta, 'subject', '') or '',
        'criptografado': reader.is_encrypted,
        'tamanho_mb': round(os.path.getsize(filepath) / (1024 * 1024), 2),
        'marcadores': marcadores,
        'tem_marcadores': len(marcadores) > 0,
        'qtd_marcadores': len(marcadores),
        'reportlab': REPORTLAB_AVAILABLE,
        'pymupdf': PYMUPDF_AVAILABLE,
    }

# ─── Funções de Processamento ─────────────────────────────────────────────────

def dividir_por_partes(caminho_pdf, num_partes, pasta_saida):
    reader = PdfReader(caminho_pdf)
    total = len(reader.pages)
    num_partes = max(2, min(num_partes, total))
    ppp = total // num_partes
    extras = total % num_partes
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    arquivos, pg = [], 0
    for i in range(num_partes):
        w = PdfWriter()
        n = ppp + (1 if i < extras else 0)
        inicio = pg + 1
        for _ in range(n):
            if pg < total:
                w.add_page(reader.pages[pg]); pg += 1
        nome = f"{nome_base}_parte_{i+1}_de_{num_partes}.pdf"
        with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
        arquivos.append({'nome': nome, 'paginas': n, 'pagina_inicio': inicio, 'pagina_fim': pg})
    return arquivos, total

def dividir_por_paginas(caminho_pdf, paginas_por_parte, pasta_saida):
    reader = PdfReader(caminho_pdf)
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    arquivos, pg, parte = [], 0, 1
    while pg < total:
        w = PdfWriter()
        inicio = pg + 1; cnt = 0
        for _ in range(paginas_por_parte):
            if pg < total:
                w.add_page(reader.pages[pg]); pg += 1; cnt += 1
        nome = f"{nome_base}_parte_{parte}_paginas_{inicio}-{pg}.pdf"
        with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
        arquivos.append({'nome': nome, 'paginas': cnt, 'pagina_inicio': inicio, 'pagina_fim': pg})
        parte += 1
    return arquivos, total

def extrair_paginas(caminho_pdf, paginas, pasta_saida):
    reader = PdfReader(caminho_pdf)
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    w = PdfWriter()
    validas = sorted(set(p for p in paginas if 1 <= p <= total))
    if not validas:
        raise ValueError("Nenhuma página válida selecionada")
    for p in validas:
        w.add_page(reader.pages[p - 1])
    nome = f"{nome_base}_paginas_extraidas.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': len(validas), 'paginas_lista': validas}], total

def extrair_intervalo(caminho_pdf, inicio, fim, pasta_saida):
    reader = PdfReader(caminho_pdf)
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    inicio, fim = max(1, inicio), min(total, fim)
    if inicio > fim:
        raise ValueError("Intervalo inválido")
    w = PdfWriter()
    for i in range(inicio - 1, fim):
        w.add_page(reader.pages[i])
    nome = f"{nome_base}_paginas_{inicio}-{fim}.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': fim - inicio + 1, 'pagina_inicio': inicio, 'pagina_fim': fim}], total

def mesclar_pdfs(arquivos, pasta_saida, nome_saida):
    merger = PdfMerger()
    total = 0
    for a in arquivos:
        r = PdfReader(a); total += len(r.pages); merger.append(a)
    nome = f"{nome_saida}.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: merger.write(f)
    merger.close()
    return [{'nome': nome, 'paginas': total, 'arquivos_mesclados': len(arquivos)}], total

def rotacionar_paginas(caminho_pdf, angulo, paginas, pasta_saida):
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    pgs = set(paginas) if paginas else set(range(1, total + 1))
    for i, page in enumerate(reader.pages):
        if (i + 1) in pgs:
            page.rotate(angulo)
        w.add_page(page)
    nome = f"{nome_base}_rotacionado.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': total, 'paginas_rotacionadas': len(pgs), 'angulo': angulo}], total

def remover_paginas(caminho_pdf, paginas_remover, pasta_saida):
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    pgs = set(paginas_remover)
    mantidas = 0
    for i, page in enumerate(reader.pages):
        if (i + 1) not in pgs:
            w.add_page(page); mantidas += 1
    if mantidas == 0:
        raise ValueError("Não é possível remover todas as páginas")
    nome = f"{nome_base}_editado.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': mantidas, 'paginas_removidas': len(pgs)}], total

def reordenar_paginas(caminho_pdf, nova_ordem, pasta_saida):
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    for p in nova_ordem:
        if 1 <= p <= total:
            w.add_page(reader.pages[p - 1])
    nome = f"{nome_base}_reordenado.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': len(nova_ordem)}], total

def adicionar_senha(caminho_pdf, senha, pasta_saida):
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    for page in reader.pages:
        w.add_page(page)
    w.encrypt(senha)
    nome = f"{nome_base}_protegido.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': len(reader.pages), 'protegido': True}], len(reader.pages)

def comprimir_pdf(caminho_pdf, pasta_saida):
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    for page in reader.pages:
        page.compress_content_streams()
        w.add_page(page)
    nome = f"{nome_base}_comprimido.pdf"
    cs = os.path.join(pasta_saida, nome)
    with open(cs, 'wb') as f: w.write(f)
    to = os.path.getsize(caminho_pdf); tn = os.path.getsize(cs)
    return [{
        'nome': nome, 'paginas': len(reader.pages),
        'tamanho_original_mb': round(to / 1024 / 1024, 2),
        'tamanho_novo_mb': round(tn / 1024 / 1024, 2),
        'reducao_percentual': round((1 - tn / to) * 100, 1) if to > 0 else 0
    }], len(reader.pages)

# ─── Novas Funções ────────────────────────────────────────────────────────────

def remover_senha_pdf(caminho_pdf, senha_atual, pasta_saida):
    """Remove a senha de proteção do PDF"""
    reader = PdfReader(caminho_pdf)
    if reader.is_encrypted:
        result = reader.decrypt(senha_atual)
        if result == 0:
            raise ValueError("Senha incorreta ou formato não suportado")
    w = PdfWriter()
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    for page in reader.pages:
        w.add_page(page)
    nome = f"{nome_base}_sem_senha.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': len(reader.pages), 'protegido': False}], len(reader.pages)

def adicionar_marca_dagua(caminho_pdf, texto, opacidade, angulo, pasta_saida):
    """Adiciona marca d'água de texto ao PDF"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab não instalado. Execute: py -m pip install reportlab")
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    for page in reader.pages:
        mb = page.mediabox
        larg, alt = float(mb.width), float(mb.height)
        packet = io.BytesIO()
        c = rl_canvas.Canvas(packet, pagesize=(larg, alt))
        c.setFillColor(Color(0.4, 0.4, 0.4, alpha=float(opacidade)))
        c.translate(larg / 2, alt / 2)
        c.rotate(float(angulo))
        font_size = max(12, min(larg, alt) * 0.1)
        c.setFont("Helvetica-Bold", font_size)
        c.drawCentredString(0, 0, texto)
        c.save(); packet.seek(0)
        page.merge_page(PdfReader(packet).pages[0])
        w.add_page(page)
    nome = f"{nome_base}_marca_dagua.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': len(reader.pages), 'marca': texto}], len(reader.pages)

def converter_para_imagens(caminho_pdf, formato, dpi, pasta_saida):
    """Converte páginas do PDF em imagens PNG ou JPG"""
    if not PYMUPDF_AVAILABLE:
        raise ImportError("pymupdf não instalado. Execute: py -m pip install pymupdf")
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    doc = fitz.open(caminho_pdf)
    arquivos = []
    mat = fitz.Matrix(dpi / 72, dpi / 72)
    for i, page in enumerate(doc):
        pix = page.get_pixmap(matrix=mat)
        ext = formato.lower()
        if ext == 'jpg':
            ext = 'jpeg'
        nome = f"{nome_base}_pagina_{i+1:03d}.{formato}"
        save_path = os.path.join(pasta_saida, nome)
        pix.save(save_path)
        arquivos.append({'nome': nome, 'pagina': i + 1, 'tipo': 'imagem',
                         'largura': pix.width, 'altura': pix.height})
    doc.close()
    return arquivos, len(arquivos)

def adicionar_numeracao(caminho_pdf, posicao, estilo, pasta_saida):
    """Adiciona numeração de páginas ao PDF"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab não instalado. Execute: py -m pip install reportlab")
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    for i, page in enumerate(reader.pages):
        mb = page.mediabox
        larg, alt = float(mb.width), float(mb.height)
        packet = io.BytesIO()
        c = rl_canvas.Canvas(packet, pagesize=(larg, alt))
        c.setFont("Helvetica", 11)
        c.setFillColorRGB(0.2, 0.2, 0.2)
        if estilo == 'numero':
            texto = str(i + 1)
        elif estilo == 'numero_total':
            texto = f"{i+1}/{total}"
        else:
            texto = f"Página {i+1} de {total}"
        m = 28
        y = m if 'bottom' in posicao else alt - m
        if 'center' in posicao:
            c.drawCentredString(larg / 2, y, texto)
        elif 'right' in posicao:
            c.drawRightString(larg - m, y, texto)
        else:
            c.drawString(m, y, texto)
        c.save(); packet.seek(0)
        page.merge_page(PdfReader(packet).pages[0])
        w.add_page(page)
    nome = f"{nome_base}_numerado.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': total}], total

def editar_metadados_pdf(caminho_pdf, titulo, autor, assunto, palavras_chave, pasta_saida):
    """Edita os metadados do PDF"""
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    for page in reader.pages:
        w.add_page(page)
    w.add_metadata({
        '/Title': titulo or '',
        '/Author': autor or '',
        '/Subject': assunto or '',
        '/Keywords': palavras_chave or '',
        '/Producer': 'Divisor de PDF PRO v2.0',
        '/ModDate': datetime.now().strftime("D:%Y%m%d%H%M%S"),
    })
    nome = f"{nome_base}_metadados.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': len(reader.pages), 'titulo': titulo, 'autor': autor}], len(reader.pages)

def dividir_por_marcadores_pdf(caminho_pdf, pasta_saida):
    """Divide o PDF por marcadores/bookmarks"""
    reader = PdfReader(caminho_pdf)
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    if not reader.outline:
        raise ValueError("Este PDF não possui marcadores (bookmarks)")
    caps = []
    def walk(outline, d=0):
        for item in outline:
            if isinstance(item, list):
                walk(item, d + 1)
            else:
                try:
                    pg = reader.get_destination_page_number(item)
                    caps.append({'titulo': str(item.title), 'pagina': pg})
                except:
                    pass
    walk(reader.outline)
    if not caps:
        raise ValueError("Não foi possível processar os marcadores")
    caps.sort(key=lambda x: x['pagina'])
    caps = [c for i, c in enumerate(caps) if i == 0 or c['pagina'] != caps[i-1]['pagina']]
    arquivos = []
    for i, cap in enumerate(caps):
        inicio = cap['pagina']
        fim = caps[i + 1]['pagina'] if i + 1 < len(caps) else total
        if inicio >= fim:
            continue
        ww = PdfWriter()
        for p in range(inicio, fim):
            if p < total:
                ww.add_page(reader.pages[p])
        if not ww.pages:
            continue
        titulo_safe = "".join(c for c in cap['titulo'] if c.isalnum() or c in ' -_')[:35].strip() or f"secao_{i+1}"
        nome = f"{nome_base}_{i+1:02d}_{titulo_safe}.pdf"
        with open(os.path.join(pasta_saida, nome), 'wb') as f: ww.write(f)
        arquivos.append({
            'nome': nome, 'paginas': fim - inicio,
            'pagina_inicio': inicio + 1, 'pagina_fim': fim,
            'titulo': cap['titulo']
        })
    if not arquivos:
        raise ValueError("Nenhuma secção foi gerada")
    return arquivos, total

# ─── Novas Funcionalidades Avançadas ────────────────────────────────────────

def imagens_para_pdf(caminhos, pasta_saida, nome_saida):
    """Converte imagens (JPG/PNG/BMP/TIFF/WEBP) para PDF"""
    if not PIL_AVAILABLE:
        raise ImportError('Pillow não instalado: py -m pip install Pillow')
    imgs = []
    for c in caminhos:
        img = PILImage2.open(c).convert('RGB')
        imgs.append(img)
    if not imgs:
        raise ValueError('Nenhuma imagem válida enviada')
    nome = f'{nome_saida}.pdf'
    caminho_saida = os.path.join(pasta_saida, nome)
    imgs[0].save(caminho_saida, save_all=True, append_images=imgs[1:])
    total = len(imgs)
    return [{'nome': nome, 'paginas': total, 'imagens_convertidas': total}], total

def redimensionar_paginas(caminho_pdf, formato_destino, pasta_saida):
    """Redimensiona todas as páginas para um formato padrão (A4, A3, Letter...)"""
    formatos = {
        'A4':     (595.28, 841.89),
        'A3':     (841.89, 1190.55),
        'A5':     (419.53, 595.28),
        'Letter': (612.0, 792.0),
        'Legal':  (612.0, 1008.0),
    }
    if formato_destino not in formatos:
        raise ValueError(f'Formato desconhecido: {formato_destino}')
    larg_dest, alt_dest = formatos[formato_destino]
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    total = len(reader.pages)
    for page in reader.pages:
        larg_orig = float(page.mediabox.width)
        alt_orig  = float(page.mediabox.height)
        if larg_orig > alt_orig:
            lw, lh = alt_dest, larg_dest
        else:
            lw, lh = larg_dest, alt_dest
        page.mediabox.lower_left  = (0, 0)
        page.mediabox.upper_right = (lw, lh)
        sx = lw / larg_orig
        sy = lh / alt_orig
        from PyPDF2.generic import Transformation
        page.add_transformation(Transformation().scale(sx, sy))
        w.add_page(page)
    nome = f'{nome_base}_{formato_destino.lower()}.pdf'
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': total, 'formato': formato_destino}], total

def adicionar_cabecalho_rodape(caminho_pdf, texto_cab, texto_rod, pasta_saida):
    """Adiciona cabeçalho e/ou rodapé de texto em todas as páginas"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError('reportlab não instalado: py -m pip install reportlab')
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    for i, page in enumerate(reader.pages):
        mb = page.mediabox
        larg, alt = float(mb.width), float(mb.height)
        packet = io.BytesIO()
        c = rl_canvas.Canvas(packet, pagesize=(larg, alt))
        c.setFont('Helvetica', 9)
        c.setFillColorRGB(0.3, 0.3, 0.3)
        if texto_cab:
            cab = texto_cab.replace('{pagina}', str(i+1)).replace('{total}', str(total))
            c.drawCentredString(larg / 2, alt - 18, cab)
            c.setStrokeColorRGB(0.7, 0.7, 0.7)
            c.setLineWidth(0.5)
            c.line(40, alt - 22, larg - 40, alt - 22)
        if texto_rod:
            rod = texto_rod.replace('{pagina}', str(i+1)).replace('{total}', str(total))
            c.setStrokeColorRGB(0.7, 0.7, 0.7)
            c.setLineWidth(0.5)
            c.line(40, 22, larg - 40, 22)
            c.drawCentredString(larg / 2, 10, rod)
        c.save(); packet.seek(0)
        page.merge_page(PdfReader(packet).pages[0])
        w.add_page(page)
    nome = f'{nome_base}_cab_rod.pdf'
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': total}], total

def comparar_pdfs(caminho1, caminho2, pasta_saida):
    """Compara texto de dois PDFs e gera relatório de diferenças"""
    import difflib
    def extrair(path):
        if PYMUPDF_AVAILABLE:
            doc = fitz.open(path)
            return [doc[i].get_text('text').strip() for i in range(len(doc))]
        reader = PdfReader(path)
        return [(page.extract_text() or '').strip() for page in reader.pages]
    pags1 = extrair(caminho1)
    pags2 = extrair(caminho2)
    nome1 = os.path.basename(caminho1)
    nome2 = os.path.basename(caminho2)
    max_pags = max(len(pags1), len(pags2))
    linhas = [f'COMPARAÇÃO DE PDFs', '=' * 60,
              f'Arquivo A: {nome1}  ({len(pags1)} páginas)',
              f'Arquivo B: {nome2}  ({len(pags2)} páginas)', '']
    diferencas_total = 0
    for i in range(max_pags):
        t1 = pags1[i] if i < len(pags1) else '(página não existe)'
        t2 = pags2[i] if i < len(pags2) else '(página não existe)'
        if t1 == t2:
            linhas.append(f'── Página {i+1}: IDÊNTICA')
            continue
        linhas.append(f'── Página {i+1}: DIFERENTE')
        diff = list(difflib.unified_diff(
            t1.splitlines(), t2.splitlines(),
            fromfile=f'A/pág.{i+1}', tofile=f'B/pág.{i+1}', lineterm=''))
        linhas.extend(diff[:60])
        if len(diff) > 60:
            linhas.append(f'  ... (+{len(diff)-60} linhas omitidas)')
        diferencas_total += 1
        linhas.append('')
    linhas.insert(4, f'Páginas diferentes: {diferencas_total} / {max_pags}')
    linhas.insert(5, '')
    nome_txt = 'comparacao_pdfs.txt'
    with open(os.path.join(pasta_saida, nome_txt), 'w', encoding='utf-8') as f:
        f.write('\n'.join(linhas))
    return [{'nome': nome_txt, 'paginas': max_pags, 'tipo': 'texto',
             'diferencas': diferencas_total}], max_pags

def adicionar_qrcode(caminho_pdf, url, posicao, tamanho_mm, pasta_saida):
    """Adiciona QR Code em todas as páginas do PDF"""
    if not QRCODE_AVAILABLE:
        raise ImportError('qrcode não instalado: py -m pip install qrcode[pil] Pillow')
    if not REPORTLAB_AVAILABLE:
        raise ImportError('reportlab não instalado: py -m pip install reportlab')
    from reportlab.lib.utils import ImageReader
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color='black', back_color='white')
    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format='PNG')
    tam_pt = tamanho_mm * 72 / 25.4
    for page in reader.pages:
        mb = page.mediabox
        larg, alt = float(mb.width), float(mb.height)
        packet = io.BytesIO()
        c = rl_canvas.Canvas(packet, pagesize=(larg, alt))
        m = 14
        pos_map = {
            'bottom-right': (larg - tam_pt - m, m),
            'bottom-left':  (m, m),
            'top-right':    (larg - tam_pt - m, alt - tam_pt - m),
            'top-left':     (m, alt - tam_pt - m),
        }
        x, y = pos_map.get(posicao, pos_map['bottom-right'])
        qr_buf.seek(0)
        c.drawImage(ImageReader(qr_buf), x, y, width=tam_pt, height=tam_pt)
        c.save(); packet.seek(0)
        page.merge_page(PdfReader(packet).pages[0])
        w.add_page(page)
    nome = f'{nome_base}_qrcode.pdf'
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': total, 'url': url}], total

def inserir_paginas_branco(caminho_pdf, posicoes, pasta_saida):
    """Insere páginas em branco nas posições especificadas"""
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total_orig = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    posicoes_set = sorted(set(posicoes))
    p0 = reader.pages[0].mediabox
    larg, alt = float(p0.width), float(p0.height)
    inseridas = 0
    pg_idx = 0
    for i in range(1, total_orig + 1):
        while pg_idx < len(posicoes_set) and posicoes_set[pg_idx] == i:
            w.add_blank_page(width=larg, height=alt)
            inseridas += 1
            pg_idx += 1
        w.add_page(reader.pages[i - 1])
    while pg_idx < len(posicoes_set):
        w.add_blank_page(width=larg, height=alt)
        inseridas += 1
        pg_idx += 1
    nome = f'{nome_base}_com_branco.pdf'
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': total_orig + inseridas,
             'paginas_inseridas': inseridas}], total_orig

def ajustar_brilho_pdf(caminho_pdf, fator, pasta_saida):
    """Ajusta brilho de PDFs digitalizados (fator: 0.5=escuro, 1.5=claro)"""
    if not PYMUPDF_AVAILABLE:
        raise ImportError('pymupdf não instalado: py -m pip install pymupdf')
    if not PIL_AVAILABLE:
        raise ImportError('Pillow não instalado: py -m pip install Pillow')
    from PIL import ImageEnhance
    doc = fitz.open(caminho_pdf)
    doc_saida = fitz.open()
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    for page in doc:
        pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5))
        img = PILImage2.frombytes('RGB', [pix.width, pix.height], pix.samples)
        enhancer = ImageEnhance.Brightness(img)
        img_ajustada = enhancer.enhance(float(fator))
        buf = io.BytesIO()
        img_ajustada.save(buf, format='PNG')
        buf.seek(0)
        rect = fitz.Rect(0, 0, page.rect.width, page.rect.height)
        nova_pag = doc_saida.new_page(width=page.rect.width, height=page.rect.height)
        nova_pag.insert_image(rect, stream=buf.read())
    nome = f'{nome_base}_brilho.pdf'
    cs = os.path.join(pasta_saida, nome)
    doc_saida.save(cs)
    doc.close(); doc_saida.close()
    _tmp = fitz.open(cs)
    total = _tmp.page_count
    _tmp.close()
    return [{'nome': nome, 'paginas': total, 'fator_brilho': fator}], total

def ocr_pdf(caminho_pdf, lang, pasta_saida):
    """Aplica OCR num PDF digitalizado e devolve PDF pesquisável"""
    if not PYMUPDF_AVAILABLE:
        raise ImportError('pymupdf não instalado: py -m pip install pymupdf')
    if not OCR_AVAILABLE:
        raise ImportError('pytesseract não instalado. Instale o Tesseract OCR e: py -m pip install pytesseract Pillow')
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    doc = fitz.open(caminho_pdf)
    doc_saida = fitz.open()
    idiomas = {'pt': 'por', 'en': 'eng', 'es': 'spa', 'fr': 'fra', 'auto': 'por+eng'}
    tess_lang = idiomas.get(lang, 'por+eng')
    for i, page in enumerate(doc):
        mat = fitz.Matrix(2.0, 2.0)
        pix = page.get_pixmap(matrix=mat)
        img = PILImage.frombytes('RGB', [pix.width, pix.height], pix.samples)
        pdf_bytes = pytesseract.image_to_pdf_or_hocr(img, extension='pdf', lang=tess_lang)
        tmp_doc = fitz.open('pdf', pdf_bytes)
        doc_saida.insert_pdf(tmp_doc)
        tmp_doc.close()
    nome = f'{nome_base}_ocr.pdf'
    caminho_saida = os.path.join(pasta_saida, nome)
    doc_saida.save(caminho_saida)
    doc.close(); doc_saida.close()
    _tmp = fitz.open(caminho_saida)
    total_pags = _tmp.page_count
    _tmp.close()
    return [{'nome': nome, 'paginas': total_pags}], total_pags

def extrair_texto_pdf(caminho_pdf, pasta_saida):
    """Extrai todo o texto do PDF para ficheiro .txt"""
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    total_pags = 0
    if PYMUPDF_AVAILABLE:
        doc = fitz.open(caminho_pdf)
        total_pags = len(doc)
        linhas = []
        for i, page in enumerate(doc):
            txt = page.get_text('text').strip()
            if txt:
                linhas.append(f'═══ Página {i+1} ═══\n{txt}')
        doc.close()
        texto = '\n\n'.join(linhas) if linhas else '(Nenhum texto encontrado — tente OCR)'
    else:
        reader = PdfReader(caminho_pdf)
        total_pags = len(reader.pages)
        linhas = []
        for i, page in enumerate(reader.pages):
            txt = (page.extract_text() or '').strip()
            if txt:
                linhas.append(f'=== Página {i+1} ===\n{txt}')
        texto = '\n\n'.join(linhas) if linhas else '(Nenhum texto encontrado — tente OCR)'
    nome = f'{nome_base}_texto.txt'
    with open(os.path.join(pasta_saida, nome), 'w', encoding='utf-8') as f:
        f.write(texto)
    total_chars = len(texto)
    return [{'nome': nome, 'paginas': total_pags, 'tipo': 'texto',
             'caracteres': total_chars, 'palavras': len(texto.split())}], total_pags

def adicionar_assinatura(caminho_pdf, texto_assinatura, paginas, posicao, tamanho, cor_hex, pasta_saida):
    """Adiciona assinatura visual (texto estilizado) ao PDF"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError('reportlab não instalado: py -m pip install reportlab')
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    pgs = set(paginas) if paginas else set(range(1, total + 1))
    cor_hex = cor_hex.lstrip('#')
    r_cor = int(cor_hex[0:2], 16) / 255
    g_cor = int(cor_hex[2:4], 16) / 255
    b_cor = int(cor_hex[4:6], 16) / 255
    posicoes = {
        'bottom-right':  lambda larg, alt: (larg - 20, 30),
        'bottom-left':   lambda larg, alt: (20, 30),
        'bottom-center': lambda larg, alt: (larg / 2, 30),
        'top-right':     lambda larg, alt: (larg - 20, alt - 30),
        'top-left':      lambda larg, alt: (20, alt - 30),
        'top-center':    lambda larg, alt: (larg / 2, alt - 30),
    }
    for i, page in enumerate(reader.pages):
        if (i + 1) in pgs:
            mb = page.mediabox
            larg, alt = float(mb.width), float(mb.height)
            packet = io.BytesIO()
            c = rl_canvas.Canvas(packet, pagesize=(larg, alt))
            fn = posicoes.get(posicao, posicoes['bottom-right'])
            x, y = fn(larg, alt)
            c.setFillColorRGB(r_cor, g_cor, b_cor)
            c.setFont('Helvetica-BoldOblique', int(tamanho))
            c.setStrokeColorRGB(r_cor, g_cor, b_cor)
            c.setLineWidth(1)
            txt_w = c.stringWidth(texto_assinatura, 'Helvetica-BoldOblique', int(tamanho))
            if 'right' in posicao:
                c.drawRightString(x, y + 4, texto_assinatura)
                c.line(x - txt_w - 5, y + 2, x, y + 2)
            elif 'center' in posicao:
                c.drawCentredString(x, y + 4, texto_assinatura)
                c.line(x - txt_w/2 - 5, y + 2, x + txt_w/2 + 5, y + 2)
            else:
                c.drawString(x, y + 4, texto_assinatura)
                c.line(x, y + 2, x + txt_w + 5, y + 2)
            c.setFont('Helvetica', 7)
            data_str = datetime.now().strftime('%d/%m/%Y %H:%M')
            if 'right' in posicao:
                c.drawRightString(x, y - 8, data_str)
            elif 'center' in posicao:
                c.drawCentredString(x, y - 8, data_str)
            else:
                c.drawString(x, y - 8, data_str)
            c.save(); packet.seek(0)
            page.merge_page(PdfReader(packet).pages[0])
        w.add_page(page)
    nome = f'{nome_base}_assinado.pdf'
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': total, 'assinatura': texto_assinatura}], total

def adicionar_carimbo(caminho_pdf, texto, posicao, cor_hex, pasta_saida):
    """Adiciona carimbo de texto em todas as páginas"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError('reportlab não instalado: py -m pip install reportlab')
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    cor_hex = cor_hex.lstrip('#')
    r_c = int(cor_hex[0:2],16)/255; g_c = int(cor_hex[2:4],16)/255; b_c = int(cor_hex[4:6],16)/255
    for page in reader.pages:
        mb = page.mediabox
        larg, alt = float(mb.width), float(mb.height)
        packet = io.BytesIO()
        c = rl_canvas.Canvas(packet, pagesize=(larg, alt))
        font_size = min(larg, alt) * 0.07
        txt_w = len(texto) * font_size * 0.55
        txt_h = font_size * 1.4
        pos_map = {
            'center':       (larg/2 - txt_w/2, alt/2 - txt_h/2),
            'top-right':    (larg - txt_w - 20, alt - txt_h - 20),
            'top-left':     (20, alt - txt_h - 20),
            'bottom-right': (larg - txt_w - 20, 20),
            'bottom-left':  (20, 20),
        }
        x, y = pos_map.get(posicao, pos_map['top-right'])
        c.setFillColorRGB(r_c, g_c, b_c, 0.08)
        c.roundRect(x - 6, y - 4, txt_w + 12, txt_h + 4, 4, fill=1, stroke=0)
        c.setStrokeColorRGB(r_c, g_c, b_c, 0.7)
        c.setLineWidth(2)
        c.roundRect(x - 6, y - 4, txt_w + 12, txt_h + 4, 4, fill=0, stroke=1)
        c.setFillColorRGB(r_c, g_c, b_c)
        c.setFont('Helvetica-Bold', font_size)
        c.drawString(x, y + font_size * 0.2, texto)
        c.save(); packet.seek(0)
        page.merge_page(PdfReader(packet).pages[0])
        w.add_page(page)
    nome = f'{nome_base}_carimbo.pdf'
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': total, 'carimbo': texto}], total

def extrair_formulario_pdf(caminho_pdf, pasta_saida):
    """Extrai campos e valores de formulários PDF"""
    reader = PdfReader(caminho_pdf)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    campos = reader.get_fields() or {}
    if not campos:
        raise ValueError('Este PDF não contém campos de formulário preenchíveis')
    linhas = ['CAMPOS DO FORMULÁRIO PDF', '=' * 50, '']
    for nome_campo, info in campos.items():
        valor = info.get('/V', '')
        tipo  = info.get('/FT', '')
        if isinstance(valor, bytes): valor = valor.decode('utf-8', errors='ignore')
        tipo_str = {'/Tx': 'Texto', '/Btn': 'Botão/Checkbox', '/Ch': 'Lista', '/Sig': 'Assinatura'}.get(str(tipo), 'Desconhecido')
        linhas.append(f'Campo : {nome_campo}')
        linhas.append(f'Tipo  : {tipo_str}')
        linhas.append(f'Valor : {valor or "(vazio)"}')
        linhas.append('')
    texto = '\n'.join(linhas)
    nome_txt = f'{nome_base}_formulario.txt'
    with open(os.path.join(pasta_saida, nome_txt), 'w', encoding='utf-8') as f:
        f.write(texto)
    return [{'nome': nome_txt, 'paginas': len(reader.pages), 'tipo': 'texto',
             'campos': len(campos)}], len(reader.pages)

def recortar_margens_pdf(caminho_pdf, margem_mm, pasta_saida):
    """Recorta/remove margens das páginas do PDF"""
    reader = PdfReader(caminho_pdf)
    w = PdfWriter()
    total = len(reader.pages)
    nome_base = os.path.splitext(os.path.basename(caminho_pdf))[0]
    margem_pt = float(margem_mm) * 72 / 25.4
    for page in reader.pages:
        mb = page.mediabox
        larg, alt = float(mb.width), float(mb.height)
        m = min(margem_pt, min(larg, alt) / 4)
        page.mediabox.lower_left = (float(mb.left) + m, float(mb.bottom) + m)
        page.mediabox.upper_right = (float(mb.right) - m, float(mb.top) - m)
        page.cropbox.lower_left = page.mediabox.lower_left
        page.cropbox.upper_right = page.mediabox.upper_right
        w.add_page(page)
    nome = f"{nome_base}_recortado.pdf"
    with open(os.path.join(pasta_saida, nome), 'wb') as f: w.write(f)
    return [{'nome': nome, 'paginas': total, 'margem_removida_mm': margem_mm}], total

# ─── Rotas ────────────────────────────────────────────────────────────────────

@app.before_request
def before():
    if request.path == '/' and request.method == 'GET':
        log_access()

@app.route('/telemetria', methods=['POST'])
def telemetria():
    """Recebe dados de tecnologia do cliente (browser, ecrã, rede...)"""
    try:
        d = request.json or {}
        session_id = d.get('session_id')
        ip = get_real_ip()
        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db()
        row = conn.execute(
            'SELECT id FROM acessos WHERE ip=? ORDER BY id DESC LIMIT 1', (ip,)
        ).fetchone()
        if row:
            conn.execute('''
                UPDATE acessos SET
                  screen_res=?,viewport=?,color_depth=?,lang_browser=?,
                  timezone_browser=?,referrer=?,touch_support=?,connection_type=?
                WHERE id=?''',
                (d.get('screen_res'), d.get('viewport'), d.get('color_depth'),
                 d.get('lang'), d.get('timezone'), d.get('referrer','')[:200],
                 int(d.get('touch', 0)), d.get('connection_type',''), row[0]))
        conn.commit(); conn.close()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dependencias')
def check_deps():
    return jsonify({'reportlab': REPORTLAB_AVAILABLE, 'pymupdf': PYMUPDF_AVAILABLE, 'ocr': OCR_AVAILABLE})

@app.route('/info', methods=['POST'])
def get_info():
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    file = request.files['file']
    if not file.filename or not allowed_file(file.filename):
        return jsonify({'error': 'Arquivo inválido. Envie um PDF.'}), 400
    try:
        session_id = str(uuid.uuid4())[:8]
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}_{filename}")
        file.save(filepath)
        info = get_pdf_info(filepath)
        session_set(session_id, filepath)
        info.update({'session_id': session_id, 'filename': filename})
        log_access(operacao='upload', filename=filename)
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/preview_pages', methods=['POST'])
def preview_pages_route():
    """Retorna miniaturas das páginas como base64 (requer pymupdf)"""
    if not PYMUPDF_AVAILABLE:
        return jsonify({'error': 'pymupdf não instalado', 'cmd': 'py -m pip install pymupdf'}), 400
    data = request.json
    session_id = data.get('session_id')
    max_pages = int(data.get('max_pages', 100))
    filepath = session_get(session_id)
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Sessão expirada. Faça o upload novamente.'}), 400
    try:
        doc = fitz.open(filepath)
        pages = []
        for i in range(min(len(doc), max_pages)):
            pix = doc[i].get_pixmap(matrix=fitz.Matrix(0.28, 0.28))
            pages.append({
                'page': i + 1,
                'image': 'data:image/png;base64,' + base64.b64encode(pix.tobytes('png')).decode()
            })
        total = len(doc)
        doc.close()
        return jsonify({'pages': pages, 'total': total})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/processar', methods=['POST'])
def processar():
    data = request.json
    operacao = data.get('operacao')
    session_id = data.get('session_id')
    filepath = session_get(session_id)
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Sessão expirada. Faça o upload novamente.'}), 400
    try:
        pasta = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
        os.makedirs(pasta, exist_ok=True)
        if operacao == 'dividir_partes':
            arquivos, total = dividir_por_partes(filepath, int(data.get('num_partes', 2)), pasta)
        elif operacao == 'dividir_paginas':
            arquivos, total = dividir_por_paginas(filepath, int(data.get('paginas_por_parte', 10)), pasta)
        elif operacao == 'extrair_paginas':
            arquivos, total = extrair_paginas(filepath, data.get('paginas', []), pasta)
        elif operacao == 'extrair_intervalo':
            arquivos, total = extrair_intervalo(filepath, int(data.get('inicio', 1)), int(data.get('fim', 1)), pasta)
        elif operacao == 'rotacionar':
            arquivos, total = rotacionar_paginas(filepath, int(data.get('angulo', 90)), data.get('paginas', []), pasta)
        elif operacao == 'remover_paginas':
            arquivos, total = remover_paginas(filepath, data.get('paginas', []), pasta)
        elif operacao == 'reordenar':
            arquivos, total = reordenar_paginas(filepath, data.get('nova_ordem', []), pasta)
        elif operacao == 'proteger':
            senha = data.get('senha', '')
            if not senha:
                return jsonify({'error': 'Senha não fornecida'}), 400
            arquivos, total = adicionar_senha(filepath, senha, pasta)
        elif operacao == 'comprimir':
            arquivos, total = comprimir_pdf(filepath, pasta)
        elif operacao == 'remover_senha':
            arquivos, total = remover_senha_pdf(filepath, data.get('senha', ''), pasta)
        elif operacao == 'marca_dagua':
            arquivos, total = adicionar_marca_dagua(
                filepath, data.get('texto', 'CONFIDENCIAL'),
                data.get('opacidade', 0.3), data.get('angulo', 45), pasta)
        elif operacao == 'converter_imagens':
            arquivos, total = converter_para_imagens(
                filepath, data.get('formato', 'png'), int(data.get('dpi', 150)), pasta)
        elif operacao == 'numeracao_paginas':
            arquivos, total = adicionar_numeracao(
                filepath, data.get('posicao', 'bottom-center'), data.get('estilo', 'completo'), pasta)
        elif operacao == 'editar_metadados':
            arquivos, total = editar_metadados_pdf(
                filepath, data.get('titulo', ''), data.get('autor', ''),
                data.get('assunto', ''), data.get('palavras_chave', ''), pasta)
        elif operacao == 'dividir_marcadores':
            arquivos, total = dividir_por_marcadores_pdf(filepath, pasta)
        elif operacao == 'recortar_margens':
            arquivos, total = recortar_margens_pdf(filepath, float(data.get('margem_mm', 10)), pasta)
        elif operacao == 'ocr':
            arquivos, total = ocr_pdf(filepath, data.get('lang', 'auto'), pasta)
        elif operacao == 'extrair_texto':
            arquivos, total = extrair_texto_pdf(filepath, pasta)
        elif operacao == 'assinatura':
            arquivos, total = adicionar_assinatura(
                filepath, data.get('texto', 'Assinado'),
                data.get('paginas', []), data.get('posicao', 'bottom-right'),
                data.get('tamanho', 14), data.get('cor', '#1a56db'), pasta)
        elif operacao == 'carimbo':
            arquivos, total = adicionar_carimbo(
                filepath, data.get('texto', 'APROVADO'),
                data.get('posicao', 'top-right'), data.get('cor', '#16a34a'), pasta)
        elif operacao == 'extrair_formulario':
            arquivos, total = extrair_formulario_pdf(filepath, pasta)
        elif operacao == 'redimensionar':
            arquivos, total = redimensionar_paginas(filepath, data.get('formato', 'A4'), pasta)
        elif operacao == 'cabecalho_rodape':
            arquivos, total = adicionar_cabecalho_rodape(
                filepath, data.get('cabecalho', ''), data.get('rodape', ''), pasta)
        elif operacao == 'qrcode':
            arquivos, total = adicionar_qrcode(
                filepath, data.get('url', 'https://example.com'),
                data.get('posicao', 'bottom-right'),
                float(data.get('tamanho_mm', 25)), pasta)
        elif operacao == 'paginas_branco':
            arquivos, total = inserir_paginas_branco(
                filepath, data.get('posicoes', []), pasta)
        elif operacao == 'ajustar_brilho':
            arquivos, total = ajustar_brilho_pdf(
                filepath, float(data.get('fator', 1.2)), pasta)
        else:
            return jsonify({'error': f'Operação "{operacao}" inválida'}), 400
        log_access(operacao=operacao, filename=os.path.basename(filepath))
        return jsonify({
            'success': True, 'session_id': session_id,
            'total_paginas': total, 'arquivos': arquivos, 'operacao': operacao
        })
    except Exception as e:
        log_access(operacao=operacao, status=500)
        return jsonify({'error': str(e)}), 500

@app.route('/mesclar', methods=['POST'])
def mesclar():
    if 'files[]' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    files = request.files.getlist('files[]')
    nome_saida = request.form.get('nome_saida', 'documento_mesclado')
    if len(files) < 2:
        return jsonify({'error': 'Envie pelo menos 2 arquivos'}), 400
    try:
        session_id = str(uuid.uuid4())[:8]
        pasta = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
        os.makedirs(pasta, exist_ok=True)
        temps = []
        for file in files:
            if file and allowed_file(file.filename):
                fp = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}_{secure_filename(file.filename)}")
                file.save(fp); temps.append(fp)
        if len(temps) < 2:
            return jsonify({'error': 'Arquivos inválidos'}), 400
        arquivos, total = mesclar_pdfs(temps, pasta, nome_saida)
        for f in temps:
            if os.path.exists(f): os.remove(f)
        return jsonify({
            'success': True, 'session_id': session_id,
            'total_paginas': total, 'arquivos': arquivos, 'operacao': 'mesclar'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<session_id>/<filename>')
def download_file(session_id, filename):
    if not re.match(r'^[a-f0-9]{8}$', session_id):
        return jsonify({'error': 'Sessão inválida'}), 400
    return send_from_directory(
        os.path.join(app.config['OUTPUT_FOLDER'], session_id), filename, as_attachment=True)

@app.route('/download_all/<session_id>')
def download_all(session_id):
    if not re.match(r'^[a-f0-9]{8}$', session_id):
        return jsonify({'error': 'Sessão inválida'}), 400
    pasta = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fn in os.listdir(pasta):
            zf.write(os.path.join(pasta, fn), fn)
    mem.seek(0)
    return send_file(mem, mimetype='application/zip', as_attachment=True,
                     download_name=f'pdf_processado_{session_id}.zip')

@app.route('/comparar', methods=['POST'])
def comparar():
    """Compara dois PDFs"""
    if 'file1' not in request.files or 'file2' not in request.files:
        return jsonify({'error': 'Envie dois arquivos PDF'}), 400
    f1, f2 = request.files['file1'], request.files['file2']
    if not (f1 and allowed_file(f1.filename) and f2 and allowed_file(f2.filename)):
        return jsonify({'error': 'Arquivos inválidos'}), 400
    try:
        session_id = str(uuid.uuid4())[:8]
        pasta = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
        os.makedirs(pasta, exist_ok=True)
        p1 = os.path.join(app.config['UPLOAD_FOLDER'], f'{session_id}_A_{secure_filename(f1.filename)}')
        p2 = os.path.join(app.config['UPLOAD_FOLDER'], f'{session_id}_B_{secure_filename(f2.filename)}')
        f1.save(p1); f2.save(p2)
        arquivos, total = comparar_pdfs(p1, p2, pasta)
        os.remove(p1); os.remove(p2)
        log_access(operacao='comparar')
        return jsonify({'success': True, 'session_id': session_id,
                        'total_paginas': total, 'arquivos': arquivos, 'operacao': 'comparar'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/converter_imagens', methods=['POST'])
def converter_imagens_rota():
    """Converte imagens para PDF"""
    ALLOWED_IMG = {'jpg','jpeg','png','bmp','tiff','tif','webp'}
    if 'files[]' not in request.files:
        return jsonify({'error': 'Nenhuma imagem enviada'}), 400
    files = request.files.getlist('files[]')
    nome_saida = request.form.get('nome_saida', 'imagens_convertidas')
    try:
        session_id = str(uuid.uuid4())[:8]
        pasta = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
        os.makedirs(pasta, exist_ok=True)
        temps = []
        for f in files:
            ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
            if ext in ALLOWED_IMG:
                fp = os.path.join(app.config['UPLOAD_FOLDER'], f'{session_id}_{secure_filename(f.filename)}')
                f.save(fp); temps.append(fp)
        if not temps:
            return jsonify({'error': 'Nenhuma imagem válida enviada'}), 400
        arquivos, total = imagens_para_pdf(temps, pasta, nome_saida)
        for t in temps:
            if os.path.exists(t): os.remove(t)
        log_access(operacao='imagens_para_pdf')
        return jsonify({'success': True, 'session_id': session_id,
                        'total_paginas': total, 'arquivos': arquivos, 'operacao': 'imagens_para_pdf'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats')
def app_stats():
    """Estatísticas públicas da aplicação"""
    try:
        conn = get_db()
        total_ops = conn.execute("SELECT COUNT(*) FROM acessos WHERE operacao IS NOT NULL AND operacao != 'upload'").fetchone()[0]
        total_uploads = conn.execute("SELECT COUNT(*) FROM acessos WHERE operacao='upload'").fetchone()[0]
        paises = conn.execute("SELECT COUNT(DISTINCT ip) FROM acessos").fetchone()[0]
        op_top = conn.execute("SELECT operacao, COUNT(*) as q FROM acessos WHERE operacao IS NOT NULL AND operacao != 'upload' GROUP BY operacao ORDER BY q DESC LIMIT 5").fetchall()
        conn.close()
        return jsonify({
            'total_operacoes': total_ops,
            'total_uploads': total_uploads,
            'utilizadores_unicos': paises,
            'top_operacoes': [{'op': r[0], 'qtd': r[1]} for r in op_top]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/limpar/<session_id>', methods=['POST'])
def limpar_sessao(session_id):
    pasta = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
    if os.path.exists(pasta): shutil.rmtree(pasta)
    for fn in os.listdir(app.config['UPLOAD_FOLDER']):
        if fn.startswith(session_id):
            try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], fn))
            except: pass
    session_delete(session_id)
    return jsonify({'success': True})

# ─── Rotas de Auditoria ───────────────────────────────────────────────────────

@app.route('/auditoria')
def auditoria_login():
    return render_template('auditoria.html')

@app.route('/auditoria/dados')
def auditoria_dados():
    pwd = request.args.get('pwd', '')
    if pwd != AUDIT_PASSWORD:
        return jsonify({'error': 'Senha incorreta'}), 403
    page = int(request.args.get('page', 1))
    per = 50
    offset = (page - 1) * per
    conn = get_db()
    conn.row_factory = sqlite3.Row
    total = conn.execute('SELECT COUNT(*) FROM acessos').fetchone()[0]
    rows = conn.execute(
        'SELECT * FROM acessos ORDER BY id DESC LIMIT ? OFFSET ?', (per, offset)
    ).fetchall()
    stats = {}
    stats['total'] = total
    stats['hoje'] = conn.execute(
        "SELECT COUNT(*) FROM acessos WHERE ts LIKE ?",
        (datetime.utcnow().strftime('%Y-%m-%d') + '%',)
    ).fetchone()[0]
    stats['paises'] = [dict(r) for r in conn.execute(
        "SELECT pais, COUNT(*) as qtd FROM acessos WHERE pais IS NOT NULL GROUP BY pais ORDER BY qtd DESC LIMIT 10"
    ).fetchall()]
    stats['ops'] = [dict(r) for r in conn.execute(
        "SELECT operacao, COUNT(*) as qtd FROM acessos WHERE operacao IS NOT NULL GROUP BY operacao ORDER BY qtd DESC"
    ).fetchall()]
    stats['ips'] = [dict(r) for r in conn.execute(
        "SELECT ip, COUNT(*) as qtd FROM acessos GROUP BY ip ORDER BY qtd DESC LIMIT 10"
    ).fetchall()]
    stats['por_hora'] = [dict(r) for r in conn.execute(
        "SELECT substr(ts,12,2) as hora, COUNT(*) as qtd FROM acessos GROUP BY hora ORDER BY hora"
    ).fetchall()]
    stats['browsers'] = [dict(r) for r in conn.execute(
        "SELECT browser, COUNT(*) as qtd FROM acessos WHERE browser IS NOT NULL AND browser != '' GROUP BY browser ORDER BY qtd DESC"
    ).fetchall()]
    stats['os'] = [dict(r) for r in conn.execute(
        "SELECT os_name, COUNT(*) as qtd FROM acessos WHERE os_name IS NOT NULL AND os_name != '' GROUP BY os_name ORDER BY qtd DESC"
    ).fetchall()]
    stats['devices'] = [dict(r) for r in conn.execute(
        "SELECT device_type, COUNT(*) as qtd FROM acessos WHERE device_type IS NOT NULL GROUP BY device_type ORDER BY qtd DESC"
    ).fetchall()]
    stats['proxies'] = conn.execute("SELECT COUNT(*) FROM acessos WHERE proxy=1 OR vpn=1").fetchone()[0]
    stats['bots'] = conn.execute("SELECT COUNT(*) FROM acessos WHERE is_bot=1").fetchone()[0]
    conn.close()
    return jsonify({
        'rows': [dict(r) for r in rows],
        'total': total,
        'page': page,
        'pages': (total + per - 1) // per,
        'stats': stats
    })

@app.route('/auditoria/export')
def auditoria_export():
    pwd = request.args.get('pwd', '')
    if pwd != AUDIT_PASSWORD:
        return jsonify({'error': 'Sem autorização'}), 403
    conn = get_db()
    rows = conn.execute('SELECT * FROM acessos ORDER BY id DESC').fetchall()
    conn.close()
    import csv as csv_mod
    buf = io.StringIO()
    writer = csv_mod.writer(buf)
    writer.writerow(['id','ts','ip','pais','pais_code','regiao','cidade','zip_geo','lat','lon',
                     'timezone_geo','isp','org','asn','proxy','vpn','hosting','user_agent',
                     'browser','browser_version','browser_engine','os_name','os_version',
                     'device_type','is_bot','screen_res','viewport','color_depth','lang_browser',
                     'timezone_browser','referrer','touch_support','connection_type',
                     'rota','metodo','operacao','filename','status'])
    for r in rows:
        writer.writerow([v if v is not None else '' for v in r])
    csv_data = buf.getvalue()
    return send_file(
        io.BytesIO(csv_data.encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='auditoria_acessos.csv'
    )

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'error': 'Arquivo muito grande. Limite: 500 MB'}), 413

if __name__ == '__main__':
    print(f"\n{'='*65}")
    print("🔪  DIVISOR DE PDF PRO v2.0  —  16 operações!")
    print(f"{'='*65}")
    print("📍  http://localhost:5000")
    print(f"   reportlab : {'✅  disponível' if REPORTLAB_AVAILABLE else '❌  py -m pip install reportlab'}")
    print(f"   pymupdf   : {'✅  disponível' if PYMUPDF_AVAILABLE else '❌  py -m pip install pymupdf'}")
    print(f"{'='*65}\n")
    print(f"   auditoria : http://localhost:5000/auditoria  (senha: {AUDIT_PASSWORD})")
    print(f"{'='*65}\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
