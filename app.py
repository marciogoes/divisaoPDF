"""
🔪 Divisor de PDF PRO v2.0 - Aplicação Web Completa
16 operações | Preview de páginas | Histórico | Metadados | Marca d'água | +
"""

from flask import Flask, render_template, request, send_file, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import os, shutil, base64, io, zipfile, uuid, sqlite3, threading
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

# ─── Auditoria (SQLite) ───────────────────────────────────────────────────────
AUDIT_DB = 'auditoria.db'
AUDIT_PASSWORD = os.environ.get('AUDIT_PASSWORD', 'admin123')

def init_audit_db():
    conn = sqlite3.connect(AUDIT_DB)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS acessos (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT    NOT NULL,
            ip        TEXT,
            pais      TEXT,
            regiao    TEXT,
            cidade    TEXT,
            lat       REAL,
            lon       REAL,
            isp       TEXT,
            rota      TEXT,
            metodo    TEXT,
            operacao  TEXT,
            filename  TEXT,
            status    INTEGER,
            user_agent TEXT
        )
    ''')
    conn.commit(); conn.close()

init_audit_db()

def get_real_ip():
    for h in ('X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'):
        v = request.headers.get(h)
        if v:
            return v.split(',')[0].strip()
    return request.remote_addr

def geo_lookup_async(ip, row_id):
    """Busca localização geográfica em background e actualiza o registo."""
    if not REQUESTS_AVAILABLE:
        return
    if ip in ('127.0.0.1', '::1', 'localhost'):
        return
    try:
        r = req_lib.get(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp',
                        timeout=4)
        d = r.json()
        if d.get('status') == 'success':
            conn = sqlite3.connect(AUDIT_DB)
            conn.execute('''UPDATE acessos SET pais=?,regiao=?,cidade=?,lat=?,lon=?,isp=? WHERE id=?''',
                         (d.get('country'), d.get('regionName'), d.get('city'),
                          d.get('lat'), d.get('lon'), d.get('isp'), row_id))
            conn.commit(); conn.close()
    except Exception:
        pass

def log_access(operacao=None, filename=None, status=200):
    ip = get_real_ip()
    ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(AUDIT_DB)
    cur = conn.execute(
        '''INSERT INTO acessos (ts,ip,rota,metodo,operacao,filename,status,user_agent)
           VALUES (?,?,?,?,?,?,?,?)''',
        (ts, ip, request.path, request.method,
         operacao, filename, status,
         request.headers.get('User-Agent', '')[:250])
    )
    row_id = cur.lastrowid
    conn.commit(); conn.close()
    t = threading.Thread(target=geo_lookup_async, args=(ip, row_id), daemon=True)
    t.start()
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
        if not result:
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
    # Remove duplicates
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
    # Regista todas as visitas à página principal e operações
    if request.path in ('/', ) and request.method == 'GET':
        log_access()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dependencias')
def check_deps():
    return jsonify({'reportlab': REPORTLAB_AVAILABLE, 'pymupdf': PYMUPDF_AVAILABLE})

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
        info.update({'session_id': session_id, 'filename': filename, 'filepath': filepath})
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
    filepath = data.get('filepath')
    max_pages = int(data.get('max_pages', 100))
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Arquivo não encontrado'}), 400
    try:
        doc = fitz.open(filepath)
        pages = []
        for i in range(min(len(doc), max_pages)):
            pix = doc[i].get_pixmap(matrix=fitz.Matrix(0.28, 0.28))
            pages.append({
                'page': i + 1,
                'image': 'data:image/png;base64,' + base64.b64encode(pix.tobytes('png')).decode()
            })
        doc.close()
        return jsonify({'pages': pages, 'total': len(doc)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/processar', methods=['POST'])
def processar():
    data = request.json
    operacao = data.get('operacao')
    filepath = data.get('filepath')
    session_id = data.get('session_id')
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Arquivo não encontrado. Faça o upload novamente.'}), 400
    try:
        pasta = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
        os.makedirs(pasta, exist_ok=True)
        # ── Operações existentes ──────────────────────────────────────────────
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
        # ── Novas operações ───────────────────────────────────────────────────
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
    return send_from_directory(
        os.path.join(app.config['OUTPUT_FOLDER'], session_id), filename, as_attachment=True)

@app.route('/download_all/<session_id>')
def download_all(session_id):
    pasta = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fn in os.listdir(pasta):
            zf.write(os.path.join(pasta, fn), fn)
    mem.seek(0)
    return send_file(mem, mimetype='application/zip', as_attachment=True,
                     download_name=f'pdf_processado_{session_id}.zip')

@app.route('/limpar/<session_id>', methods=['POST'])
def limpar_sessao(session_id):
    pasta = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
    if os.path.exists(pasta): shutil.rmtree(pasta)
    for fn in os.listdir(app.config['UPLOAD_FOLDER']):
        if fn.startswith(session_id):
            try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], fn))
            except: pass
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
    conn = sqlite3.connect(AUDIT_DB)
    conn.row_factory = sqlite3.Row
    total = conn.execute('SELECT COUNT(*) FROM acessos').fetchone()[0]
    rows = conn.execute(
        'SELECT * FROM acessos ORDER BY id DESC LIMIT ? OFFSET ?', (per, offset)
    ).fetchall()
    # Stats
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
    conn = sqlite3.connect(AUDIT_DB)
    rows = conn.execute('SELECT * FROM acessos ORDER BY id DESC').fetchall()
    conn.close()
    lines = ['id,ts,ip,pais,regiao,cidade,lat,lon,isp,rota,metodo,operacao,filename,status,user_agent']
    for r in rows:
        lines.append(','.join(f'"{v}"' if v else '""' for v in r))
    csv = '\n'.join(lines)
    return send_file(
        io.BytesIO(csv.encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='auditoria_acessos.csv'
    )

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
