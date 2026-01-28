#!/usr/bin/env python3
"""
Private Investigator OSINT Dashboard
A comprehensive web-based toolkit for OSINT investigations
"""

import os
import sys
import json
import sqlite3
import subprocess
import threading
import queue
import uuid
import re
from datetime import datetime
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify, Response,
    redirect, url_for, flash, send_file, session
)
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Template context processor
@app.context_processor
def inject_now():
    return {'now': datetime.now}

# Configuration
UPLOAD_FOLDER = Path(__file__).parent / 'uploads'
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

# Database path
DB_PATH = Path.home() / '.pi-toolkit' / 'cases.db'
DB_PATH.parent.mkdir(exist_ok=True)

# Global queues for SSE streaming
result_queues = {}


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with required tables."""
    conn = get_db()
    cursor = conn.cursor()

    # Cases table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Searches table - linked to cases
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS searches (
            id TEXT PRIMARY KEY,
            case_id TEXT,
            search_type TEXT NOT NULL,
            query TEXT NOT NULL,
            results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )
    ''')

    # Entities table for relationship graph
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entities (
            id TEXT PRIMARY KEY,
            case_id TEXT,
            entity_type TEXT NOT NULL,
            value TEXT NOT NULL,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )
    ''')

    # Relationships table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS relationships (
            id TEXT PRIMARY KEY,
            case_id TEXT,
            source_entity_id TEXT,
            target_entity_id TEXT,
            relationship_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id),
            FOREIGN KEY (source_entity_id) REFERENCES entities(id),
            FOREIGN KEY (target_entity_id) REFERENCES entities(id)
        )
    ''')

    conn.commit()
    conn.close()


# Initialize database on startup
init_db()


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def generate_id():
    """Generate a unique ID."""
    return str(uuid.uuid4())[:8]


def run_command_stream(cmd, queue_id):
    """Run a command and stream output to a queue."""
    q = result_queues.get(queue_id)
    if not q:
        return

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=isinstance(cmd, str)
        )

        for line in iter(process.stdout.readline, ''):
            if line:
                q.put(('data', line.strip()))

        process.wait()
        q.put(('done', f'Process completed with code {process.returncode}'))
    except Exception as e:
        q.put(('error', str(e)))
    finally:
        q.put(('end', None))


def save_search(case_id, search_type, query, results):
    """Save a search to the database."""
    conn = get_db()
    cursor = conn.cursor()
    search_id = generate_id()

    cursor.execute('''
        INSERT INTO searches (id, case_id, search_type, query, results)
        VALUES (?, ?, ?, ?, ?)
    ''', (search_id, case_id, search_type, query, json.dumps(results)))

    conn.commit()
    conn.close()
    return search_id


def add_entity(case_id, entity_type, value, metadata=None):
    """Add an entity to the graph."""
    conn = get_db()
    cursor = conn.cursor()

    # Check if entity already exists
    cursor.execute('''
        SELECT id FROM entities WHERE case_id = ? AND entity_type = ? AND value = ?
    ''', (case_id, entity_type, value))

    existing = cursor.fetchone()
    if existing:
        conn.close()
        return existing['id']

    entity_id = generate_id()
    cursor.execute('''
        INSERT INTO entities (id, case_id, entity_type, value, metadata)
        VALUES (?, ?, ?, ?, ?)
    ''', (entity_id, case_id, entity_type, value, json.dumps(metadata or {})))

    conn.commit()
    conn.close()
    return entity_id


def add_relationship(case_id, source_id, target_id, rel_type):
    """Add a relationship between entities."""
    conn = get_db()
    cursor = conn.cursor()
    rel_id = generate_id()

    cursor.execute('''
        INSERT INTO relationships (id, case_id, source_entity_id, target_entity_id, relationship_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (rel_id, case_id, source_id, target_id, rel_type))

    conn.commit()
    conn.close()
    return rel_id


# ============================================================
# ROUTES - MAIN PAGES
# ============================================================

@app.route('/')
def index():
    """Dashboard home page."""
    conn = get_db()
    cursor = conn.cursor()

    # Get stats
    cursor.execute('SELECT COUNT(*) as count FROM cases WHERE status = "active"')
    active_cases = cursor.fetchone()['count']

    cursor.execute('SELECT COUNT(*) as count FROM searches')
    total_searches = cursor.fetchone()['count']

    cursor.execute('SELECT COUNT(*) as count FROM entities')
    total_entities = cursor.fetchone()['count']

    # Recent searches
    cursor.execute('''
        SELECT s.*, c.name as case_name
        FROM searches s
        LEFT JOIN cases c ON s.case_id = c.id
        ORDER BY s.created_at DESC LIMIT 5
    ''')
    recent_searches = cursor.fetchall()

    conn.close()

    return render_template('index.html',
                         active_cases=active_cases,
                         total_searches=total_searches,
                         total_entities=total_entities,
                         recent_searches=recent_searches)


@app.route('/username')
def username_page():
    """Username search page."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM cases WHERE status = "active" ORDER BY name')
    cases = cursor.fetchall()
    conn.close()
    return render_template('username.html', cases=cases)


@app.route('/email')
def email_page():
    """Email OSINT page."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM cases WHERE status = "active" ORDER BY name')
    cases = cursor.fetchall()
    conn.close()
    return render_template('email.html', cases=cases)


@app.route('/phone')
def phone_page():
    """Phone lookup page."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM cases WHERE status = "active" ORDER BY name')
    cases = cursor.fetchall()
    conn.close()
    return render_template('phone.html', cases=cases)


@app.route('/domain')
def domain_page():
    """Domain recon page."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM cases WHERE status = "active" ORDER BY name')
    cases = cursor.fetchall()
    conn.close()
    return render_template('domain.html', cases=cases)


@app.route('/spiderfoot')
def spiderfoot_page():
    """SpiderFoot page."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM cases WHERE status = "active" ORDER BY name')
    cases = cursor.fetchall()
    conn.close()
    return render_template('spiderfoot.html', cases=cases)


@app.route('/images')
def images_page():
    """Image analysis page."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM cases WHERE status = "active" ORDER BY name')
    cases = cursor.fetchall()
    conn.close()
    return render_template('images.html', cases=cases)


@app.route('/documents')
def documents_page():
    """Document analysis page."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM cases WHERE status = "active" ORDER BY name')
    cases = cursor.fetchall()
    conn.close()
    return render_template('documents.html', cases=cases)


@app.route('/cases')
def cases_page():
    """Cases management page."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT c.*,
               (SELECT COUNT(*) FROM searches WHERE case_id = c.id) as search_count,
               (SELECT COUNT(*) FROM entities WHERE case_id = c.id) as entity_count
        FROM cases c
        ORDER BY c.updated_at DESC
    ''')
    cases = cursor.fetchall()
    conn.close()
    return render_template('cases.html', cases=cases)


@app.route('/cases/<case_id>')
def case_detail(case_id):
    """View single case details."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
    case = cursor.fetchone()

    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('cases_page'))

    cursor.execute('SELECT * FROM searches WHERE case_id = ? ORDER BY created_at DESC', (case_id,))
    searches = cursor.fetchall()

    cursor.execute('SELECT * FROM entities WHERE case_id = ?', (case_id,))
    entities = cursor.fetchall()

    conn.close()
    return render_template('case_detail.html', case=case, searches=searches, entities=entities)


@app.route('/graph')
def graph_page():
    """Relationship graph page."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM cases WHERE status = "active" ORDER BY name')
    cases = cursor.fetchall()
    conn.close()
    return render_template('graph.html', cases=cases)


# ============================================================
# API ROUTES - OSINT TOOLS
# ============================================================

@app.route('/api/username/search', methods=['POST'])
def search_username():
    """Search username across platforms."""
    data = request.json
    username = data.get('username', '').strip()
    tools = data.get('tools', ['sherlock'])
    nsfw = data.get('nsfw', False)
    case_id = data.get('case_id')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    # Create queue for streaming
    queue_id = generate_id()
    result_queues[queue_id] = queue.Queue()

    results = {
        'sherlock': [],
        'maigret': [],
        'queue_id': queue_id
    }

    # Run tools in background threads
    if 'sherlock' in tools:
        cmd = ['sherlock', username, '--print-found', '--timeout', '10']
        if nsfw:
            cmd.append('--nsfw')
        thread = threading.Thread(target=run_sherlock, args=(cmd, queue_id, username))
        thread.start()

    if 'maigret' in tools:
        cmd = ['maigret', username, '--timeout', '10', '-J', 'simple']
        thread = threading.Thread(target=run_maigret, args=(cmd, queue_id, username))
        thread.start()

    # Save to case if provided
    if case_id:
        save_search(case_id, 'username', username, {'tools': tools})
        add_entity(case_id, 'username', username)

    return jsonify(results)


def run_sherlock(cmd, queue_id, username):
    """Run sherlock and parse results."""
    q = result_queues.get(queue_id)
    if not q:
        return

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in iter(process.stdout.readline, ''):
            if line.strip():
                # Parse sherlock output - look for [+] lines
                if '[+]' in line or 'http' in line.lower():
                    q.put(('sherlock', line.strip()))

        process.wait()
        q.put(('sherlock_done', 'Sherlock search completed'))
    except FileNotFoundError:
        q.put(('sherlock_error', 'Sherlock not installed. Install with: pip install sherlock-project'))
    except Exception as e:
        q.put(('sherlock_error', str(e)))


def run_maigret(cmd, queue_id, username):
    """Run maigret and parse results."""
    q = result_queues.get(queue_id)
    if not q:
        return

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in iter(process.stdout.readline, ''):
            if line.strip():
                if '[+]' in line or 'http' in line.lower():
                    q.put(('maigret', line.strip()))

        process.wait()
        q.put(('maigret_done', 'Maigret search completed'))
    except FileNotFoundError:
        q.put(('maigret_error', 'Maigret not installed. Install with: pip install maigret'))
    except Exception as e:
        q.put(('maigret_error', str(e)))


@app.route('/api/username/stream/<queue_id>')
def stream_username_results(queue_id):
    """Stream username search results via SSE."""
    def generate():
        q = result_queues.get(queue_id)
        if not q:
            yield f"data: {json.dumps({'error': 'Queue not found'})}\n\n"
            return

        done_count = 0
        while True:
            try:
                msg_type, msg_data = q.get(timeout=60)

                if msg_type in ('sherlock_done', 'maigret_done'):
                    done_count += 1
                    yield f"data: {json.dumps({'type': msg_type, 'message': msg_data})}\n\n"
                    if done_count >= 2:
                        break
                elif msg_type.endswith('_error'):
                    yield f"data: {json.dumps({'type': 'error', 'tool': msg_type.replace('_error', ''), 'message': msg_data})}\n\n"
                    done_count += 1
                else:
                    yield f"data: {json.dumps({'type': msg_type, 'data': msg_data})}\n\n"

            except queue.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"

        # Cleanup
        if queue_id in result_queues:
            del result_queues[queue_id]

    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/email/search', methods=['POST'])
def search_email():
    """Search email with Holehe."""
    data = request.json
    email = data.get('email', '').strip()
    case_id = data.get('case_id')
    auto_username = data.get('auto_username', False)

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    results = {'accounts': [], 'error': None}

    try:
        # Run holehe
        process = subprocess.run(
            ['holehe', email, '--only-used', '-C'],
            capture_output=True,
            text=True,
            timeout=120
        )

        output = process.stdout + process.stderr

        # Parse holehe output
        for line in output.split('\n'):
            line = line.strip()
            if line and ('[+]' in line or 'used' in line.lower()):
                # Extract service name
                parts = line.split()
                if parts:
                    service = parts[0].replace('[+]', '').strip()
                    if service:
                        results['accounts'].append({
                            'service': service,
                            'status': 'found',
                            'raw': line
                        })
    except FileNotFoundError:
        results['error'] = 'Holehe not installed. Install with: pip install holehe'
    except subprocess.TimeoutExpired:
        results['error'] = 'Search timed out'
    except Exception as e:
        results['error'] = str(e)

    # Save to case if provided
    if case_id:
        save_search(case_id, 'email', email, results)
        add_entity(case_id, 'email', email)

    # Extract username for additional search
    if auto_username:
        username = email.split('@')[0]
        results['username_prefix'] = username

    return jsonify(results)


@app.route('/api/phone/lookup', methods=['POST'])
def lookup_phone():
    """Lookup phone number information."""
    data = request.json
    phone = data.get('phone', '').strip()
    country_code = data.get('country_code', 'US')
    case_id = data.get('case_id')

    if not phone:
        return jsonify({'error': 'Phone number is required'}), 400

    results = {
        'valid': False,
        'formatted': None,
        'country': None,
        'carrier': None,
        'type': None,
        'timezone': None,
        'location': None,
        'coordinates': None
    }

    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone

        # Parse phone number
        parsed = phonenumbers.parse(phone, country_code)

        results['valid'] = phonenumbers.is_valid_number(parsed)
        results['formatted'] = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )
        results['country'] = geocoder.country_name_for_number(parsed, 'en')
        results['location'] = geocoder.description_for_number(parsed, 'en')

        try:
            results['carrier'] = carrier.name_for_number(parsed, 'en')
        except:
            pass

        try:
            tz = timezone.time_zones_for_number(parsed)
            results['timezone'] = list(tz) if tz else None
        except:
            pass

        # Determine type
        number_type = phonenumbers.number_type(parsed)
        type_map = {
            0: 'Fixed Line',
            1: 'Mobile',
            2: 'Fixed Line or Mobile',
            3: 'Toll Free',
            4: 'Premium Rate',
            5: 'Shared Cost',
            6: 'VoIP',
            7: 'Personal Number',
            8: 'Pager',
            9: 'UAN',
            10: 'Unknown'
        }
        results['type'] = type_map.get(number_type, 'Unknown')

    except ImportError:
        results['error'] = 'phonenumbers library not installed'
    except Exception as e:
        results['error'] = str(e)

    # Save to case if provided
    if case_id:
        save_search(case_id, 'phone', phone, results)
        if results['valid']:
            add_entity(case_id, 'phone', results['formatted'])

    return jsonify(results)


@app.route('/api/domain/search', methods=['POST'])
def search_domain():
    """Search domain with theHarvester."""
    data = request.json
    domain = data.get('domain', '').strip()
    sources = data.get('sources', ['google', 'bing', 'duckduckgo'])
    case_id = data.get('case_id')

    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    # Create queue for streaming
    queue_id = generate_id()
    result_queues[queue_id] = queue.Queue()

    # Run theHarvester in background
    thread = threading.Thread(target=run_harvester, args=(domain, sources, queue_id))
    thread.start()

    # Save to case if provided
    if case_id:
        save_search(case_id, 'domain', domain, {'sources': sources})
        add_entity(case_id, 'domain', domain)

    return jsonify({'queue_id': queue_id})


def run_harvester(domain, sources, queue_id):
    """Run theHarvester and stream results."""
    q = result_queues.get(queue_id)
    if not q:
        return

    results = {
        'emails': [],
        'subdomains': [],
        'ips': [],
        'hosts': []
    }

    try:
        source_str = ','.join(sources)
        cmd = ['theHarvester', '-d', domain, '-b', source_str, '-l', '200']

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        current_section = None

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line:
                continue

            # Detect sections
            if 'Emails' in line and 'found' in line:
                current_section = 'emails'
                q.put(('section', 'emails'))
            elif 'Hosts' in line and 'found' in line:
                current_section = 'hosts'
                q.put(('section', 'hosts'))
            elif 'IPs' in line and 'found' in line:
                current_section = 'ips'
                q.put(('section', 'ips'))
            elif '@' in line and current_section == 'emails':
                email = line.strip()
                results['emails'].append(email)
                q.put(('email', email))
            elif line and current_section == 'hosts':
                results['hosts'].append(line)
                q.put(('host', line))
            elif line and current_section == 'ips':
                # Check if it looks like an IP
                if re.match(r'\d+\.\d+\.\d+\.\d+', line):
                    results['ips'].append(line)
                    q.put(('ip', line))

            # Stream raw output too
            q.put(('raw', line))

        process.wait()
        q.put(('results', results))
        q.put(('done', 'theHarvester search completed'))

    except FileNotFoundError:
        q.put(('error', 'theHarvester not installed. Install with: pip install theHarvester'))
    except Exception as e:
        q.put(('error', str(e)))
    finally:
        q.put(('end', None))


@app.route('/api/domain/stream/<queue_id>')
def stream_domain_results(queue_id):
    """Stream domain search results via SSE."""
    def generate():
        q = result_queues.get(queue_id)
        if not q:
            yield f"data: {json.dumps({'error': 'Queue not found'})}\n\n"
            return

        while True:
            try:
                msg_type, msg_data = q.get(timeout=120)

                if msg_type == 'end':
                    break
                elif msg_type == 'done':
                    yield f"data: {json.dumps({'type': 'done', 'message': msg_data})}\n\n"
                elif msg_type == 'error':
                    yield f"data: {json.dumps({'type': 'error', 'message': msg_data})}\n\n"
                elif msg_type == 'results':
                    yield f"data: {json.dumps({'type': 'results', 'data': msg_data})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': msg_type, 'data': msg_data})}\n\n"

            except queue.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"

        # Cleanup
        if queue_id in result_queues:
            del result_queues[queue_id]

    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/spiderfoot/scan', methods=['POST'])
def spiderfoot_scan():
    """Run SpiderFoot scan."""
    data = request.json
    target = data.get('target', '').strip()
    modules = data.get('modules', [])
    case_id = data.get('case_id')

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    # Auto-detect target type
    target_type = detect_target_type(target)

    # Create queue for streaming
    queue_id = generate_id()
    result_queues[queue_id] = queue.Queue()

    # Run SpiderFoot in background
    thread = threading.Thread(target=run_spiderfoot, args=(target, modules, queue_id))
    thread.start()

    # Save to case if provided
    if case_id:
        save_search(case_id, 'spiderfoot', target, {'modules': modules, 'type': target_type})
        add_entity(case_id, target_type, target)

    return jsonify({'queue_id': queue_id, 'target_type': target_type})


def detect_target_type(target):
    """Auto-detect the type of target."""
    # Email
    if '@' in target and '.' in target:
        return 'email'
    # IP address
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        return 'ip'
    # Domain
    if '.' in target and not target.startswith('http'):
        return 'domain'
    # URL
    if target.startswith('http'):
        return 'url'
    # Phone
    if re.match(r'^[\d\+\-\(\)\s]+$', target) and len(re.sub(r'\D', '', target)) >= 7:
        return 'phone'
    # Default to username
    return 'username'


def run_spiderfoot(target, modules, queue_id):
    """Run SpiderFoot CLI and stream results."""
    q = result_queues.get(queue_id)
    if not q:
        return

    try:
        # Build SpiderFoot command
        cmd = ['spiderfoot', '-s', target, '-q']

        if modules:
            cmd.extend(['-m', ','.join(modules)])

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        results = []
        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if line:
                results.append(line)
                q.put(('data', line))

        process.wait()
        q.put(('results', results))
        q.put(('done', 'SpiderFoot scan completed'))

    except FileNotFoundError:
        q.put(('error', 'SpiderFoot not installed. Install from: https://github.com/smicallef/spiderfoot'))
    except Exception as e:
        q.put(('error', str(e)))
    finally:
        q.put(('end', None))


@app.route('/api/spiderfoot/stream/<queue_id>')
def stream_spiderfoot_results(queue_id):
    """Stream SpiderFoot results via SSE."""
    def generate():
        q = result_queues.get(queue_id)
        if not q:
            yield f"data: {json.dumps({'error': 'Queue not found'})}\n\n"
            return

        while True:
            try:
                msg_type, msg_data = q.get(timeout=300)  # 5 min timeout for long scans

                if msg_type == 'end':
                    break
                elif msg_type == 'done':
                    yield f"data: {json.dumps({'type': 'done', 'message': msg_data})}\n\n"
                elif msg_type == 'error':
                    yield f"data: {json.dumps({'type': 'error', 'message': msg_data})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': msg_type, 'data': msg_data})}\n\n"

            except queue.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"

        # Cleanup
        if queue_id in result_queues:
            del result_queues[queue_id]

    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/image/analyze', methods=['POST'])
def analyze_image():
    """Analyze image for EXIF data."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    case_id = request.form.get('case_id')

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Save file temporarily
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    results = {
        'filename': filename,
        'exif': {},
        'gps': None,
        'basic': {}
    }

    try:
        # Get basic file info
        from PIL import Image
        with Image.open(filepath) as img:
            results['basic'] = {
                'format': img.format,
                'mode': img.mode,
                'size': f"{img.width}x{img.height}",
                'width': img.width,
                'height': img.height
            }

        # Get EXIF data
        import exifread
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f, details=True)

            for tag, value in tags.items():
                if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                    results['exif'][tag] = str(value)

            # Extract GPS coordinates
            gps_lat = tags.get('GPS GPSLatitude')
            gps_lat_ref = tags.get('GPS GPSLatitudeRef')
            gps_lon = tags.get('GPS GPSLongitude')
            gps_lon_ref = tags.get('GPS GPSLongitudeRef')

            if gps_lat and gps_lon:
                lat = convert_gps_to_decimal(gps_lat, gps_lat_ref)
                lon = convert_gps_to_decimal(gps_lon, gps_lon_ref)
                if lat and lon:
                    results['gps'] = {
                        'latitude': lat,
                        'longitude': lon
                    }

    except ImportError as e:
        results['error'] = f'Missing library: {str(e)}'
    except Exception as e:
        results['error'] = str(e)
    finally:
        # Optionally clean up file
        pass

    # Save to case if provided
    if case_id:
        save_search(case_id, 'image', filename, results)

    return jsonify(results)


def convert_gps_to_decimal(coord, ref):
    """Convert GPS coordinates to decimal format."""
    try:
        # Parse the coordinate values
        values = str(coord).replace('[', '').replace(']', '').split(',')

        def parse_ratio(s):
            s = s.strip()
            if '/' in s:
                num, denom = s.split('/')
                return float(num) / float(denom)
            return float(s)

        degrees = parse_ratio(values[0])
        minutes = parse_ratio(values[1])
        seconds = parse_ratio(values[2])

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

        if str(ref) in ['S', 'W']:
            decimal = -decimal

        return round(decimal, 6)
    except:
        return None


@app.route('/api/document/analyze', methods=['POST'])
def analyze_document():
    """Analyze document metadata."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    case_id = request.form.get('case_id')

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Save file temporarily
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    results = {
        'filename': filename,
        'metadata': {},
        'file_type': None
    }

    # Detect file type
    ext = os.path.splitext(filename)[1].lower()

    try:
        if ext == '.pdf':
            results['file_type'] = 'PDF'
            results['metadata'] = extract_pdf_metadata(filepath)
        elif ext in ['.docx', '.doc']:
            results['file_type'] = 'Word Document'
            results['metadata'] = extract_docx_metadata(filepath)
        else:
            results['error'] = f'Unsupported file type: {ext}'

    except Exception as e:
        results['error'] = str(e)

    # Save to case if provided
    if case_id:
        save_search(case_id, 'document', filename, results)

    return jsonify(results)


def extract_pdf_metadata(filepath):
    """Extract metadata from PDF file."""
    metadata = {}
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(filepath)

        if reader.metadata:
            for key, value in reader.metadata.items():
                # Clean up key name
                clean_key = key.replace('/', '').replace('_', ' ')
                metadata[clean_key] = str(value) if value else None

        metadata['Page Count'] = len(reader.pages)

    except ImportError:
        metadata['error'] = 'PyPDF2 not installed'
    except Exception as e:
        metadata['error'] = str(e)

    return metadata


def extract_docx_metadata(filepath):
    """Extract metadata from Word document."""
    metadata = {}
    try:
        from docx import Document
        doc = Document(filepath)

        core_props = doc.core_properties

        metadata['Author'] = core_props.author
        metadata['Created'] = str(core_props.created) if core_props.created else None
        metadata['Modified'] = str(core_props.modified) if core_props.modified else None
        metadata['Last Modified By'] = core_props.last_modified_by
        metadata['Title'] = core_props.title
        metadata['Subject'] = core_props.subject
        metadata['Keywords'] = core_props.keywords
        metadata['Category'] = core_props.category
        metadata['Comments'] = core_props.comments
        metadata['Revision'] = core_props.revision

    except ImportError:
        metadata['error'] = 'python-docx not installed'
    except Exception as e:
        metadata['error'] = str(e)

    return metadata


# ============================================================
# API ROUTES - CASES
# ============================================================

@app.route('/api/cases', methods=['GET', 'POST'])
def api_cases():
    """List or create cases."""
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        data = request.json
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()

        if not name:
            return jsonify({'error': 'Case name is required'}), 400

        case_id = generate_id()
        cursor.execute('''
            INSERT INTO cases (id, name, description)
            VALUES (?, ?, ?)
        ''', (case_id, name, description))

        conn.commit()
        conn.close()

        return jsonify({'id': case_id, 'name': name})

    # GET - list all cases
    cursor.execute('''
        SELECT c.*,
               (SELECT COUNT(*) FROM searches WHERE case_id = c.id) as search_count
        FROM cases c
        ORDER BY c.updated_at DESC
    ''')
    cases = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify(cases)


@app.route('/api/cases/<case_id>', methods=['GET', 'PUT', 'DELETE'])
def api_case(case_id):
    """Get, update, or delete a case."""
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'DELETE':
        cursor.execute('DELETE FROM searches WHERE case_id = ?', (case_id,))
        cursor.execute('DELETE FROM relationships WHERE case_id = ?', (case_id,))
        cursor.execute('DELETE FROM entities WHERE case_id = ?', (case_id,))
        cursor.execute('DELETE FROM cases WHERE id = ?', (case_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

    if request.method == 'PUT':
        data = request.json
        name = data.get('name')
        description = data.get('description')
        status = data.get('status')

        updates = []
        values = []

        if name:
            updates.append('name = ?')
            values.append(name)
        if description is not None:
            updates.append('description = ?')
            values.append(description)
        if status:
            updates.append('status = ?')
            values.append(status)

        if updates:
            updates.append('updated_at = CURRENT_TIMESTAMP')
            values.append(case_id)

            cursor.execute(f'''
                UPDATE cases SET {', '.join(updates)} WHERE id = ?
            ''', values)
            conn.commit()

        conn.close()
        return jsonify({'success': True})

    # GET
    cursor.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
    case = cursor.fetchone()

    if not case:
        conn.close()
        return jsonify({'error': 'Case not found'}), 404

    conn.close()
    return jsonify(dict(case))


@app.route('/api/cases/<case_id>/report')
def generate_report(case_id):
    """Generate HTML report for a case."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
    case = cursor.fetchone()

    if not case:
        conn.close()
        return jsonify({'error': 'Case not found'}), 404

    cursor.execute('SELECT * FROM searches WHERE case_id = ? ORDER BY created_at', (case_id,))
    searches = cursor.fetchall()

    cursor.execute('SELECT * FROM entities WHERE case_id = ?', (case_id,))
    entities = cursor.fetchall()

    conn.close()

    # Generate HTML report
    report = render_template('report.html', case=case, searches=searches, entities=entities)

    return Response(
        report,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename=case_{case_id}_report.html'}
    )


# ============================================================
# API ROUTES - GRAPH
# ============================================================

@app.route('/api/graph/<case_id>')
def get_graph_data(case_id):
    """Get graph data for visualization."""
    conn = get_db()
    cursor = conn.cursor()

    # Get entities
    cursor.execute('SELECT * FROM entities WHERE case_id = ?', (case_id,))
    entities = cursor.fetchall()

    # Get relationships
    cursor.execute('SELECT * FROM relationships WHERE case_id = ?', (case_id,))
    relationships = cursor.fetchall()

    conn.close()

    # Format for vis.js
    nodes = []
    for entity in entities:
        node = {
            'id': entity['id'],
            'label': entity['value'],
            'group': entity['entity_type'],
            'title': f"{entity['entity_type']}: {entity['value']}"
        }
        nodes.append(node)

    edges = []
    for rel in relationships:
        edge = {
            'from': rel['source_entity_id'],
            'to': rel['target_entity_id'],
            'label': rel['relationship_type'] or 'related'
        }
        edges.append(edge)

    return jsonify({'nodes': nodes, 'edges': edges})


@app.route('/api/graph/entity', methods=['POST'])
def add_graph_entity():
    """Manually add an entity to the graph."""
    data = request.json
    case_id = data.get('case_id')
    entity_type = data.get('type')
    value = data.get('value')

    if not all([case_id, entity_type, value]):
        return jsonify({'error': 'Missing required fields'}), 400

    entity_id = add_entity(case_id, entity_type, value)
    return jsonify({'id': entity_id})


@app.route('/api/graph/relationship', methods=['POST'])
def add_graph_relationship():
    """Manually add a relationship."""
    data = request.json
    case_id = data.get('case_id')
    source_id = data.get('source_id')
    target_id = data.get('target_id')
    rel_type = data.get('relationship_type', 'related')

    if not all([case_id, source_id, target_id]):
        return jsonify({'error': 'Missing required fields'}), 400

    rel_id = add_relationship(case_id, source_id, target_id, rel_type)
    return jsonify({'id': rel_id})


# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    print("=" * 50)
    print("PI OSINT Dashboard")
    print("=" * 50)
    print(f"Database: {DB_PATH}")
    print("Starting server at http://127.0.0.1:5000")
    print("=" * 50)

    app.run(debug=True, threaded=True, host='127.0.0.1', port=5000)
