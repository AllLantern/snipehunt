# PI OSINT Dashboard - Setup Guide

A comprehensive browser-based OSINT toolkit for private investigators.

## System Requirements

- **Python**: 3.9 or higher
- **OS**: Windows 10/11, Linux, or macOS
- **Browser**: Chrome, Firefox, or Edge (modern versions)
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 500MB for application + space for case data

---

## Quick Start

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Run the application
python app.py

# 3. Open browser to http://127.0.0.1:5000
```

---

## Detailed Installation

### Step 1: Python Dependencies

Install all required Python packages:

```bash
pip install -r requirements.txt
```

This installs:
| Package | Purpose |
|---------|---------|
| Flask | Web framework |
| phonenumbers | Phone number validation and lookup |
| Pillow | Image processing |
| exifread | EXIF metadata extraction |
| PyPDF2 | PDF metadata extraction |
| python-docx | Word document metadata |
| python-whois | WHOIS lookups |
| requests | HTTP requests |
| gevent | Async support |

---

### Step 2: OSINT Tools (Optional but Recommended)

The dashboard integrates with several OSINT command-line tools. Install the ones you need:

#### Sherlock (Username Search)
Searches 400+ social networks for usernames.

```bash
pip install sherlock-project
```

**Test installation:**
```bash
sherlock --version
```

#### Maigret (Advanced Username Search)
Extended username search with more sites and detailed reports.

```bash
pip install maigret
```

**Test installation:**
```bash
maigret --version
```

#### Holehe (Email OSINT)
Checks if an email is registered on various websites.

```bash
pip install holehe
```

**Test installation:**
```bash
holehe --help
```

#### theHarvester (Domain Reconnaissance)
Gathers emails, subdomains, hosts, and IPs from public sources.

```bash
pip install theHarvester
```

**Test installation:**
```bash
theHarvester --help
```

#### SpiderFoot (Comprehensive OSINT)
Full-featured OSINT automation tool.

**Option A - pip install:**
```bash
pip install spiderfoot
```

**Option B - Standalone (recommended for full features):**
1. Download from: https://github.com/smicallef/spiderfoot/releases
2. Extract to a folder
3. Run: `python sf.py -l 127.0.0.1:5001`

**Note:** SpiderFoot has its own web interface. The dashboard integrates with its CLI mode.

---

### Step 3: System Tools

#### WHOIS (Domain Lookups)

**Windows:**
- The dashboard uses `python-whois` library (installed via requirements.txt)
- No additional installation needed

**Linux:**
```bash
# Debian/Ubuntu
sudo apt install whois

# RHEL/CentOS
sudo yum install whois
```

**macOS:**
```bash
brew install whois
```

---

## Running the Application

### Basic Start
```bash
python app.py
```

The server starts at `http://127.0.0.1:5000`

### What Gets Created

On first run, the application creates:

| Path | Purpose |
|------|---------|
| `~/.pi-toolkit/cases.db` | SQLite database for cases and searches |
| `~/.pi-toolkit/.secret_key` | Session encryption key |
| `./uploads/` | Temporary file uploads (auto-cleaned) |

---

## Feature Availability

| Feature | Requires | Status if Missing |
|---------|----------|-------------------|
| Username Search | sherlock, maigret | Shows install instructions |
| Email OSINT | holehe | Shows install instructions |
| Phone Lookup | phonenumbers (pip) | Core feature, always works |
| Domain Recon | theHarvester | Shows install instructions |
| SpiderFoot | spiderfoot | Shows install instructions |
| Image Analysis | Pillow, exifread (pip) | Core feature, always works |
| Document Analysis | PyPDF2, python-docx (pip) | Core feature, always works |
| IP Geolocation | None (uses ip-api.com) | Core feature, always works |
| WHOIS Lookup | python-whois (pip) | Core feature, always works |
| Cases & Graph | None | Core feature, always works |

---

## Troubleshooting

### "Module not found" errors
```bash
# Reinstall all dependencies
pip install --upgrade -r requirements.txt
```

### "Sherlock/Maigret not found"
The tools must be in your system PATH. After pip install:
```bash
# Find where pip installed it
pip show sherlock-project | grep Location

# Add to PATH if needed (Windows)
# Add the Scripts folder to your PATH environment variable
```

### Database errors
Delete the database to reset:
```bash
# Windows
del %USERPROFILE%\.pi-toolkit\cases.db

# Linux/macOS
rm ~/.pi-toolkit/cases.db
```

### Port 5000 already in use
Edit the last line of `app.py`:
```python
app.run(debug=True, threaded=True, host='127.0.0.1', port=5001)  # Change port
```

### Windows-specific: Long path errors
Enable long paths in Windows:
1. Run `regedit` as administrator
2. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`
3. Set `LongPathsEnabled` to `1`
4. Restart

---

## Security Notes

1. **Local Only**: By default, the server only listens on `127.0.0.1` (localhost)
2. **No Authentication**: Add authentication if exposing to a network
3. **API Keys**: Store sensitive API keys in the Settings page (encrypted in database)
4. **File Uploads**: Uploaded files are processed and immediately deleted

---

## Keyboard Shortcuts

Press `g` then a letter to navigate:

| Shortcut | Page |
|----------|------|
| `g` + `h` | Dashboard (Home) |
| `g` + `u` | Username Search |
| `g` + `e` | Email OSINT |
| `g` + `p` | Phone Lookup |
| `g` + `d` | Domain Recon |
| `g` + `i` | IP/WHOIS |
| `g` + `b` | Batch Search |
| `g` + `c` | Cases |
| `g` + `g` | Relationship Graph |
| `g` + `s` | Settings |

---

## Recommended Setup Order

1. Install Python dependencies (required)
2. Install Sherlock (most commonly used)
3. Install Holehe (email investigations)
4. Test basic functionality
5. Add other tools as needed

---

## Support

- Check the browser console (F12) for JavaScript errors
- Check the terminal running `app.py` for Python errors
- Database is at `~/.pi-toolkit/cases.db` (SQLite, can be opened with DB Browser)
