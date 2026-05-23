from flask import Flask, render_template, request, jsonify
import re
import os
import math
import hashlib
import json
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max

# ─── KNOWN MALWARE HASHES (SHA256) — sample known bad hashes ───
KNOWN_BAD_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty file (suspicious)",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR test malware signature",
}

# ─── DANGEROUS PATTERNS ───────────────────────────────────────────

PATTERNS = {
    "python": [
        (r'\beval\s*\(', "CRITICAL", "eval() — arbitrary code execution risk"),
        (r'\bexec\s*\(', "CRITICAL", "exec() — arbitrary code execution risk"),
        (r'__import__\s*\(', "HIGH", "Dynamic import — code injection risk"),
        (r'subprocess\.(call|run|Popen)', "HIGH", "Subprocess call — command injection risk"),
        (r'os\.system\s*\(', "HIGH", "os.system() — command injection risk"),
        (r'os\.popen\s*\(', "HIGH", "os.popen() — command injection risk"),
        (r'pickle\.(loads|load)\s*\(', "HIGH", "Pickle deserialization — RCE risk"),
        (r'marshal\.loads\s*\(', "HIGH", "Marshal deserialization — RCE risk"),
        (r'input\s*\(.*\)', "MEDIUM", "Unvalidated user input"),
        (r'requests\.get\([^)]*verify\s*=\s*False', "MEDIUM", "SSL verification disabled"),
        (r'hashlib\.md5\s*\(', "LOW", "MD5 is cryptographically weak"),
        (r'hashlib\.sha1\s*\(', "LOW", "SHA1 is cryptographically weak"),
        (r'random\.\w+\(', "LOW", "Non-cryptographic random — use secrets module"),
        (r'password\s*=\s*["\'][^"\']+["\']', "HIGH", "Hardcoded password detected"),
        (r'secret\s*=\s*["\'][^"\']+["\']', "HIGH", "Hardcoded secret detected"),
        (r'api_key\s*=\s*["\'][^"\']+["\']', "HIGH", "Hardcoded API key detected"),
        (r'SELECT.+FROM.+WHERE.+\+', "HIGH", "SQL injection risk — string concatenation in query"),
        (r'DROP\s+TABLE', "CRITICAL", "Destructive SQL statement"),
    ],
    "javascript": [
        (r'\beval\s*\(', "CRITICAL", "eval() — arbitrary code execution"),
        (r'document\.write\s*\(', "HIGH", "document.write() — XSS risk"),
        (r'innerHTML\s*=', "HIGH", "innerHTML assignment — XSS risk"),
        (r'outerHTML\s*=', "HIGH", "outerHTML assignment — XSS risk"),
        (r'setTimeout\s*\(\s*["\']', "HIGH", "String in setTimeout — code injection"),
        (r'setInterval\s*\(\s*["\']', "HIGH", "String in setInterval — code injection"),
        (r'new\s+Function\s*\(', "HIGH", "new Function() — code injection risk"),
        (r'location\.href\s*=', "MEDIUM", "Open redirect risk"),
        (r'window\.location\s*=', "MEDIUM", "Open redirect risk"),
        (r'localStorage\.setItem.*password', "HIGH", "Password stored in localStorage"),
        (r'console\.log.*password', "MEDIUM", "Password logged to console"),
        (r'http://', "LOW", "HTTP (not HTTPS) URL detected"),
        (r'var\s+password\s*=\s*["\']', "HIGH", "Hardcoded password"),
        (r'api_key\s*[:=]\s*["\'][^"\']+["\']', "HIGH", "Hardcoded API key"),
        (r'Math\.random\(\)', "LOW", "Non-cryptographic random number"),
    ],
    "php": [
        (r'\beval\s*\(', "CRITICAL", "eval() — arbitrary code execution"),
        (r'system\s*\(', "CRITICAL", "system() — OS command injection"),
        (r'exec\s*\(', "CRITICAL", "exec() — OS command injection"),
        (r'shell_exec\s*\(', "CRITICAL", "shell_exec() — OS command injection"),
        (r'passthru\s*\(', "CRITICAL", "passthru() — OS command injection"),
        (r'\$_GET\[', "MEDIUM", "Unvalidated GET parameter"),
        (r'\$_POST\[', "MEDIUM", "Unvalidated POST parameter"),
        (r'\$_REQUEST\[', "MEDIUM", "Unvalidated REQUEST parameter"),
        (r'mysql_query\s*\(', "HIGH", "Deprecated mysql_query — SQLi risk"),
        (r'include\s*\(\s*\$', "CRITICAL", "Dynamic include — LFI/RFI risk"),
        (r'require\s*\(\s*\$', "CRITICAL", "Dynamic require — LFI/RFI risk"),
        (r'md5\s*\(', "LOW", "MD5 is cryptographically weak"),
        (r'base64_decode\s*\(.*eval', "CRITICAL", "Obfuscated code execution pattern"),
        (r'password\s*=\s*["\'][^"\']+["\']', "HIGH", "Hardcoded password"),
    ],
    "generic": [
        (r'password\s*[:=]\s*["\'][^"\']{3,}["\']', "HIGH", "Hardcoded password detected"),
        (r'secret\s*[:=]\s*["\'][^"\']{3,}["\']', "HIGH", "Hardcoded secret detected"),
        (r'api[_\-]?key\s*[:=]\s*["\'][^"\']{8,}["\']', "HIGH", "Hardcoded API key detected"),
        (r'token\s*[:=]\s*["\'][^"\']{8,}["\']', "MEDIUM", "Hardcoded token detected"),
        (r'private[_\-]?key\s*[:=]', "CRITICAL", "Private key reference detected"),
        (r'BEGIN RSA PRIVATE KEY', "CRITICAL", "RSA private key exposed!"),
        (r'BEGIN OPENSSH PRIVATE KEY', "CRITICAL", "SSH private key exposed!"),
        (r'AKIA[0-9A-Z]{16}', "CRITICAL", "AWS Access Key ID exposed!"),
        (r'[0-9a-f]{32}', "LOW", "Potential MD5 hash or token in plaintext"),
        (r'(?i)todo.*security', "LOW", "Security-related TODO comment"),
        (r'(?i)fixme.*auth', "MEDIUM", "Auth-related FIXME comment"),
    ]
}

SEVERITY_SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}

# ─── HELPERS ─────────────────────────────────────────────────────

def detect_language(filename, content):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    ext_map = {
        'py': 'python', 'js': 'javascript', 'ts': 'javascript',
        'jsx': 'javascript', 'tsx': 'javascript', 'php': 'php',
        'java': 'java', 'cs': 'csharp', 'rb': 'ruby',
        'sh': 'shell', 'bash': 'shell', 'sql': 'sql',
        'html': 'html', 'htm': 'html', 'xml': 'xml',
        'json': 'json', 'yaml': 'yaml', 'yml': 'yaml',
        'env': 'env', 'cfg': 'config', 'conf': 'config',
        'txt': 'text', 'md': 'text',
    }
    return ext_map.get(ext, 'generic')

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return round(entropy, 2)

def check_file_hash(content_bytes):
    sha256 = hashlib.sha256(content_bytes).hexdigest()
    md5 = hashlib.md5(content_bytes).hexdigest()
    known = KNOWN_BAD_HASHES.get(sha256) or KNOWN_BAD_HASHES.get(md5)
    return sha256, md5, known

def scan_patterns(content, language):
    findings = []
    patterns = PATTERNS.get(language, []) + PATTERNS['generic']
    lines = content.split('\n')

    for pattern, severity, description in patterns:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "line": i,
                    "severity": severity,
                    "description": description,
                    "code": line.strip()[:120],
                    "pattern": pattern
                })

    # Deduplicate by description + line
    seen = set()
    unique = []
    for f in findings:
        key = f"{f['description']}:{f['line']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

def analyze_structure(content, language):
    checks = []
    lines = content.split('\n')
    total_lines = len(lines)
    blank_lines = sum(1 for l in lines if not l.strip())
    comment_lines = sum(1 for l in lines if l.strip().startswith(('#', '//', '/*', '*', '<!--')))

    checks.append({
        "label": "Total Lines",
        "value": str(total_lines),
        "status": "info"
    })
    checks.append({
        "label": "Comment Coverage",
        "value": f"{round(comment_lines/max(total_lines,1)*100)}%",
        "status": "pass" if comment_lines/max(total_lines,1) > 0.1 else "warn"
    })

    # Check for extremely long lines (obfuscation signal)
    long_lines = [i+1 for i, l in enumerate(lines) if len(l) > 500]
    checks.append({
        "label": "Long Lines (>500 chars)",
        "value": str(len(long_lines)),
        "status": "fail" if long_lines else "pass"
    })

    # Entropy check
    entropy = calculate_entropy(content[:5000])
    checks.append({
        "label": "Entropy Score",
        "value": str(entropy),
        "status": "fail" if entropy > 6.5 else "warn" if entropy > 5.5 else "pass"
    })

    # Check for null bytes (binary in text)
    has_null = '\x00' in content
    checks.append({
        "label": "Binary Content",
        "value": "Detected" if has_null else "Clean",
        "status": "warn" if has_null else "pass"
    })

    return checks

def calculate_risk_score(findings):
    penalty = sum(SEVERITY_SCORE.get(f['severity'], 0) for f in findings)
    score = max(0, 100 - penalty)
    return score

def get_grade(score):
    if score >= 90: return "A", "Secure"
    if score >= 75: return "B", "Mostly Safe"
    if score >= 60: return "C", "Moderate Risk"
    if score >= 40: return "D", "High Risk"
    return "F", "Critical Risk"

def get_recommendations(findings, language):
    recs = []
    severities = [f['severity'] for f in findings]

    if 'CRITICAL' in severities:
        recs.append("🚨 Fix all CRITICAL issues immediately before deployment")
    if any('eval' in f['description'] for f in findings):
        recs.append("🔧 Replace eval()/exec() with safe alternatives like ast.literal_eval()")
    if any('SQL' in f['description'] or 'sql' in f['description'].lower() for f in findings):
        recs.append("🛡️ Use parameterized queries / prepared statements to prevent SQL injection")
    if any('password' in f['description'].lower() or 'secret' in f['description'].lower() for f in findings):
        recs.append("🔑 Move secrets to environment variables — never hardcode credentials")
    if any('XSS' in f['description'] for f in findings):
        recs.append("🌐 Sanitize all user inputs and use textContent instead of innerHTML")
    if any('MD5' in f['description'] or 'SHA1' in f['description'] for f in findings):
        recs.append("🔐 Upgrade to SHA-256 or bcrypt for cryptographic operations")
    if any('injection' in f['description'].lower() for f in findings):
        recs.append("⚠️ Validate and sanitize all external inputs before processing")
    if not recs:
        recs.append("✅ No major issues found — maintain secure coding practices")
        recs.append("📋 Continue using code reviews and static analysis in your CI/CD pipeline")

    return recs

# ─── ROUTES ──────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        if 'file' in request.files and request.files['file'].filename:
            f = request.files['file']
            filename = f.filename
            content_bytes = f.read()
            try:
                content = content_bytes.decode('utf-8', errors='replace')
            except:
                content = content_bytes.decode('latin-1', errors='replace')
        elif request.json and request.json.get('code'):
            content = request.json['code']
            filename = request.json.get('filename', 'snippet.txt')
            content_bytes = content.encode('utf-8')
        else:
            return jsonify({"error": "No file or code provided"}), 400

        if len(content) > 500000:
            return jsonify({"error": "File too large — max 500KB"}), 400

        language = detect_language(filename, content)
        sha256, md5, known_bad = check_file_hash(content_bytes)
        findings = scan_patterns(content, language)
        structure = analyze_structure(content, language)
        score = calculate_risk_score(findings)
        grade, grade_label = get_grade(score)
        recommendations = get_recommendations(findings, language)

        # Summary stats
        critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in findings if f['severity'] == 'HIGH')
        medium = sum(1 for f in findings if f['severity'] == 'MEDIUM')
        low = sum(1 for f in findings if f['severity'] == 'LOW')

        return jsonify({
            "filename": filename,
            "language": language,
            "score": score,
            "grade": grade,
            "grade_label": grade_label,
            "scanned_at": datetime.now().strftime("%b %d, %Y at %H:%M"),
            "file_size": f"{len(content_bytes)/1024:.1f} KB",
            "line_count": len(content.split('\n')),
            "hashes": {"sha256": sha256[:32] + "...", "md5": md5},
            "known_malware": known_bad,
            "stats": {"critical": critical, "high": high, "medium": medium, "low": low, "total": len(findings)},
            "findings": findings[:50],  # cap at 50
            "structure": structure,
            "recommendations": recommendations,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
