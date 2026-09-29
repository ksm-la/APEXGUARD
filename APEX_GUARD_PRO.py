"""
APEX GUARD - ALL-IN-ONE EDITION
Python authorized application security auditing toolkit.

Run:
    python APEX_GUARD_all_in_one.py

Dependencies:
    pip install PySide6

Use only against applications, source code, and environments that
you own or have explicit permission to assess.
"""

import sys
import json
import html
import hashlib
import re
import zipfile
from pathlib import Path
from datetime import datetime, timezone

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTextEdit, QProgressBar,
    QGroupBox, QMessageBox
)
from PySide6.QtCore import QThread, Signal

"""
APEX GUARD - Part 8
Risk normalization, scoring and report generation helpers.
"""

import json
import html
from pathlib import Path


class RiskEngine:
    ORDER = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 0
    }

    @classmethod
    def normalize(cls, findings):
        normalized = []

        for item in findings:
            item = dict(item)

            severity = str(item.get("severity", "info")).lower()

            if severity not in cls.ORDER:
                severity = "info"

            item["severity"] = severity
            item["title"] = str(item.get("title", "Untitled finding"))
            item["description"] = str(item.get("description", ""))
            item["evidence"] = str(item.get("evidence", ""))
            item["remediation"] = str(item.get("remediation", ""))

            normalized.append(item)

        normalized.sort(
            key=lambda x: cls.ORDER[x["severity"]],
            reverse=True
        )

        return normalized

    @classmethod
    def summary(cls, findings):
        result = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for item in findings:
            severity = item["severity"]
            result[severity] += 1

        return result

    @classmethod
    def score(cls, findings):
        weights = {
            "critical": 25,
            "high": 12,
            "medium": 5,
            "low": 1,
            "info": 0
        }

        raw = sum(weights[x["severity"]] for x in findings)
        return min(100, raw)


class ReportGenerator:
    @staticmethod
    def save_json(result, destination):
        destination = Path(destination)
        destination.write_text(
            json.dumps(result, indent=2),
            encoding="utf-8"
        )

    @staticmethod
    def save_html(result, destination):
        destination = Path(destination)

        summary = result.get("summary", {})
        findings = result.get("findings", [])

        cards = []
        for severity in ("critical", "high", "medium", "low", "info"):
            cards.append(
                f"<div class='card'><b>{severity.upper()}</b>"
                f"<span>{summary.get(severity, 0)}</span></div>"
            )

        rows = []

        for item in findings:
            severity = html.escape(item["severity"].upper())
            title = html.escape(item["title"])
            description = html.escape(item["description"])
            evidence = html.escape(item["evidence"])
            remediation = html.escape(item["remediation"])

            rows.append(
                "<tr>"
                f"<td><b>{severity}</b></td>"
                f"<td>{title}</td>"
                f"<td>{description}</td>"
                f"<td><code>{evidence}</code></td>"
                f"<td>{remediation}</td>"
                "</tr>"
            )

        page = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>APEX GUARD Security Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 35px;
    background: #f4f6f8;
    color: #20242a;
}}
h1 {{ margin-bottom: 5px; }}
.meta {{
    background: white;
    padding: 18px;
    border-radius: 10px;
    margin-bottom: 20px;
}}
.cards {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}}
.card {{
    background: white;
    padding: 18px;
    border-radius: 10px;
    min-width: 100px;
}}
.card span {{
    display: block;
    font-size: 28px;
    margin-top: 8px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
}}
th, td {{
    padding: 12px;
    border: 1px solid #ddd;
    vertical-align: top;
    text-align: left;
}}
th {{ background: #e9edf1; }}
code {{ white-space: pre-wrap; }}
</style>
</head>
<body>
<h1>🛡 APEX GUARD</h1>
<p>Authorized security audit report</p>

<div class="meta">
<b>Target:</b> {html.escape(result.get("target", ""))}<br>
<b>Type:</b> {html.escape(result.get("target_type", ""))}<br>
<b>Timestamp:</b> {html.escape(result.get("timestamp", ""))}<br>
<b>Risk score:</b> {result.get("risk_score", 0)}/100
</div>

<div class="cards">
{''.join(cards)}
</div>

<table>
<thead>
<tr>
<th>Severity</th>
<th>Finding</th>
<th>Description</th>
<th>Evidence</th>
<th>Remediation</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>
"""

        destination.write_text(page, encoding="utf-8")


"""
APEX GUARD - Part 3
Static source/file analysis.

This module does not execute the target.
"""

from pathlib import Path
import hashlib
import re


class StaticScanner:
    TEXT_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt",
        ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".rb",
        ".go", ".rs", ".json", ".xml", ".yaml", ".yml",
        ".ini", ".cfg", ".conf", ".txt", ".md"
    }

    DANGEROUS_PATTERNS = [
        (
            "STATIC-001",
            "high",
            "Potential command execution sink",
            r"\bos\.system\s*\(|\bsubprocess\.(?:Popen|run|call)\s*\(",
            "Review whether untrusted input can reach a command execution API."
        ),
        (
            "STATIC-002",
            "high",
            "Potential unsafe deserialization",
            r"\bpickle\.(?:load|loads)\s*\(",
            "Avoid deserializing untrusted pickle data."
        ),
        (
            "STATIC-003",
            "medium",
            "Dynamic code execution",
            r"\beval\s*\(|\bexec\s*\(",
            "Avoid dynamic execution of untrusted input."
        ),
        (
            "STATIC-004",
            "medium",
            "TLS certificate verification disabled",
            r"verify\s*=\s*False|CERT_NONE",
            "Keep certificate verification enabled in production."
        ),
        (
            "STATIC-005",
            "medium",
            "Debug mode indicator",
            r"DEBUG\s*=\s*True|debug\s*=\s*True",
            "Disable debugging in production builds."
        ),
    ]

    def __init__(self, target):
        self.target = Path(target)

    def run(self):
        findings = []

        files = list(self.iter_files())

        if not files:
            findings.append({
                "id": "STATIC-000",
                "severity": "info",
                "title": "No text source files discovered",
                "description": "Static source inspection had no supported text files to inspect.",
                "evidence": str(self.target),
                "remediation": "Provide source files or use a format-specific analyzer."
            })
            return findings

        for path in files:
            try:
                text = path.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )
            except OSError:
                continue

            findings.extend(self.scan_text(path, text))

        findings.extend(self.file_inventory(files))
        return findings

    def iter_files(self):
        if self.target.is_file():
            if self.target.suffix.lower() in self.TEXT_EXTENSIONS:
                yield self.target
            return

        ignored = {
            ".git", ".venv", "venv", "__pycache__",
            "node_modules", ".idea", ".vs"
        }

        for path in self.target.rglob("*"):
            if not path.is_file():
                continue

            if any(part in ignored for part in path.parts):
                continue

            if path.suffix.lower() in self.TEXT_EXTENSIONS:
                yield path

    def scan_text(self, path, text):
        findings = []

        for item_id, severity, title, pattern, remediation in self.DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                line = text[:match.start()].count("\n") + 1

                findings.append({
                    "id": item_id,
                    "severity": severity,
                    "title": title,
                    "description": f"Potentially security-sensitive pattern found in {path.name}.",
                    "evidence": f"{path}:{line}: {self.safe_line(text, line)}",
                    "remediation": remediation
                })

        return findings

    @staticmethod
    def safe_line(text, line_number):
        lines = text.splitlines()
        if 1 <= line_number <= len(lines):
            line = lines[line_number - 1].strip()
            return line[:240]
        return ""

    def file_inventory(self, files):
        total_bytes = 0
        hashes = []

        for path in files:
            try:
                data = path.read_bytes()
                total_bytes += len(data)
                digest = hashlib.sha256(data).hexdigest()
                hashes.append((str(path), digest))
            except OSError:
                pass

        return [{
            "id": "STATIC-INFO",
            "severity": "info",
            "title": "Static inventory completed",
            "description": f"Inspected {len(files)} text files.",
            "evidence": f"Total readable bytes: {total_bytes}",
            "remediation": "No action required."
        }]


"""
APEX GUARD - Part 4
Permission and manifest checks.
"""

from pathlib import Path
import re
import zipfile


class PermissionScanner:
    SENSITIVE = {
        "android.permission.READ_SMS": "Access to SMS messages",
        "android.permission.RECEIVE_SMS": "Receive SMS messages",
        "android.permission.READ_CONTACTS": "Read contacts",
        "android.permission.WRITE_CONTACTS": "Modify contacts",
        "android.permission.RECORD_AUDIO": "Record audio",
        "android.permission.CAMERA": "Camera access",
        "android.permission.ACCESS_FINE_LOCATION": "Precise location",
        "android.permission.ACCESS_COARSE_LOCATION": "Approximate location",
        "android.permission.READ_EXTERNAL_STORAGE": "Read external storage",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Write external storage",
    }

    def __init__(self, target):
        self.target = Path(target)

    def run(self):
        if self.target.suffix.lower() == ".apk":
            return self.scan_apk()

        if self.target.is_dir():
            return self.scan_project()

        return [{
            "id": "PERM-INFO",
            "severity": "info",
            "title": "Permission analysis not applicable",
            "description": "No Android APK or recognizable project manifest was supplied.",
            "evidence": str(self.target),
            "remediation": "Use an APK or Android source project for permission analysis."
        }]

    def scan_apk(self):
        findings = []

        try:
            with zipfile.ZipFile(self.target) as archive:
                names = archive.namelist()

                if "AndroidManifest.xml" not in names:
                    return [{
                        "id": "PERM-001",
                        "severity": "medium",
                        "title": "Android manifest not directly available",
                        "description": "The APK contains a compiled manifest that requires a format-aware decoder.",
                        "evidence": "AndroidManifest.xml is binary/compiled.",
                        "remediation": "Use an authorized APK analysis tool that decodes Android resources."
                    }]

                raw = archive.read("AndroidManifest.xml")
                text = raw.decode("utf-8", errors="ignore")

                for permission, description in self.SENSITIVE.items():
                    if permission in text:
                        findings.append({
                            "id": "PERM-002",
                            "severity": "info",
                            "title": "Sensitive Android permission requested",
                            "description": description,
                            "evidence": permission,
                            "remediation": "Confirm that this permission is necessary and properly disclosed."
                        })

        except zipfile.BadZipFile:
            findings.append({
                "id": "PERM-003",
                "severity": "high",
                "title": "Invalid APK archive",
                "description": "The supplied APK could not be read as a ZIP archive.",
                "evidence": str(self.target),
                "remediation": "Verify the APK file and obtain a clean build."
            })

        return findings

    def scan_project(self):
        findings = []

        manifests = list(self.target.rglob("AndroidManifest.xml"))

        for manifest in manifests[:20]:
            try:
                text = manifest.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )
            except OSError:
                continue

            for permission, description in self.SENSITIVE.items():
                if permission in text:
                    findings.append({
                        "id": "PERM-004",
                        "severity": "info",
                        "title": "Sensitive permission in project",
                        "description": description,
                        "evidence": f"{manifest}: {permission}",
                        "remediation": "Check whether the permission is necessary."
                    })

            if 'android:debuggable="true"' in text:
                findings.append({
                    "id": "PERM-005",
                    "severity": "medium",
                    "title": "Android debuggable flag enabled",
                    "description": "The manifest explicitly enables debugging.",
                    "evidence": str(manifest),
                    "remediation": "Disable debuggable mode for production builds."
                })

        if not findings:
            findings.append({
                "id": "PERM-INFO",
                "severity": "info",
                "title": "Permission inspection completed",
                "description": "No notable permission issue was identified by this basic scanner.",
                "evidence": str(self.target),
                "remediation": "Perform a deeper platform-specific review before release."
            })

        return findings


"""
APEX GUARD - Part 5
Conservative hard-coded secret detection.

The scanner reports suspicious patterns but does not transmit or exploit
discovered values.
"""

from pathlib import Path
import re


class SecretScanner:
    MAX_FILE_SIZE = 2 * 1024 * 1024

    PATTERNS = [
        (
            "SECRET-001",
            "high",
            "Possible API key assignment",
            r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"
        ),
        (
            "SECRET-002",
            "high",
            "Possible access token assignment",
            r"(?i)\b(access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"][^'\"]{16,}['\"]"
        ),
        (
            "SECRET-003",
            "high",
            "Possible private key material",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        (
            "SECRET-004",
            "medium",
            "Possible database credential",
            r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]"
        ),
        (
            "SECRET-005",
            "medium",
            "Possible cloud credential",
            r"(?i)\b(AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS)\b"
        ),
    ]

    EXTENSIONS = {
        ".py", ".js", ".ts", ".java", ".kt", ".json", ".xml",
        ".yaml", ".yml", ".ini", ".env", ".cfg", ".conf",
        ".php", ".rb", ".go", ".rs", ".cs", ".txt"
    }

    def __init__(self, target):
        self.target = Path(target)

    def run(self):
        findings = []

        for path in self.iter_files():
            try:
                if path.stat().st_size > self.MAX_FILE_SIZE:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for item_id, severity, title, pattern in self.PATTERNS:
                match = re.search(pattern, text)

                if not match:
                    continue

                line = text[:match.start()].count("\n") + 1

                findings.append({
                    "id": item_id,
                    "severity": severity,
                    "title": title,
                    "description": (
                        "A pattern resembling a credential or secret was detected. "
                        "The scanner intentionally does not print the suspected value."
                    ),
                    "evidence": f"{path}:{line}",
                    "remediation": (
                        "Remove secrets from source control, rotate exposed credentials, "
                        "and use an appropriate secret-management mechanism."
                    )
                })

        if not findings:
            findings.append({
                "id": "SECRET-INFO",
                "severity": "info",
                "title": "No obvious hard-coded secret patterns found",
                "description": "The conservative pattern scanner found no matches.",
                "evidence": str(self.target),
                "remediation": "Use dedicated secret scanners as an additional control."
            })

        return findings

    def iter_files(self):
        if self.target.is_file():
            if self.target.suffix.lower() in self.EXTENSIONS:
                yield self.target
            return

        ignored = {
            ".git", ".venv", "venv", "node_modules",
            "__pycache__", "dist", "build"
        }

        for path in self.target.rglob("*"):
            if path.is_file() and path.suffix.lower() in self.EXTENSIONS:
                if not any(part in ignored for part in path.parts):
                    yield path


"""
APEX GUARD - Part 6
Dependency inventory and basic version hygiene checks.
"""

from pathlib import Path
import json
import re


class DependencyScanner:
    FILES = {
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
    }

    def __init__(self, target):
        self.target = Path(target)

    def run(self):
        findings = []
        found = []

        for path in self.iter_dependency_files():
            found.append(str(path))

            if path.name.startswith("requirements"):
                findings.extend(self.requirements(path))
            elif path.name == "package.json":
                findings.extend(self.package_json(path))
            elif path.name == "pyproject.toml":
                findings.extend(self.pyproject(path))

        if not found:
            findings.append({
                "id": "DEP-INFO",
                "severity": "info",
                "title": "No recognized dependency manifest found",
                "description": "No supported dependency manifest was discovered.",
                "evidence": str(self.target),
                "remediation": "Add dependency manifests and pin production dependencies."
            })
        else:
            findings.append({
                "id": "DEP-INV",
                "severity": "info",
                "title": "Dependency manifests discovered",
                "description": f"Found {len(found)} supported dependency file(s).",
                "evidence": "; ".join(found[:10]),
                "remediation": "Review dependency versions and use automated vulnerability monitoring."
            })

        return findings

    def iter_dependency_files(self):
        if self.target.is_file():
            if self.target.name in self.FILES:
                yield self.target
            return

        for path in self.target.rglob("*"):
            if path.is_file() and path.name in self.FILES:
                if ".git" not in path.parts and "node_modules" not in path.parts:
                    yield path

    def requirements(self, path):
        findings = []

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        for number, line in enumerate(text.splitlines(), 1):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "==" not in line and not line.startswith("-"):
                findings.append({
                    "id": "DEP-001",
                    "severity": "low",
                    "title": "Unpinned Python dependency",
                    "description": "A requirement does not use an exact version pin.",
                    "evidence": f"{path}:{number}: {line[:120]}",
                    "remediation": "Consider pinning production dependencies and maintaining lock files."
                })

        return findings

    def package_json(self, path):
        findings = []

        try:
            data = json.loads(path.read_text(
                encoding="utf-8", errors="ignore"
            ))
        except (OSError, json.JSONDecodeError):
            return [{
                "id": "DEP-002",
                "severity": "medium",
                "title": "Invalid package.json",
                "description": "The package manifest could not be parsed.",
                "evidence": str(path),
                "remediation": "Fix the manifest and validate it before deployment."
            }]

        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))

        for name, version in deps.items():
            if isinstance(version, str) and version.startswith("*"):
                findings.append({
                    "id": "DEP-003",
                    "severity": "low",
                    "title": "Wildcard dependency version",
                    "description": f"{name} uses a wildcard version range.",
                    "evidence": f"{name}: {version}",
                    "remediation": "Use a controlled version range or lockfile."
                })

        return findings

    def pyproject(self, path):
        findings = []

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        if re.search(r"dependencies\s*=\s*\[[^\]]+", text, re.I | re.S):
            if not re.search(r"[A-Za-z0-9_-]+\s*==\s*[0-9]", text):
                findings.append({
                    "id": "DEP-004",
                    "severity": "low",
                    "title": "PyProject dependencies may be loosely constrained",
                    "description": "The basic parser could not confirm exact version pins.",
                    "evidence": str(path),
                    "remediation": "Use a lockfile or controlled dependency constraints."
                })

        return findings


"""
APEX GUARD - Part 7
Network/security configuration checks.
No active probing or exploitation is performed.
"""

from pathlib import Path
import re


class NetworkScanner:
    URL_PATTERN = re.compile(
        r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
        re.I
    )

    def __init__(self, target):
        self.target = Path(target)

    def run(self):
        findings = []

        for path in self.iter_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            urls = self.URL_PATTERN.findall(text)

            for url in urls:
                if url.lower().startswith("http://"):
                    findings.append({
                        "id": "NET-001",
                        "severity": "medium",
                        "title": "Unencrypted HTTP endpoint referenced",
                        "description": "The application source references an HTTP URL.",
                        "evidence": self.redact_url(url),
                        "remediation": "Use HTTPS unless plaintext HTTP is explicitly required and protected elsewhere."
                    })

            if re.search(r"ssl\._create_unverified_context|verify\s*=\s*False", text, re.I):
                findings.append({
                    "id": "NET-002",
                    "severity": "high",
                    "title": "TLS verification may be disabled",
                    "description": "The source contains a common pattern associated with disabled TLS verification.",
                    "evidence": str(path),
                    "remediation": "Use normal certificate and hostname verification."
                })

        if not findings:
            findings.append({
                "id": "NET-INFO",
                "severity": "info",
                "title": "Network configuration scan completed",
                "description": "No basic network configuration issue was detected.",
                "evidence": str(self.target),
                "remediation": "Review runtime traffic separately in an authorized test environment."
            })

        return findings

    def iter_files(self):
        extensions = {
            ".py", ".js", ".ts", ".java", ".kt", ".cs",
            ".go", ".rs", ".php", ".rb", ".json", ".xml",
            ".yaml", ".yml", ".ini", ".cfg"
        }

        if self.target.is_file():
            if self.target.suffix.lower() in extensions:
                yield self.target
            return

        for path in self.target.rglob("*"):
            if path.is_file() and path.suffix.lower() in extensions:
                if ".git" not in path.parts and "node_modules" not in path.parts:
                    yield path

    @staticmethod
    def redact_url(url):
        # Keep host and scheme, but avoid returning query strings or tokens.
        cleaned = url.split("?", 1)[0]
        return cleaned[:180]


"""
APEX GUARD - Part 2
Scan orchestration and safe target classification.
"""

from pathlib import Path
from datetime import datetime, timezone



class SecurityEngine:
    def __init__(self, target):
        self.target = Path(target).resolve()

        if not self.target.exists():
            raise FileNotFoundError(f"Target does not exist: {self.target}")

        self.findings = []

    def classify(self):
        if self.target.is_dir():
            return "project"

        suffix = self.target.suffix.lower()

        if suffix == ".apk":
            return "apk"

        if suffix == ".exe":
            return "windows_executable"

        if suffix in {".py", ".js", ".ts", ".java", ".cs", ".cpp", ".c"}:
            return "source"

        if suffix in {".zip", ".jar"}:
            return "archive"

        return "unknown"

    def scan(self, progress_callback=None):
        kind = self.classify()

        def progress(value, message):
            if progress_callback:
                progress_callback(value, message)

        progress(5, "Initializing scanner")

        self.findings = []

        scanners = [
            (StaticScanner(self.target), 15, 25, "Running static analysis"),
            (PermissionScanner(self.target), 25, 40, "Checking permissions"),
            (SecretScanner(self.target), 40, 55, "Searching for exposed secrets"),
            (DependencyScanner(self.target), 55, 70, "Inspecting dependencies"),
            (NetworkScanner(self.target), 70, 85, "Checking network configuration"),
        ]

        for scanner, start, end, message in scanners:
            progress(start, message)

            try:
                results = scanner.run()
                self.findings.extend(results)
            except Exception as exc:
                self.findings.append({
                    "id": "ENGINE-001",
                    "severity": "info",
                    "title": f"Scanner module skipped: {scanner.__class__.__name__}",
                    "description": str(exc),
                    "evidence": "",
                    "remediation": "Review the target format and scanner logs."
                })

            progress(end, message + " complete")

        progress(90, "Calculating risk")
        self.findings = RiskEngine.normalize(self.findings)

        summary = RiskEngine.summary(self.findings)
        score = RiskEngine.score(self.findings)

        progress(100, "Scan complete")

        return {
            "schema_version": "1.0",
            "scanner": "APEX GUARD",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": str(self.target),
            "target_type": kind,
            "summary": summary,
            "risk_score": score,
            "findings": self.findings,
        }


"""
APEX GUARD - Part 1
Authorized application security auditing GUI.
Only analyze applications/projects you own or have permission to test.
"""

import sys
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTextEdit, QProgressBar,
    QMessageBox, QGroupBox
)
from PySide6.QtCore import Qt, QThread, Signal



class ScanWorker(QThread):
    progress = Signal(int, str)
    finished_scan = Signal(dict)
    failed = Signal(str)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):
        try:
            engine = SecurityEngine(self.target)
            result = engine.scan(
                progress_callback=lambda p, m: self.progress.emit(p, m)
            )
            self.finished_scan.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.target = None
        self.result = None
        self.worker = None

        self.setWindowTitle("APEX GUARD - Security Auditor")
        self.resize(1050, 700)
        self.build_ui()

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        title = QLabel("🛡 APEX GUARD")
        title.setStyleSheet("font-size: 28px; font-weight: bold;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Authorized static security auditing for APK, EXE and source projects"
        )
        layout.addWidget(subtitle)

        target_box = QGroupBox("Target")
        target_layout = QHBoxLayout(target_box)

        self.target_label = QLabel("No target selected")
        self.select_button = QPushButton("Select Target")
        self.select_button.clicked.connect(self.select_target)

        target_layout.addWidget(self.target_label, 1)
        target_layout.addWidget(self.select_button)
        layout.addWidget(target_box)

        self.scan_button = QPushButton("START SECURITY SCAN")
        self.scan_button.setMinimumHeight(50)
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setEnabled(False)
        layout.addWidget(self.scan_button)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        layout.addWidget(self.progress)

        self.status = QLabel("Ready")
        layout.addWidget(self.status)

        results_box = QGroupBox("Results")
        results_layout = QVBoxLayout(results_box)

        self.results = QTextEdit()
        self.results.setReadOnly(True)
        results_layout.addWidget(self.results)

        buttons = QHBoxLayout()
        self.report_button = QPushButton("Export HTML Report")
        self.report_button.clicked.connect(self.export_report)
        self.report_button.setEnabled(False)

        self.json_button = QPushButton("Export JSON")
        self.json_button.clicked.connect(self.export_json)
        self.json_button.setEnabled(False)

        buttons.addWidget(self.report_button)
        buttons.addWidget(self.json_button)
        results_layout.addLayout(buttons)

        layout.addWidget(results_box, 1)

    def select_target(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Application or Project File",
            "",
            "All Supported (*);;APK (*.apk);;EXE (*.exe);;Python (*.py)"
        )

        if not path:
            directory = QFileDialog.getExistingDirectory(
                self, "Or select a project directory"
            )
            path = directory

        if path:
            self.target = Path(path)
            self.target_label.setText(str(self.target))
            self.scan_button.setEnabled(True)
            self.status.setText("Target selected")

    def start_scan(self):
        if not self.target:
            return

        self.scan_button.setEnabled(False)
        self.select_button.setEnabled(False)
        self.report_button.setEnabled(False)
        self.json_button.setEnabled(False)
        self.results.clear()
        self.progress.setValue(0)

        self.worker = ScanWorker(self.target)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished_scan.connect(self.scan_finished)
        self.worker.failed.connect(self.scan_failed)
        self.worker.start()

    def update_progress(self, value, message):
        self.progress.setValue(value)
        self.status.setText(message)

    def scan_finished(self, result):
        self.result = result
        self.scan_button.setEnabled(True)
        self.select_button.setEnabled(True)
        self.report_button.setEnabled(True)
        self.json_button.setEnabled(True)
        self.status.setText("Scan complete")

        summary = result.get("summary", {})
        text = [
            f"Target: {result.get('target')}",
            f"Type: {result.get('target_type')}",
            "",
            "RISK SUMMARY",
            f"Critical: {summary.get('critical', 0)}",
            f"High:     {summary.get('high', 0)}",
            f"Medium:   {summary.get('medium', 0)}",
            f"Low:      {summary.get('low', 0)}",
            f"Info:     {summary.get('info', 0)}",
            "",
            "FINDINGS",
        ]

        for item in result.get("findings", []):
            text.append(
                f"[{item['severity'].upper()}] {item['title']}\n"
                f"  {item['description']}\n"
                f"  Evidence: {item.get('evidence', 'N/A')}\n"
                f"  Fix: {item.get('remediation', 'N/A')}\n"
            )

        self.results.setPlainText("\n".join(text))

    def scan_failed(self, message):
        self.scan_button.setEnabled(True)
        self.select_button.setEnabled(True)
        self.status.setText("Scan failed")
        QMessageBox.critical(self, "Scan Error", message)

    def export_report(self):
        if not self.result:
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report", "apex_guard_report.html", "HTML (*.html)"
        )
        if path:
            ReportGenerator.save_html(self.result, Path(path))
            self.status.setText(f"Report saved: {path}")

    def export_json(self):
        if not self.result:
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Report", "apex_guard_report.json", "JSON (*.json)"
        )
        if path:
            ReportGenerator.save_json(self.result, Path(path))
            self.status.setText(f"JSON saved: {path}")


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
