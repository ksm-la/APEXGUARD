# APEXGUARD
## 🚀 How to Run

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/APEX-GUARD-PRO.git
cd APEX-GUARD-PRO
```

### 2. Install Python

Make sure Python 3.10 or newer is installed.

Check your Python version:

```bash
python --version
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

If you only need the GUI dependency:

```bash
pip install PySide6
```

### 4. Run APEX GUARD PRO

```bash
python APEX_GUARD_PRO.py
```

The graphical interface will open if PySide6 is installed.

### 5. Run from the command line

Scan a Python application:

```bash
python APEX_GUARD_PRO.py my_app.py
```

Generate a JSON report:

```bash
python APEX_GUARD_PRO.py my_app.py --json result.json
```

Generate an HTML report:

```bash
python APEX_GUARD_PRO.py my_app.py --html result.html
```

Generate both:

```bash
python APEX_GUARD_PRO.py my_app.py --json result.json --html result.html
```

### 6. URL auditing

For applications or test servers that you own or have explicit permission to test:

```bash
python APEX_GUARD_PRO.py --url https://your-test-server.example
```

### ⚠️ Authorized Use

APEX GUARD PRO is designed for defensive security auditing and authorized testing.

Only scan applications, files, systems, and servers that you own or have explicit permission to test.

Do not use this software to access, attack, disrupt, or test systems without authorization.
