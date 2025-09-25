import subprocess

def run_nikto_scan(target):
    try:
        result = subprocess.check_output(['nikto', '-host', target], text=True)
        return result
    except Exception as e:
        return f"Error running Nikto: {e}"
