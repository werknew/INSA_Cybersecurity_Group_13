import os
import json

def generate_report(results, target, format='txt'):
    os.makedirs('reports', exist_ok=True)
    filename = f"reports/{target.replace('.', '_')}_report.{format}"

    if format == 'txt':
        with open(filename, 'w') as f:
            for key, value in results.items():
                f.write(f"=== {key.upper()} RESULTS ===\n")
                f.write(str(value) + "\n\n")
    elif format == 'json':
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
    elif format == 'html':
        with open(filename, 'w') as f:
            f.write("<html><body><h1>Scan Report</h1>")
            for section, content in results.items():
                f.write(f"<h2>{section.upper()}</h2><pre>{str(content)}</pre>")
            f.write("</body></html>")
