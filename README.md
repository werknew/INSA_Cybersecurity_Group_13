
# INSA_Cybersecurity_Group_13
this is the repository of Insa Cyber Talent Group 13


# 🔍 Automated Vulnerability Scanner Security Tool

## 📌 Project Overview

A comprehensive security scanning tool designed to perform both network and web application vulnerability assessments.
It combines a Flask backend for powerful scanning capabilities with a React frontend for better user experience.
The tool helps security researchers, system admins, and developers quickly identify weaknesses in their systems.

🚀 Features

🔧 Backend Capabilities

 Multiple Scan Types: Quick, Full, Stealth, Vulnerability, and Web scans

 Nmap Integration: Network discovery, port scanning, and service detection

 Nikto Integration: Web application vulnerability scanning

 CVE Database: Local vulnerability database with severity ratings for reference

RESTful API: Flask-based JSON API with robust error handling

🎨 Frontend Features

 Modern UI: Built with React and TypeScript for type safety and maintainability

 Responsive Design: Styled with Tailwind CSS, supporting dark/light mode

 Real-time Scanning: Interactive forms with live results while scans are running

 Visual Results: Collapsible sections with severity indicators for better readability

 Copy & Export: Copy/export scan results

🛠️ Technology Stack

Backend

 Python 3.8+ – Core programming language

 Flask – REST API framework

 Nmap – Network scanning engine

 Nikto – Web vulnerability scanner

 xmltodict – Parse XML outputs from scanning tools

Frontend

 React 18 – Frontend framework

 TypeScript – Type-safe development

 Tailwind CSS – Utility-first CSS framework for responsive UI

 Next.js (Optional) – For advanced React features like SSR and routing

 🧱 Project Structure

     Automated-Vulnerability-Scanner/
     │
     ├── BackEnd/
     │   ├── app.py               # Flask API entry point
     │   ├── scanner.py           # Main scanning engine (Nmap & Nikto)
     │   ├── requirements.txt     # Backend dependencies
     │   └── cve_database.json    # Local CVE database (optional)
     │
     ├── FrontEnd/
     │   ├── src/
     │   │   ├── components/      # Reusable UI components
     │   │   ├── pages/           # Page routes (Dashboard, Results, etc.)
     │   │   └── utils/           # API calls, formatters, etc.
     │   ├── package.json         # Frontend dependencies
     │   └── tailwind.config.js   # Styling configuration
     │
     └── README.md

🧩 Installation Guide

🔹 Clone the Repository

  git clone https://github.com/<your-username>/Automated-Vulnerability-Scanner.git
       cd Automated-Vulnerability-Scanner

🔹 Backend Setup (Flask API)

   cd BackEnd
      python3 -m venv venv
       source venv/bin/activate
       pip install -r requirements.txt
       python app.py

  🖥️ The backend will start at:
          http://127.0.0.1:5000 or http://<your-local-ip>:5000

  🔹 Frontend Setup:
        cd FrontEnd
        npm install
         npm start
   
🌐 Access via:
      http://localhost:3000

🧰 Usage
 
🖥️ Web Version

    1. Open the web interface in your browser.

    2. Enter a target (IP or domain).

    3. Choose a scan type (Quick, Full, Stealth, Vulnerability, Web).

    4. Click Start Scan — results will appear in real-time.

    5. Export or copy the results for reporting.

 💻 CLI Version

      Run scans directly from the terminal:

🧠 Future Enhancements

    1. Add SQLMap integration for SQL injection detection

    2. Include XSS & directory traversal detection

    3. Store results in a PostgreSQL database

    4. Implement user authentication and role-based dashboards

    5. Improve CVE correlation with Nmap & Nikto outputs

🧾 License

     This project is licensed under the MIT License — free to use and modify with attribution.



