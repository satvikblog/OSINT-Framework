import re
import mariadb
import sys
import requests
import dns.resolver
import whois
import mysql.connector
import threading
import time
import os
import subprocess
from flask import Flask, render_template, request, jsonify , redirect , url_for

app = Flask(__name__)
# Configure the MariaDB connection
def get_db_connection(database='Tooling_DB'):
    try:
        conn = mariadb.connect(
            user="flaskuser",
            password="Satvik1624@",  # Replace with your MariaDB password
            host="localhost",
            port=3306,
            database=database
        )
        return conn
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB: {e}")
        sys.exit(1)
def remove_ansi_codes(text):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# IP Geolocation API key (replace with your actual API key)
def get_ip_location(ip):
    try:
        # Use ip-api.com for IP geolocation data
        response = requests.get(f'http://ip-api.com/json/{ip}')
        return response.json()  # Returning the JSON response
    except Exception as e:
        print(f"Error fetching IP location: {e}")
        return {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/osint', methods=['GET', 'POST'])
def osint():
    if request.method == 'POST':
        target = request.form.get('target')

        # Perform DNS Lookup (A record)
        try:
            dns_info_a = dns.resolver.resolve(target, 'A')
            dns_result_a = [str(ip) for ip in dns_info_a]
        except Exception as e:
            dns_result_a = f"Error: {e}"

        # Perform DNS Lookup (MX record)
        try:
            dns_info_mx = dns.resolver.resolve(target, 'MX')
            dns_result_mx = [str(mx.exchange) for mx in dns_info_mx]
        except Exception as e:
            dns_result_mx = f"Error: {e}"

        # Perform DNS Lookup (NS record)
        try:
            dns_info_ns = dns.resolver.resolve(target, 'NS')
            dns_result_ns = [str(ns) for ns in dns_info_ns]
        except Exception as e:
            dns_result_ns = f"Error: {e}"

        # Perform DNS Lookup (TXT record)
        try:
            dns_info_txt = dns.resolver.resolve(target, 'TXT')
            dns_result_txt = [str(txt) for txt in dns_info_txt]
        except Exception as e:
            dns_result_txt = f"Error: {e}"

        # Perform WHOIS Lookup
        try:
            whois_info = whois.whois(target)
            whois_result = {
                "domain": whois_info.domain_name,
                "registrar": whois_info.registrar,
                "creation_date": whois_info.creation_date,
                "expiration_date": whois_info.expiration_date,
                "registrant_name": whois_info.name,
                "registrant_email": whois_info.emails,
            }
        except Exception as e:
            whois_result = f"Error: {e}"

        # Get IP Location info
        ip_location = get_ip_location(target)

        # Combine all results
        result = {
            "dns_info_a": dns_result_a,
            "dns_info_mx": dns_result_mx,
            "dns_info_ns": dns_result_ns,
            "dns_info_txt": dns_result_txt,
            "whois_info": whois_result,
            "ip_location": ip_location
        }

        return render_template('osint_results.html', result=result)

    # If method is GET, display the HTML form
    return render_template('osint.html')
@app.route('/passive_recon', methods=['GET', 'POST'])
def passive_recon():
    if request.method == 'POST':
        target = request.form.get('target')

        # Initialize results dictionary
        result = {
            "dns_info": {},
            "whois_info": {},
            "emails": [],
            "subdomains": []
        }

        # Perform DNS Lookup
        try:
            dns_info_a = dns.resolver.resolve(target, 'A')
            result["dns_info"]["A"] = [str(ip) for ip in dns_info_a]
        except Exception as e:
            result["dns_info"]["A"] = f"Error: {e}"

        # Perform WHOIS Lookup
        try:
            whois_info = whois.whois(target)
            result["whois_info"] = {
                "domain": whois_info.domain_name,
                "registrar": whois_info.registrar,
                "creation_date": whois_info.creation_date,
                "expiration_date": whois_info.expiration_date,
                "registrant_name": whois_info.name,
                "registrant_email": whois_info.emails,
            }
        except Exception as e:
            result["whois_info"] = f"Error: {e}"

        # Perform Email Harvesting using theHarvester via shell command
        try:
            harvester_command = ['theHarvester', '-d', target, '-b', 'all']
            harvester_result = subprocess.run(harvester_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Extract email addresses using regex
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', harvester_result.stdout)
            result["emails"] = emails if emails else ["No emails found"]
        except Exception as e:
            result["emails"] = [f"Error running theHarvester: {e}"]

        # Perform Subdomain Enumeration using Sublist3r
        try:
            subdomains = sublist3r.main(target, 40, None, None, True, True, None)
            result["subdomains"] = subdomains
        except Exception as e:
            result["subdomains"] = f"Error: {e}"

        # Store results in MariaDB
        conn = get_db_connection(database='recon_DB')  # Connect to the recon_DB database
        cur = conn.cursor()

        # Insert DNS info into the database
        try:
            cur.execute("INSERT INTO dns_info (target, a_records) VALUES (?, ?)",
                        (target, ','.join(result["dns_info"].get("A", []))))
        except mariadb.Error as e:
            print(f"Error inserting DNS info: {e}")

        # Insert WHOIS info into the database
        try:
            cur.execute("INSERT INTO whois_info (target, domain, registrar, creation_date, expiration_date, registrant_name, registrant_email) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (target, result["whois_info"].get("domain", ""),
                         result["whois_info"].get("registrar", ""),
                         result["whois_info"].get("creation_date", ""),
                         result["whois_info"].get("expiration_date", ""),
                         result["whois_info"].get("registrant_name", ""),
                         result["whois_info"].get("registrant_email", "")))
        except mariadb.Error as e:
            print(f"Error inserting WHOIS info: {e}")

        # Insert email info into the database
        try:
            for email in result["emails"]:
                cur.execute("INSERT INTO emails (target, email) VALUES (?, ?)", (target, email))
        except mariadb.Error as e:
            print(f"Error inserting emails: {e}")

        # Insert subdomain info into the database
        try:
            for subdomain in result["subdomains"]:
                cur.execute("INSERT INTO subdomains (target, subdomain) VALUES (?, ?)", (target, subdomain))
        except mariadb.Error as e:
            print(f"Error inserting subdomains: {e}")

        conn.commit()
        cur.close()
        conn.close()

        # Render result on a neat table with structured output
        return render_template('passive_recon_results.html', result=result)

    # If method is GET, display the HTML form
    return render_template('passive_recon.html')

@app.route('/data', methods=['POST'])
def receive_data():
    try:
        data = request.get_json()
        if not all(key in data for key in ["temperature", "humidity", "air_quality", "distance"]):
            return jsonify({"error": "Missing data fields"}), 400

        temperature = data["temperature"]
        humidity = data["humidity"]
        air_quality = data["air_quality"]
        distance = data["distance"]

        conn = get_db_connection(database='sensor_DB')
        cur = conn.cursor()

        try:
            cur.execute("INSERT INTO sensor_data (temperature, humidity, air_quality, distance) VALUES (?, ?, ?, ?)",
                        (temperature, humidity, air_quality, distance))
        except mariadb.Error as e:
            print(f"Error inserting sensor data: {e}")
            conn.rollback()
            return jsonify({"error": "Error inserting data"}), 500

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Data received successfully"}), 200
    except Exception as e:
        print(f"Error processing data: {e}")
        return jsonify({"error": "Error processing data"}), 500

@app.route('/live_data', methods=['GET'])
def live_data():
    try:
        conn = get_db_connection(database='sensor_DB')
        cur = conn.cursor()

        cur.execute("SELECT temperature, humidity, air_quality, distance FROM sensor_data ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()

        cur.close()
        conn.close()

        if row:
            data = {
                "temperature": row[0],
                "humidity": row[1],
                "air_quality": row[2],
                "distance": row[3]
            }
            return jsonify(data)
        else:
            return jsonify({"error": "No data available"}), 404
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB: {e}")
        return jsonify({"error": "Error connecting to database"}), 500
    except Exception as e:
        print(f"Error processing data: {e}")
        return jsonify({"error": "Error processing data"}), 500

@app.route('/')
def index():
    # Read comments from the file
    comments = []
    if os.path.exists('comments.txt'):
        with open('comments.txt', 'r') as file:
            comments = file.readlines()
    
    return render_template('index.html', comments=comments)

# Route to handle comment submissions
@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    comment = request.form['comment']
    
    # Append the comment to a local file
    with open('comments.txt', 'a') as file:
        file.write(f'{comment}\n')
    
    # Commit and push the comment file to your Git repository
    subprocess.call(['git', 'add', 'comments.txt'])
    subprocess.call(['git', 'commit', '-m', 'Added new comment'])
    subprocess.call(['git', 'push'])
    
    return redirect('/')
@app.route('/sd_enum', methods=['GET', 'POST'])
def sd_enum():
    if request.method == 'POST':
        domain = request.form['domain']
        if domain:
            results = enumerate_subdomains(domain)
            save_results_to_db(domain, results)
            return render_template('sd_enum_results.html', domain=domain, results=results)
    return render_template('sd_enum.html')

def enumerate_subdomains(domain):
    try:
        # Run Sublist3r and save output to a temporary file
        result = subprocess.run(['sublist3r', '-d', domain, '-o', '/tmp/subdomains.txt'], capture_output=True, text=True)
        # Read the results from the file
        with open('/tmp/subdomains.txt', 'r') as file:
            subdomains = file.read().splitlines()
        return subdomains
    except Exception as e:
        print(f"Error: {e}")
        return []

def save_results_to_db(domain, results):
    try:
        conn = mysql.connector.connect(user='flaskuser', password='Satvik1624@', host='localhost', database='Tooling DB')
        cursor = conn.cursor()
        # Remove old results for the domain
        cursor.execute('DELETE FROM subdomain_results WHERE domain = %s', (domain,))
        # Insert new results
        for subdomain in results:
            cursor.execute('INSERT INTO subdomain_results (domain, subdomain) VALUES (%s, %s)', (domain, subdomain))
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")

@app.route('/nmap', methods=['GET', 'POST'])
def nmap_scan():
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        
        if not target_ip:
            return jsonify({'error': 'No target IP provided'}), 400

        scan_status = "Scan is in progress"
        # Run Nmap scan in shell and get the output
        try:
            cmd = f"sudo nmap -sS -p1-4000 -T4 {target_ip}"
            scan_output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Nmap scan failed', 'details': str(e)}), 500

        # Process scan output
        scan_results = process_scan_results(scan_output)

        # Store results in MariaDB
        store_scan_results(target_ip, scan_results)

        return render_template('nmap_results.html', results=scan_results, message="Scan is completed, Results are:")
    else:
        return render_template('nmap.html')

def process_scan_results(scan_output):
    results = []
    for line in scan_output.split('\n'):
        if 'open' in line:
            parts = line.split()
            port = parts[0].split('/')[0]  # Extract port number
            state = parts[-1]
            results.append({'port': port, 'state': state})
    return results

def store_scan_results(target_ip, results):
    # Connect to the database
    db = mysql.connector.connect(
        host="localhost",
        user="flaskuser",
        password="Satvik1624@",
        database="Tooling_DB"
    )
    cursor = db.cursor()

    # Create table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nmap_results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            target_ip VARCHAR(255),
            port INT,
            state VARCHAR(255)
        )
    ''')

    # Insert scan results
    for result in results:
        cursor.execute('''
            INSERT INTO nmap_results (target_ip, port, state)
            VALUES (%s, %s, %s)
        ''', (target_ip, result['port'], result['state']))

    db.commit()
    cursor.close()
    db.close()
@app.route('/dnsrecon', methods=['GET', 'POST'])
def dns_recon():
    if request.method == 'POST':
        domain = request.form.get('domain')
        
        if not domain:
            return jsonify({'error': 'No domain provided'}), 400

        # Perform DNS Recon
        recon_data = perform_dns_recon(domain)

        # Store in MariaDB
        store_dns_data(domain, recon_data)

        return render_template('dnsrecon_results.html', domain=domain, results=recon_data)
    else:
        return render_template('dnsrecon.html')


def perform_dns_recon(domain):
    dns_data = {'A': [], 'AAAA': [], 'MX': [], 'CNAME': [], 'TXT': []}
    
    # Fetch A records
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            dns_data['A'].append(str(rdata))
    except Exception:
        dns_data['A'].append('No A record found')

    # Fetch AAAA records
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        for rdata in answers:
            dns_data['AAAA'].append(str(rdata))
    except Exception:
        dns_data['AAAA'].append('No AAAA record found')

    # Fetch MX records
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            dns_data['MX'].append(f"{rdata.exchange} (Priority: {rdata.preference})")
    except Exception:
        dns_data['MX'].append('No MX record found')

    # Fetch CNAME records
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            dns_data['CNAME'].append(str(rdata.target))
    except Exception:
        dns_data['CNAME'].append('No CNAME record found')

    # Fetch TXT records
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            dns_data['TXT'].append(''.join(rdata.strings))
    except Exception:
        dns_data['TXT'].append('No TXT record found')

    return dns_data


def store_dns_data(domain, dns_data):
    # Connect to MariaDB
    db = mysql.connector.connect(
        host="localhost",
        user="flaskuser",
        password="Satvik1624@",
        database="Tooling_DB"
    )
    cursor = db.cursor()

    # Create table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_records (
            id INT AUTO_INCREMENT PRIMARY KEY,
            domain VARCHAR(255),
            record_type VARCHAR(10),
            record_value TEXT
        )
    ''')

    # Insert DNS records
    for record_type, records in dns_data.items():
        for record in records:
            cursor.execute('''
                INSERT INTO dns_records (domain, record_type, record_value)
                VALUES (%s, %s, %s)
            ''', (domain, record_type, record))

    db.commit()
    cursor.close()
    db.close()
# Firewall Detection Ro
def run_wafw00f(url):
    try:
        result = subprocess.run(['wafw00f', url], capture_output=True, text=True)
        output = result.stdout
        
        # Clean up unwanted characters and symbols
        cleaned_output = re.sub(r'\x1b\[[0-9;]*m', '', output)  # Remove ANSI escape sequences
        return cleaned_output
    except Exception as e:
        return str(e)
@app.route('/waf', methods=['GET', 'POST'])
def waf():
    if request.method == 'POST':
        url = request.form['url']
        if url:
            waf_result = run_wafw00f(url)
            return render_template('waf_results.html', waf_result=waf_result, url=url)
    return render_template('waf.html')

def run_and_store_whatweb(url):
    try:
        # Run WhatWeb command
        result = subprocess.run(['whatweb', '--color=never', url], capture_output=True, text=True)
        output = result.stdout

        # Clean up the output (remove unwanted symbols)
        cleaned_output = re.sub(r'\x1b\[[0-9;]*m', '', output)

        # Store the result in the database
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO whatweb_results (url, result) VALUES (?, ?)", (url, cleaned_output))
        connection.commit()
        cursor.close()
        connection.close()

        return cleaned_output
    except Exception as e:
        return str(e)

# Function to fetch WhatWeb results from the database
def fetch_whatweb_results(url):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT result FROM whatweb_results WHERE url=? ORDER BY scan_date DESC LIMIT 1", (url,))
    row = cursor.fetchone()
    cursor.close()
    connection.close()
    
    if row:
        return row[0]
    else:
        return None

@app.route('/wweb', methods=['GET', 'POST'])
def wweb():
    if request.method == 'POST':
        url = request.form['url']
        if url:
            # Check if results already exist in the database
            whatweb_result = fetch_whatweb_results(url)
            if not whatweb_result:
                # If no result, run WhatWeb and store the result
                whatweb_result = run_and_store_whatweb(url)
            
            return render_template('wweb_results.html', whatweb_result=whatweb_result, url=url)
    return render_template('wweb.html')

if __name__ == '__main__':
    app.run(debug=True)
