from flask import Flask, render_template, request
import nmap

app = Flask(__name__)

def run_nmap_scan(target):
    # x86 Homebrew and standard Linux paths prioritized
    nm = nmap.PortScanner(nmap_search_path=['/usr/local/bin/nmap', 'nmap', '/usr/bin/nmap'])
    
    # -Pn: Necessary for Mac host scanning (bypasses ping block)
    # -sV: Required for CVE detection
    # -T4: Aggressive timing for faster results
    nm.scan(target, arguments="-sV -F -Pn -T4 --script vulners")
    
    results = []
    for host in nm.all_hosts():
        host_data = {"ip": host, "ports": []}
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                info = nm[host][proto][port]
                # Extract CVE data or return 'Clean' if no vulnerabilities found
                vuln_data = info.get('script', {}).get('vulners', 'Clean')
                
                host_data["ports"].append({
                    "port": port,
                    "service": f"{info['name']} {info['version']}",
                    "vuln": vuln_data
                })
        results.append(host_data)
    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    scan_results = None
    if request.method == 'POST':
        target = request.form.get('target')
        if target:
            scan_results = run_nmap_scan(target)
    return render_template('index.html', results=scan_results)

if __name__ == '__main__':
    # Running on your preferred port 5002
    app.run(debug=True, port=5002)