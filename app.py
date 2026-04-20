from flask import Flask, render_template, request
import nmap

app = Flask(__name__)

def run_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sV -F --script vulners")
    results = []
    for host in nm.all_hosts():
        host_data = {"ip": host, "ports": []}
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                info = nm[host][proto][port]
                host_data["ports"].append({
                    "port": port,
                    "service": f"{info['name']} {info['version']}",
                    "vuln": info.get('script', {}).get('vulners', 'Clean')
                })
        results.append(host_data)
    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    scan_results = None
    if request.method == 'POST':
        target = request.form.get('target')
        scan_results = run_nmap_scan(target)
    return render_template('index.html', results=scan_results)

if __name__ == '__main__':
    app.run(debug=True, port=5002)