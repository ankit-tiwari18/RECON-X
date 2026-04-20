import nmap
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

console = Console()

def terminal_scan(target):
    console.print(Panel.fit("[bold green]RECON-X CLI[/bold green]", subtitle="v1.1"))
    nm = nmap.PortScanner(nmap_search_path=['/usr/local/bin/nmap', 'nmap', '/usr/bin/nmap', '/opt/homebrew/bin/nmap'])
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=100)
        nm.scan(target, arguments="-Pn -sV -F --script vulners")
        progress.update(task, advance=100)

    if not nm.all_hosts():
        console.print(f"[bold red][!] No response from {target}.[/bold red]")
        return

    for host in nm.all_hosts():
        table = Table(title=f"Scan Results: {host}")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="white")
        table.add_column("CVEs", style="red")

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                vulns = info.get('script', {}).get('vulners', 'Clean')
                table.add_row(f"{port}/{proto}", f"{info['name']} {info['version']}", vulns[:100] + "...")
        console.print(table)

if __name__ == "__main__":
    target = input("Target: ")
    if target: terminal_scan(target)