import subprocess
import yara
import sys
import os
from pathlib import Path
from multiprocessing import Pool, cpu_count
import tempfile
import shutil
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.prompt import Prompt

# Initialize Rich console
console = Console()

# Global scan report file
SCAN_REPORT_FILE = "scan_report.txt"

def display_banner():
    banner = """
██╗  ██╗███████╗██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
█████╔╝ █████╗   ╚████╔╝ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔═██╗ ██╔══╝    ╚██╔╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║  ██╗███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                                                                       
    Keylogger Scanner - v1.2 | Secure Your System
    
    Developed by: PRIYADHARSHAN VADIVEL
    """
    console.print(f"[bold blue]{banner}[/bold blue]")

def print_success(message):
    console.print(f"[bold green]{message}[/bold green]")

def print_warning(message):
    console.print(f"[bold yellow]{message}[/bold yellow]")

def print_error(message):
    console.print(f"[bold red]{message}[/bold red]")

def load_yara_rules():
    """ Load improved YARA rules for keylogger detection """
    yara_file = "keylogger_rule.yara"
    if not os.path.exists(yara_file):
        print_error(f"[ERROR] YARA rules file '{yara_file}' not found.")
        return None
    try:
        rules = yara.compile(filepath=yara_file)
        print_success("[INFO] YARA rules loaded successfully.")
        return rules
    except yara.SyntaxError as e:
        print_error(f"[ERROR] YARA syntax error: {e}")
    except yara.Error as e:
        print_error(f"[ERROR] YARA error: {e}")
    return None

def scan_with_yara(file_path, rules):
    """ Scan a file using YARA rules """
    try:
        matches = rules.match(file_path)
        return (file_path, bool(matches))
    except Exception as e:
        print_error(f"Error scanning {file_path}: {e}")
        return (file_path, False)

def extract_deb(file_path):
    """ Extract .deb file contents using dpkg-deb (faster than ar/tar) """
    temp_dir = tempfile.mkdtemp()
    try:
        subprocess.run(['dpkg-deb', '-x', file_path, temp_dir], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return temp_dir
    except Exception as e:
        print_error(f"Error extracting {file_path}: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None

def scan_deb(file_path, yara_rules):
    """ Scan extracted files for suspicious scripts """
    console.print(f"[bold cyan][INFO] Scanning .deb file: {file_path}[/bold cyan]")
    file_size = os.path.getsize(file_path) / (1024 * 1024)
    
    table = Table(title="Scan Details", show_header=True, header_style="bold blue")
    table.add_column("File", style="cyan")
    table.add_column("Size (MB)", style="magenta")
    table.add_column("Scan Date", style="yellow")
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    table.add_row(file_path, f"{file_size:.2f}", scan_date)
    console.print(table)

    temp_dir = extract_deb(file_path)
    if not temp_dir:
        return False
    
    suspicious_files = [
        os.path.join(root, file) for root, _, files in os.walk(temp_dir)
        for file in files if file.endswith((".sh", ".py", ".conf", ".service"))
    ]
    
    detected = False
    cpu_cores = min(cpu_count(), 4)  # Limit to 4 cores for safety

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn()) as progress:
        task = progress.add_task("[cyan]Scanning files...", total=len(suspicious_files))

        with Pool(processes=cpu_cores) as pool:
            results = pool.starmap(scan_with_yara, [(file, yara_rules) for file in suspicious_files])

        for file, match in results:
            progress.update(task, advance=1)
            if match:
                detected = True
                print_warning(f"[ALERT] Keylogger detected in {file}!")
                break

    scan_result = "[SAFE] No keylogger detected." if not detected else "[ALERT] Keylogger detected!"
    
    save_scan_report(file_path, file_size, scan_date, scan_result)
    
    print_success(scan_result)
    shutil.rmtree(temp_dir)
    return detected

def save_scan_report(file_path, file_size, scan_date, scan_result):
    """ Save scan report to a structured file """
    with open(SCAN_REPORT_FILE, "a") as report_file:
        report_file.write("=" * 50 + "\n")
        report_file.write(f"Scan Date: {scan_date}\n")
        report_file.write(f"Scanned File: {file_path}\n")
        report_file.write(f"File Size: {file_size:.2f} MB\n")
        report_file.write(f"Scan Result: {scan_result}\n")
        report_file.write("=" * 50 + "\n\n")
    print_success(f"[INFO] Scan report saved: {SCAN_REPORT_FILE}")

def scan_with_sandbox(file_path, yara_rules):
    """ Run scan inside Firejail for better security """
    console.print("[bold yellow][INFO] Running scan inside Firejail sandbox.[/bold yellow]")
    try:
        subprocess.run(["firejail", "--noprofile", "python3", "sandboxed_scan.py", file_path], check=True)
    except subprocess.CalledProcessError:
        print_error("[ERROR] Sandboxed scan failed!")

def main():
    display_banner()
    yara_rules = load_yara_rules()
    
    if not yara_rules:
        print_error("[ERROR] YARA rules could not be loaded. Exiting.")
        sys.exit(1)

    while True:
        console.print("\n[bold cyan]Select an option:[/bold cyan]")
        console.print("[1] Scan a .deb file")
        console.print("[2] View scan report")
        console.print("[3] Exit")

        choice = Prompt.ask("[bold yellow]Enter your choice[/bold yellow]", choices=["1", "2", "3"])
        
        if choice == "1":
            file_path = Prompt.ask("[bold green]Enter the path of the .deb file to scan[/bold green]")
            if os.path.exists(file_path) and file_path.endswith(".deb"):
                scan_deb(file_path, yara_rules)
            else:
                print_error("[ERROR] Invalid file format.")
        
        elif choice == "2":
            console.print(f"\n[bold cyan]Displaying scan reports:[/bold cyan]")
            with open(SCAN_REPORT_FILE, "r") as report:
                console.print(report.read())

        elif choice == "3":
            print_success("[INFO] Exiting. Stay safe!")
            sys.exit(0)

if __name__ == "__main__":
    main()
