# 🛡️ keyguard-Keylogger Scanner  

### 🔍 Secure Your System from Hidden Keyloggers  

Keylogger Scanner is an advanced security tool designed to detect keyloggers hidden inside `.deb` package files before installation. It leverages **YARA rules** to scan extracted files, identify suspicious scripts, and ensure system security.  

---

## 🚀 Features  

✅ **Deep Analysis** – Extracts and scans `.deb` files for suspicious scripts  
✅ **YARA-Based Detection** – Uses custom YARA rules to find keyloggers  
✅ **Parallelized Scanning** – Optimized with multiprocessing for speed  
✅ **Rich CLI Interface** – Clean UI with progress bars and alerts  
✅ **Sandboxed Execution** – Option to scan inside Firejail for added security  
✅ **Detailed Scan Reports** – Saves structured logs for review  

---

## 📦 Installation  

Ensure the following dependencies are installed before running the scanner:  

```bash
sudo apt update
sudo apt install yara dpkg firejail python3-pip
pip install rich
```
## **Install Dependencies**  
Make sure you have Python 3 installed. Then, install the required dependencies:  
```bash
pip install -r requirements.txt
```
(Update `requirements.txt` with the necessary dependencies before running the above command.)

---

## 🛠 Usage  

Run the scanner using:  

```bash
sudo python3 keylogger_scanner.py
```

Then select one of the available options:  

1️⃣ Scan a `.deb` file  
2️⃣ View previous scan reports  
3️⃣ Exit  

---

## 📜 Example Scan  

```
[INFO] YARA rules loaded successfully.
Enter the path of the .deb file to scan: /home/user/malware.deb
[INFO] Scanning .deb file: /home/user/malware.deb
[ALERT] Keylogger detected in /home/user/malware.deb!
```

If no keylogger is detected:  

```
[SAFE] No keylogger detected.
```

---

## 🔬 How It Works  

1. **Extracts `.deb` package** – Using `dpkg-deb` for fast extraction  
2. **Identifies scripts** – Finds `.sh`, `.py`, `.conf`, and `.service` files  
3. **Scans using YARA** – Matches scripts against pre-defined keylogger rules  
4. **Displays results** – Alerts user about potential threats  
5. **Logs reports** – Saves details for future reference  

---

## ⚠️ Important Notes  

- Ensure **proper file permissions** to avoid errors when saving reports  
- To improve accuracy, update `keylogger_rule.yara` with the latest detection rules  
- **Use Firejail** for extra security:  
  ```bash
  firejail --noprofile python3 keylogger_scanner.py
  ```

---

## 📄 License  

This project is open-source under the **MIT License**. Contributions and improvements are welcome!  

---

## 🤝 Contributing  

Want to improve this project? Feel free to submit **pull requests** or **open issues**.  

---



