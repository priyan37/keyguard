rule KeyloggerDetection
{
    meta:
        author = "Priyadharshan Vadivel"
        description = "Detects potential keyloggers in executable files and scripts"
        version = "2.0"
        date = "2025-03-24"
        category = "malware, keylogger"
    
    strings:
        // Common keylogger libraries in Python
        $python_keylog1 = "pynput.keyboard.Listener" nocase
        $python_keylog2 = "keyboard.record" nocase
        $python_keylog3 = "keyboard.on_press" nocase
        $python_keylog4 = "keyboard.hook" nocase
        $python_keylog5 = "ctypes.windll.user32.GetAsyncKeyState" nocase
        $python_keylog6 = "evdev.InputDevice" nocase
        $python_keylog7 = "Xlib.display.Display" nocase

        // Keylogging behavior patterns
        $keylog_pattern1 = "open(\"keystrokes.txt\", \"a\")" nocase
        $keylog_pattern2 = "write(keystrokes)" nocase
        $keylog_pattern3 = "logfile.write" nocase
        $keylog_pattern4 = "log_key" nocase
        $keylog_pattern5 = "keypress" nocase

        // Suspicious persistence methods
        $startup1 = "Startup\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $startup2 = "/etc/systemd/system/" nocase
        $startup3 = "crontab -l" nocase
        $startup4 = ".service" nocase

        // Network exfiltration methods
        $network1 = "requests.post(" nocase
        $network2 = "urllib.request.urlopen(" nocase
        $network3 = "socket.connect((" nocase
        $network4 = "ftp.storbinary" nocase

    condition:
        any of ($python_keylog*) or
        any of ($keylog_pattern*) or
        any of ($startup*) or
        any of ($network*)
}
