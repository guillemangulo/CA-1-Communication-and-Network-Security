import os
import requests
import urllib3
import json
import time
from flask import Flask, request, jsonify

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

OLLAMA_BASE = os.environ.get('OLLAMA_HOST', 'http://ollama:11434')
OLLAMA_URL = f"{OLLAMA_BASE.rstrip('/')}/api/generate"
WAZUH_API = os.environ.get('WAZUH_MANAGER', 'https://wazuh.manager:55000')
WAZUH_USER = os.environ.get('WAZUH_USER', 'wazuh-wui')
WAZUH_PASS = os.environ.get('WAZUH_PASS', 'MyS3cr37P450r.*-')

ACTION_MAP = {
    "linux": {
        "REMEDIATE": "custom-remediation0", 
        "LOCK_USER": "block-account0"
    },
    "windows": {
        "WIN_LOCK": "win-lock0",
        "WIN_DELETE": "win-delete0",
        "WIN_KILL": "win-kill0"
    }
}

# --- MEMORIA CACHÉ PARA DEDUPLICACIÓN (ANTI-SPAM) ---
RECENT_ALERTS = {}
DEDUPLICATION_WINDOW = 30 # Segundos de "enfriamiento"

def get_wazuh_token():
    auth_url = f"{WAZUH_API}/security/user/authenticate"
    response = requests.get(auth_url, auth=(WAZUH_USER, WAZUH_PASS), verify=False, timeout=10)
    response.raise_for_status()
    return response.json().get('data', {}).get('token')

@app.route('/alert', methods=['POST'])
def handle_alert():
    alert = request.json
    all_fields = alert.get('all_fields', {})
    
    agent_id = all_fields.get('agent', {}).get('id', 'Unknown')
    rule_id = all_fields.get('rule', {}).get('id', 'Unknown')
    description = all_fields.get('rule', {}).get('description', 'No description')
    
    # --- MOTOR DE DEDUPLICACIÓN ---
    current_time = time.time()
    alert_signature = f"{agent_id}_{rule_id}"
    
    if alert_signature in RECENT_ALERTS:
        time_elapsed = current_time - RECENT_ALERTS[alert_signature]
        if time_elapsed < DEDUPLICATION_WINDOW:
            print(f"DEBUG: Duplicate ignored. Rule {rule_id} from Agent {agent_id} triggered {time_elapsed:.1f}s ago.", flush=True)
            return jsonify({"status": "ignored", "reason": "deduplicated"}), 200
            
    RECENT_ALERTS[alert_signature] = current_time
    # ------------------------------
    
    agent_data = all_fields.get('agent', {})
    decoder_data = all_fields.get('decoder', {})
    is_windows = "win" in agent_data.get('os', {}).get('platform', '').lower() or "windows" in decoder_data.get('name', '').lower()
    os_type = "windows" if is_windows else "linux"
    
    print(f"\n--- ALERT RECEIVED: {description} (Agent: {agent_id}, OS: {os_type}) ---", flush=True)

    prompt = f"""[INST] Eres un clasificador estricto de seguridad. Tu única función es devolver UNA palabra exacta. Cero explicaciones.
    
    REGLAS LINUX:
    1. Si la alerta contiene 'sudoers', 'malicious_user' o 'T1548.003': devuelve LOCK_USER
    2. Si la alerta contiene 'cron', 'crontab', 'hidden_bash' o 'SUID': devuelve REMEDIATE
    
    REGLAS WINDOWS:
    3. Si la alerta contiene 'T1087.002' o 'Local administrators group': devuelve WIN_LOCK
    4. Si la alerta contiene 'T1003.002' o 'SAM registry hive': devuelve WIN_DELETE
    5. Si la alerta contiene 'T1059.001' o 'Obfuscated PowerShell': devuelve WIN_KILL
    
    Si no coincide con ninguna: devuelve IGNORE
    
    Alerta: '{description}'
    
    Respuesta: [/INST]"""
        
    try:
        payload = {
            "model": "llama3.2", 
            "prompt": prompt, 
            "stream": False, 
            "options": {"temperature": 0.0}
        }
        response = requests.post(OLLAMA_URL, json=payload, timeout=30)
        raw_ai_output = response.json().get('response', 'IGNORE').upper().strip()
        
        print(f"DEBUG: Raw AI Output: '{raw_ai_output}'", flush=True)

        tag = "IGNORE"
        if "LOCK_USER" in raw_ai_output:
            tag = "LOCK_USER"
        elif "REMEDIATE" in raw_ai_output:
            tag = "REMEDIATE"
        elif "WIN_LOCK" in raw_ai_output:
            tag = "WIN_LOCK"
        elif "WIN_DELETE" in raw_ai_output:
            tag = "WIN_DELETE"
        elif "WIN_KILL" in raw_ai_output:
            tag = "WIN_KILL"
                
        print(f"AI Decision: {tag}", flush=True)
    except Exception as e:
        print(f"Ollama Error: {e}", flush=True)
        tag = "IGNORE"

    if tag in ACTION_MAP[os_type]:
        command_to_run = ACTION_MAP[os_type][tag]
        execute_remediation(command_to_run, agent_id, alert)
    else:
        print(f"Action {tag} ignored or not mapped for {os_type}.", flush=True)
        
    return jsonify({"status": "processed"}), 200

def execute_remediation(cmd, agent_id, alert_payload):
    try:
        print(f"Triggering {cmd} on Agent {agent_id}...", flush=True)
        token = get_wazuh_token()
        ar_url = f"{WAZUH_API}/active-response?agents_list={agent_id}"
        headers = {"Authorization": f"Bearer {token}"}
        
        if cmd == "block-account0":
            if 'data' not in alert_payload:
                alert_payload['data'] = {}
            alert_payload['data']['dstuser'] = "malicious_user"
        
        payload = {
            "command": cmd,
            "custom": True,
            "alert": alert_payload
        }
        
        ar_response = requests.put(ar_url, headers=headers, json=payload, verify=False, timeout=15)
        
        if ar_response.ok:
            print(f"SUCCESS: Manager accepted the {cmd} request.", flush=True)
        else:
            print(f"Wazuh API Error: {ar_response.text}", flush=True)
            
    except Exception as e:
        print(f"Remediation Execution Failed: {e}", flush=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)