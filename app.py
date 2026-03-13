import threading
import time
import os
import socket
from mitmproxy import http, ctx
from aes_utils import AESUtils
from proto_utils import ProtobufUtils
import LoginRes_pb2
import LoginResNew_pb2
import Login_pb2
import binascii
from mitmproxy.tools.main import mitmdump
import random
import json
from datetime import datetime
try:
    from proto_validator import (
        validate_protobuf_message, 
        safe_set_protobuf_field,
        check_proto_changes_on_startup,
        OPTIONAL_FIELDS
    )
    PROTO_VALIDATOR_AVAILABLE = True
except ImportError:
    PROTO_VALIDATOR_AVAILABLE = False
    ctx.log.warn("proto_validator nÃ£o disponÃ­vel - validaÃ§Ã£o desabilitada")

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UID_FILE = os.path.join(BASE_DIR, "uid.txt")
UID_API_URL = "https://user-log-ec5b2-default-rtdb.firebaseio.com/"  # Firebase Realtime Database base URL
UID_CHECK_API_URL = ""  # Optional status API (disabled when empty)
USE_API = True  # True = Firebase Realtime Database, False = uid.txt
CACHE_REFRESH_INTERVAL = 1
DB_SYNC_INTERVAL = 1
WHITELIST_MSG = "[ffffff] UID NOT AUTHORIZED\n\n[FFFFFF]UID: {uid} ."
WHITELIST_MSG_EXPIRED = "[ff0000] UID EXPIRADO\n\n[FFFFFF]Seu UID: {uid}\n[ff0000]Expirou em: {expired_at}\n\n[FFFFFF]Entre em contato com o suporte."
WHITELIST_MSG_BANNED = "[ff0000] UID BANIDO\n\n[FFFFFF]Seu UID: {uid}\n[ff0000]Banido atÃ©: {banned_until}\n\n[FFFFFF]Entre em contato com o suporte para mais informaÃ§Ãµes."
WHITELIST_MSG_PAUSED = "[ffff00] UID PAUSADO\n\n[FFFFFF]Seu UID: {uid}\n[ffff00]Pausado atÃ©: {paused_until}\n\n[FFFFFF]Sua conta foi temporariamente pausada."
WHITELIST_MSG_MAINTENANCE = "[00ffff] UID EM MANUTENCAO\n\n[FFFFFF]Seu UID: {uid}\n[00ffff]ManutenÃ§Ã£o atÃ©: {maintenance_until}\n\n[FFFFFF]Estamos realizando manutenÃ§Ãµes. Tente novamente mais tarde."


aes_utils = AESUtils()
proto_utils = ProtobufUtils()

uid_cache = set()
cache_lock = threading.Lock()
last_cache_refresh = 0
cache_initialized = False

def fetch_uids_from_api():
    """Busca UIDs do Firebase Realtime Database via HTTP REST"""
    global uid_cache, last_cache_refresh, cache_initialized
    try:
        import urllib.request
        import urllib.error
        import json

        base_url = UID_API_URL.rstrip("/")
        firebase_auth = os.getenv("FIREBASE_DB_AUTH", "").strip()
        firebase_url = f"{base_url}/uids.json"
        if firebase_auth:
            firebase_url = f"{firebase_url}?auth={firebase_auth}"

        ctx.log.debug(f"Loading UIDs from Firebase: {base_url}/uids")
        req = urllib.request.Request(firebase_url)

        with urllib.request.urlopen(req, timeout=5) as response:
            raw_data = response.read().decode("utf-8").strip()

        new_uid_cache = set()
        if raw_data:
            payload = json.loads(raw_data)
            if isinstance(payload, dict):
                for uid in payload.keys():
                    uid_str = str(uid).strip()
                    if uid_str and uid_str.isdigit():
                        new_uid_cache.add(uid_str)

        if not new_uid_cache:
            ctx.log.debug("No UIDs found in Firebase")

        with cache_lock:
            uid_cache.clear()
            uid_cache.update(new_uid_cache)
            last_cache_refresh = time.time()
            cache_initialized = True

        ctx.log.info(f"Loaded {len(new_uid_cache)} UIDs from Firebase")
        return True
    except urllib.error.URLError as e:
        ctx.log.warn(f"Firebase request failed: {e} - falling back to file")
        return fetch_uids_from_file()
    except json.JSONDecodeError as e:
        ctx.log.error(f"Firebase JSON parse error: {e} - falling back to file")
        return fetch_uids_from_file()
    except Exception as e:
        ctx.log.error(f"Firebase loading error: {e} - falling back to file")
        return fetch_uids_from_file()

def fetch_uids_from_file():
    """Busca UIDs de arquivo local (fallback)"""
    global uid_cache, last_cache_refresh, cache_initialized
    try:
        ctx.log.debug(f"Loading from {UID_FILE}")
        new_uid_cache = set()
        if os.path.exists(UID_FILE):
            with open(UID_FILE, 'r') as file:
                for line in file:
                    uid = line.strip()
                    if uid and uid.isdigit():
                        new_uid_cache.add(uid)
        if not new_uid_cache:
            ctx.log.debug("No UIDs found")
        with cache_lock:
            uid_cache.clear()
            uid_cache.update(new_uid_cache)
            last_cache_refresh = time.time()
            cache_initialized = True
        ctx.log.info(f"Loaded {len(new_uid_cache)} UIDs from file")
        return True
    except Exception as e:
        ctx.log.error(f"File loading error: {e}")
        with cache_lock:
            cache_initialized = True
        return False

def fetch_uids():
    """FunÃ§Ã£o principal que escolhe entre API ou arquivo"""
    if USE_API:
        return fetch_uids_from_api()
    else:
        return fetch_uids_from_file()

def save_json_to_file(json_data, endpoint_name, host_name=""):
    """
    Salva JSON interceptado em arquivo .txt
    """
    try:
        # Criar pasta json_logs se nÃ£o existir
        logs_dir = "json_logs"
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)
        
        # Gerar nome do arquivo baseado no timestamp e endpoint
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]  # Milissegundos
        safe_endpoint = endpoint_name.replace("/", "_").replace("\\", "_").replace(":", "_").replace("?", "_")
        if len(safe_endpoint) > 100:  # Limitar tamanho do nome
            safe_endpoint = safe_endpoint[:100]
        
        filename = f"{logs_dir}/{timestamp}_{safe_endpoint}.txt"
        
        # Salvar JSON formatado
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Endpoint: {host_name}{endpoint_name}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n")
            f.write("=" * 60 + "\n\n")
            
            if isinstance(json_data, dict):
                f.write(json.dumps(json_data, indent=2, ensure_ascii=False))
            elif isinstance(json_data, str):
                # Se for string, tentar parsear para formatar
                try:
                    parsed = json.loads(json_data)
                    f.write(json.dumps(parsed, indent=2, ensure_ascii=False))
                except:
                    f.write(json_data)
            else:
                f.write(str(json_data))
            
            f.write("\n")
        
        ctx.log.info(f"  [ðŸ’¾] JSON salvo em: {filename}")
        return filename
    except Exception as e:
        ctx.log.debug(f"Erro ao salvar JSON: {e}")
        return None


def check_uid_status_via_api(uid: str) -> dict:
    """Verifica status detalhado do UID via API - PRIORIDADE 1"""
    try:
        import urllib.request
        import urllib.error
        import json
        
        url = f"{UID_CHECK_API_URL}?uid={uid}"
        req = urllib.request.Request(url)
        
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data
    except urllib.error.URLError as e:
        ctx.log.debug(f"API check failed: {e}")
        return None
    except Exception as e:
        ctx.log.debug(f"Error checking UID status: {e}")
        return None

def check_uid_exists(uid: str, client_ip: str = None) -> tuple[bool, bool, dict]:
    """
    Verifica se UID existe e retorna status detalhado
    PRIORIDADE: 1) API de verificaÃ§Ã£o detalhada (UID_CHECK_API_URL), 2) VerificaÃ§Ã£o normal (cache)
    Returns: (is_authorized, needs_message, status_info)
    """
    uid = str(uid).strip()

    if uid == "0":
        return True, False, None

    # PRIORIDADE 1: Verificar via API de status detalhado PRIMEIRO
    if USE_API and UID_CHECK_API_URL:
        try:
            status_info = check_uid_status_via_api(uid)
            if status_info is not None:
                is_authorized = status_info.get('authorized', False)
                status = status_info.get('status', 'unknown')
                
                if is_authorized:
                    ctx.log.info(f"âœ… API UID {uid} autorizado (status: {status})")
                    return True, False, None
                else:
                    ctx.log.warn(f"âŒ API UID {uid} nÃ£o autorizado (status: {status})")
                    return False, True, status_info
            else:
                # API nÃ£o retornou dados, continuar para verificaÃ§Ã£o normal
                ctx.log.debug(f"API check returned None for UID {uid}, using cache fallback")
        except Exception as api_error:
            # Erro na API, usar fallback
            ctx.log.debug(f"API check failed for UID {uid}: {api_error}, using cache fallback")
    
    # PRIORIDADE 2: Fallback para verificaÃ§Ã£o simples via cache
    with cache_lock:
        if not cache_initialized:
            ctx.log.warn(f"Cache not initialized, denying UID {uid} (strict whitelist)")
            return False, True, None

        needs_refresh = (not uid_cache or time.time() - last_cache_refresh > CACHE_REFRESH_INTERVAL)
        is_authorized = uid in uid_cache

    if needs_refresh and not USE_API:
        ctx.log.debug("Scheduling background cache refresh")
        threading.Thread(target=fetch_uids, daemon=True).start()

    # Fast path for local-file mode: if cache missed, force one sync reload before deny.
    # This avoids false negatives when uid.txt changed moments ago.
    if not is_authorized and not USE_API:
        try:
            if fetch_uids_from_file():
                with cache_lock:
                    is_authorized = uid in uid_cache
                if is_authorized:
                    ctx.log.info(f"âœ… CACHE UID {uid} (after forced reload)")
                    return True, False, None
        except Exception as reload_error:
            ctx.log.debug(f"Forced file reload failed for UID {uid}: {reload_error}")

    if not is_authorized:
        ctx.log.warn(f"UID {uid} not in cache, denying login")
        return False, True, None

    ctx.log.info(f"âœ… CACHE UID {uid}")
    return is_authorized, False, None

def get_local_ip():
    """ObtÃ©m o IP local da mÃ¡quina"""
    try:
        # Conecta a um servidor externo para descobrir o IP local
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            # Fallback: obtÃ©m o hostname e resolve
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            return ip
        except Exception:
            return "127.0.0.1"

def get_public_ip():
    """ObtÃ©m o IP pÃºblico da mÃ¡quina"""
    try:
        import urllib.request
        urls = [
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.me/ip"
        ]
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    ip = response.read().decode('utf-8').strip()
                    if ip:
                        return ip
            except:
                continue
        return None
    except Exception:
        return None

def is_port_available(port):
    """Verifica se a porta estÃ¡ disponÃ­vel"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((LISTEN_HOST, port))
            return True
    except OSError:
        return False

def find_available_port(start_port, max_attempts=10):
    """Encontra uma porta disponÃ­vel comeÃ§ando de start_port"""
    for i in range(max_attempts):
        port = start_port + i
        if is_port_available(port):
            return port
    return None

def get_client_ip(flow: http.HTTPFlow) -> str:
    try:
        if hasattr(flow, 'client_conn') and hasattr(flow.client_conn, 'address'):
            return flow.client_conn.address[0]
        return "unknown"
    except:
        return "unknown"

def list_all_protobuf_fields(message_obj) -> list:
    """
    Lista TODOS os campos disponÃ­veis em uma mensagem protobuf
    Ãštil para descobrir nomes reais dos campos
    """
    all_fields = []
    try:
        # Tentar usar DESCRIPTOR do protobuf para listar campos
        if hasattr(message_obj, 'DESCRIPTOR'):
            descriptor = message_obj.DESCRIPTOR
            if hasattr(descriptor, 'fields'):
                for field in descriptor.fields:
                    all_fields.append({
                        'name': field.name,
                        'number': field.number,
                        'type': str(field.type)
                    })
                return all_fields
        
        # Fallback: usar dir() e filtrar atributos (mÃ©todo menos preciso)
        for attr in dir(message_obj):
            if not attr.startswith('_') and not callable(getattr(message_obj, attr, None)):
                # Tentar obter nÃºmero do campo via protobuf (se possÃ­vel)
                try:
                    if hasattr(message_obj, 'DESCRIPTOR'):
                        descriptor = message_obj.DESCRIPTOR
                        if hasattr(descriptor, 'fields_by_name') and attr in descriptor.fields_by_name:
                            field = descriptor.fields_by_name[attr]
                            all_fields.append({
                                'name': attr,
                                'number': field.number,
                                'type': str(field.type)
                            })
                            continue
                except:
                    pass
                # Se nÃ£o conseguir, adiciona apenas o nome
                all_fields.append(attr)
    except Exception as e:
        ctx.log.debug(f"Erro ao listar campos: {e}")
    
    return all_fields

def verify_protobuf_field_numbers(message_obj, expected_fields: dict) -> dict:
    """
    Verifica em runtime se os campos com nÃºmeros especÃ­ficos ainda existem
    
    Args:
        message_obj: Objeto protobuf decodificado
        expected_fields: Dict {nome_campo: numero_esperado}
    
    Returns:
        Dict com resultados da verificaÃ§Ã£o
    """
    results = {
        'valid': True,
        'missing': [],
        'changed': [],
        'working': [],
        'total': len(expected_fields)
    }
    
    try:
        # Tentar acessar cada campo pelo nome
        for field_name, expected_number in expected_fields.items():
            if hasattr(message_obj, field_name):
                # Campo existe - tenta obter e verificar se Ã© acessÃ­vel
                try:
                    value = getattr(message_obj, field_name)
                    # Verifica se consegue setar tambÃ©m (teste completo)
                    try:
                        setattr(message_obj, field_name, value)  # Teste write
                        results['working'].append(f"{field_name} (#{expected_number})")
                    except Exception as e:
                        results['changed'].append(f"{field_name} (#{expected_number}): erro ao escrever - {e}")
                        results['valid'] = False
                except Exception as e:
                    results['changed'].append(f"{field_name} (#{expected_number}): erro ao ler - {e}")
                    results['valid'] = False
            else:
                # Campo nÃ£o encontrado - pode ter mudado
                results['missing'].append(f"{field_name} (#{expected_number})")
                results['valid'] = False
                
    except Exception as e:
        ctx.log.error(f"Erro na verificaÃ§Ã£o de campos: {e}")
        results['valid'] = False
    
    return results

def get_consistent_device_profile():
    """
    FIX #1 (RANKED): Expanded device profiles - PRIORITIZE MID-RANGE for ranked.
    Focus on extremely common devices in India/Brazil/Bangladesh to blend in.
    Each profile has matching Model + CPU + GPU + Android Version.
    
    NOTE: For ranked play, mid-range devices are MUCH safer than flagships.
    """
    # RANKED FIX #3: Prioritize mid-range devices (80% mid-range, 20% flagship)
    mid_range_profiles = [
        # MID-RANGE DEVICES (Most Common - SAFEST FOR RANKED)
        {
            # Redmi Note 12 - Very popular in India/Bangladesh
            "model": "Redmi Note 12",
            "cpu": "ARMv8 FP ASIMD AES | 2800 | 8",
            "gpu": "Adreno (TM) 610",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (5800, 8100),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2400,
            "dpi_range": (420, 480)
        },
        {
            # Redmi Note 13 - Newer version, very common
            "model": "Redmi Note 13",
            "cpu": "ARMv8 FP ASIMD AES | 2600 | 8",
            "gpu": "Mali-G57 MC2",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2400,
            "dpi_range": (395, 440)
        },
        {
            # Realme Narzo 50 - Popular budget device
            "model": "Realme RMX3286",
            "cpu": "ARMv8 FP ASIMD AES | 2050 | 8",
            "gpu": "Mali-G57 MC2",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 12 / API-31 (SP1A.210812.016)",
            "ram_range": (4000, 6000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2412,
            "dpi_range": (400, 440)
        },
        {
            # POCO M5 - Very common budget gaming phone
            "model": "POCO M5",
            "cpu": "ARMv8 FP ASIMD AES | 2000 | 8",
            "gpu": "Mali-G52 MC2",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 12 / API-31 (SP1A.210812.016)",
            "ram_range": (4000, 6000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2400,
            "dpi_range": (395, 440)
        },
        {
            # POCO X5 Pro - Popular gaming mid-range
            "model": "POCO X5 Pro 5G",
            "cpu": "ARMv8 FP ASIMD AES | 2400 | 8",
            "gpu": "Adreno (TM) 642L",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2400,
            "dpi_range": (420, 460)
        },
        {
            # Moto G84 - Popular in Brazil
            "model": "Motorola moto g84 5G",
            "cpu": "ARMv8 FP ASIMD AES | 2200 | 8",
            "gpu": "Adreno (TM) 619",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2400,
            "dpi_range": (400, 440)
        },
        {
            # Moto G73 - Common in Brazil/India
            "model": "Motorola moto g73 5G",
            "cpu": "ARMv8 FP ASIMD AES | 2200 | 8",
            "gpu": "Mali-G57 MC2",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2400,
            "dpi_range": (395, 440)
        },
        {
            # Samsung Galaxy A34 - Very popular mid-range
            "model": "Samsung SM-A346B",
            "cpu": "ARMv8 FP ASIMD AES | 2600 | 8",
            "gpu": "Mali-G68 MP4",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2340,
            "dpi_range": (411, 450)
        },
        {
            # Samsung Galaxy A54 - Very popular mid-range
            "model": "Samsung SM-A546B",
            "cpu": "ARMv8 FP ASIMD AES | 2400 | 8",
            "gpu": "Mali-G68 MP4",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2340,
            "dpi_range": (420, 450)
        },
        {
            # Redmi Note 11 Pro - Extremely common
            "model": "Redmi Note 11 Pro",
            "cpu": "ARMv8 FP ASIMD AES | 2050 | 8",
            "gpu": "Mali-G57 MC2",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 12 / API-31 (SP1A.210812.016)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2400,
            "dpi_range": (395, 440)
        },
        {
            # Realme 10 Pro - Popular in Southeast Asia
            "model": "Realme RMX3663",
            "cpu": "ARMv8 FP ASIMD AES | 2200 | 8",
            "gpu": "Adreno (TM) 619",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2412,
            "dpi_range": (400, 450)
        },
        {
            # Vivo Y75 - Popular in India
            "model": "vivo V2202",
            "cpu": "ARMv8 FP ASIMD AES | 2000 | 8",
            "gpu": "Mali-G57 MC2",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 12 / API-31 (SP1A.210812.016)",
            "ram_range": (4000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2408,
            "dpi_range": (400, 440)
        },
        {
            # Vivo Y56 - Common budget device
            "model": "vivo V2231",
            "cpu": "ARMv8 FP ASIMD AES | 2200 | 8",
            "gpu": "Mali-G57 MC2",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2408,
            "dpi_range": (395, 440)
        },
        {
            # OPPO A78 - Common budget device
            "model": "OPPO CPH2565",
            "cpu": "ARMv8 FP ASIMD AES | 2200 | 8",
            "gpu": "Mali-G57 MC2",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2400,
            "dpi_range": (400, 440)
        },
        {
            # Samsung Galaxy M34 - Popular in India
            "model": "Samsung SM-M346B",
            "cpu": "ARMv8 FP ASIMD AES | 2200 | 8",
            "gpu": "Mali-G68 MP4",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.1"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (6000, 8000),
            "arch": "64",
            "screen_width": 1080,
            "screen_height": 2340,
            "dpi_range": (411, 450)
        }
    ]
    
    flagship_profiles = [
        # FLAGSHIP DEVICES (Use sparingly - heavily watched in ranked)
        {
            # Samsung Galaxy S23 Ultra - Snapdragon 8 Gen 2
            "model": "Samsung SM-S918B",
            "cpu": "ARMv8 FP ASIMD AES | 3360 | 8",
            "gpu": "Adreno (TM) 740",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.3"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (8000, 12000),
            "arch": "64",
            "screen_width": 1440,
            "screen_height": 3088,
            "dpi_range": (450, 500)
        },
        {
            # OnePlus 11 - Snapdragon 8 Gen 2
            "model": "OnePlus CPH2613",
            "cpu": "ARMv8 FP ASIMD AES | 3200 | 8",
            "gpu": "Adreno (TM) 740",
            "gl_version": random.choice(["OpenGL ES 3.2", "Vulkan 1.3"]),
            "android_ver": "Android OS 13 / API-33 (TQ3A.230805.001)",
            "ram_range": (8000, 16000),
            "arch": "64",
            "screen_width": 1440,
            "screen_height": 3216,
            "dpi_range": (450, 510)
        }
    ]
    
    # RANKED FIX #3: 80% mid-range, 20% flagship
    if random.random() < 0.8:
        selected = random.choice(mid_range_profiles)
    else:
        selected = random.choice(flagship_profiles)
    
    # Add minor randomization to avoid exact fingerprint matching
    selected["dpi"] = str(random.randint(selected["dpi_range"][0], selected["dpi_range"][1]))
    # RANKED FIX #2: Higher loading times for mid-range devices (more realistic)
    selected["loading_time_ms"] = random.randint(1500, 4500)
    
    return selected

def get_session_profile(flow: http.HTTPFlow):
    """
    RANKED FIX #1: Get or create a session-consistent device profile.
    The SAME profile is used for ALL packets in one session (login â†’ matchmaking â†’ in-game).
    This prevents inconsistencies that trigger ranked detection.
    """
    # Check if profile already exists for this flow/session
    if not hasattr(flow, 'spoofed_profile') or flow.spoofed_profile is None:
        # Create new profile for this session
        flow.spoofed_profile = get_consistent_device_profile()
        ctx.log.info(f"[RANKED FIX #1] Locked profile for session: {flow.spoofed_profile['model']}")
    
    return flow.spoofed_profile

def spoof_field_94_device_data(device_data_str, spoofed_model):
    """
    FIX #2: Improved Field 94 (deviceData) handling with better fallback.
    Handles JSON, encrypted, or plain string formats.
    """
    if not device_data_str:
        return device_data_str
    
    try:
        # Try to parse as JSON first
        import json
        try:
            device_data = json.loads(device_data_str)
            
            # Replace hardware identifiers to match spoofed model
            if isinstance(device_data, dict):
                # Common fields that leak real hardware
                if 'model' in device_data:
                    device_data['model'] = spoofed_model
                if 'device' in device_data:
                    device_data['device'] = spoofed_model
                if 'product' in device_data:
                    device_data['product'] = spoofed_model.split()[0]  # Brand name
                if 'manufacturer' in device_data:
                    device_data['manufacturer'] = spoofed_model.split()[0]
                if 'brand' in device_data:
                    device_data['brand'] = spoofed_model.split()[0]
                if 'hardware' in device_data:
                    # Randomize hardware ID
                    device_data['hardware'] = f"qcom_{random.randint(1000, 9999)}"
                if 'board' in device_data:
                    device_data['board'] = f"board_{random.randint(1000, 9999)}"
                if 'serial' in device_data:
                    # Randomize serial number
                    device_data['serial'] = binascii.hexlify(os.urandom(8)).decode().upper()
                if 'androidId' in device_data or 'android_id' in device_data:
                    key = 'androidId' if 'androidId' in device_data else 'android_id'
                    device_data[key] = binascii.hexlify(os.urandom(8)).decode()
                
                ctx.log.info(f"  [FIX #2] Field 94 JSON parsed and spoofed")
                return json.dumps(device_data, ensure_ascii=False)
            
        except json.JSONDecodeError:
            # Not JSON, might be encrypted or plain string
            ctx.log.debug("  [FIX #2] Field 94 is not JSON, trying other methods")
            
            # If it looks like a device model string, replace it
            if any(brand in device_data_str for brand in ['Samsung', 'Xiaomi', 'OnePlus', 'Google', 'ASUS', 'Redmi', 'POCO', 'Realme', 'Moto', 'Vivo', 'OPPO']):
                ctx.log.info(f"  [FIX #2] Field 94 contains device string, replacing with: {spoofed_model}")
                return spoofed_model
            
            # If it's encrypted/binary (contains non-printable chars), randomize bytes
            if any(ord(c) < 32 or ord(c) > 126 for c in device_data_str if c not in ['\n', '\r', '\t']):
                ctx.log.info(f"  [FIX #2] Field 94 appears encrypted ({len(device_data_str)} bytes), randomizing")
                # Keep same length but randomize content
                random_bytes = os.urandom(len(device_data_str))
                return random_bytes.decode('latin-1')  # Preserve byte length
            
            # Fallback: Clear the field entirely if we can't parse it
            ctx.log.warn("  [FIX #2] Field 94 format unknown, clearing field")
            return ""
    
    except Exception as e:
        ctx.log.debug(f"  [FIX #2] Error spoofing field 94: {e}, clearing field")
        return ""
    
    return device_data_str

def sanitize_reserved_fields(login_req):
    """
    FIX #3: Improved reserved fields (1-19, 60-88) sanitization.
    Randomize within realistic ranges instead of zeroing to avoid patterns.
    """
    reserved_fields = [
        'reserved1', 'reserved2', 'reserved3', 'reserved4', 'reserved5',
        'reserved6', 'reserved7', 'reserved8', 'reserved9', 'reserved10',
        'reserved11', 'reserved12', 'reserved13', 'reserved14', 'reserved15',
        'reserved16', 'reserved17', 'reserved18', 'reserved19'
    ]
    
    # Additional reserved int fields (60-88)
    reserved_int_fields = [f'reserved{i}' for i in range(60, 89) if hasattr(login_req, f'reserved{i}')]
    
    sanitized_count = 0
    for field_name in reserved_fields + reserved_int_fields:
        if hasattr(login_req, field_name):
            try:
                current_value = getattr(login_req, field_name)
                # If field has a value, randomize it
                if current_value:
                    # For int fields, randomize within realistic ranges
                    if isinstance(current_value, int):
                        # Use different ranges for different field types
                        if field_name in ['reserved1', 'reserved2', 'reserved3']:
                            setattr(login_req, field_name, random.randint(0, 10))
                        elif field_name in ['reserved60', 'reserved61', 'reserved64', 'reserved65', 'reserved66', 'reserved67']:
                            setattr(login_req, field_name, random.randint(40000, 110000))
                        else:
                            setattr(login_req, field_name, random.randint(0, 5000))
                        sanitized_count += 1
                    # For string fields, randomize or clear
                    elif isinstance(current_value, str):
                        if random.random() < 0.5:
                            setattr(login_req, field_name, "")
                        else:
                            setattr(login_req, field_name, binascii.hexlify(os.urandom(4)).decode())
                        sanitized_count += 1
                    # For bytes fields, randomize
                    elif isinstance(current_value, bytes):
                        if random.random() < 0.5:
                            setattr(login_req, field_name, b"")
                        else:
                            setattr(login_req, field_name, os.urandom(len(current_value)))
                        sanitized_count += 1
            except Exception as e:
                ctx.log.debug(f"Error sanitizing {field_name}: {e}")
    
    if sanitized_count > 0:
        ctx.log.info(f"  [FIX #3] Randomized {sanitized_count} reserved fields")
    
    return sanitized_count

def handle_field_102_checksum(login_req):
    """
    FIX #4: Improved Field 102 (reserved20) handling.
    Randomize 70% of the time, clear 30% to avoid detection patterns.
    """
    if hasattr(login_req, 'reserved20'):
        try:
            current_value = getattr(login_req, 'reserved20')
            if current_value:
                # Strategy: Randomize most of the time, clear sometimes
                if random.random() < 0.7:
                    # Randomize with same length (appears as valid checksum)
                    random_bytes = os.urandom(len(current_value) if isinstance(current_value, bytes) else 32)
                    setattr(login_req, 'reserved20', random_bytes)
                    ctx.log.info(f"  [FIX #4] Randomized Field 102 (reserved20): {len(random_bytes)} bytes")
                else:
                    # Clear it (no checksum provided)
                    setattr(login_req, 'reserved20', b'')
                    ctx.log.info("  [FIX #4] Cleared Field 102 (reserved20)")
                
                return True
        except Exception as e:
            ctx.log.debug(f"Error handling field 102: {e}")
    
    return False

def get_spoofed_device_info(flow: http.HTTPFlow = None):
    """
    Updated to use session-consistent profiles with ranked-specific improvements.
    RANKED FIX #1: Uses flow.spoofed_profile for consistency across session.
    RANKED FIX #2: Adds ranked-specific fields with realistic values.
    """
    # RANKED FIX #1: Get session-consistent profile
    if flow is not None:
        profile = get_session_profile(flow)
    else:
        # Fallback if no flow provided
        profile = get_consistent_device_profile()
    
    carriers = ["Ncell", "Verizon", "AT&T", "T-Mobile", "Vodafone", "Jio", "Airtel", "Vi"]
    
    # RANKED FIX #2: Spoof location to major ranked cities (more realistic)
    ranked_cities = ["Delhi", "SÃ£o Paulo", "Dhaka", "Jakarta", "Manila", "Mumbai", "Kolkata", "Rio de Janeiro"]
    ranked_subdivisions = ["Delhi", "SÃ£o Paulo", "Dhaka", "Jakarta", "Metro Manila", "Maharashtra", "West Bengal", "Rio de Janeiro"]
    
    # Generate RAM within the profile's range
    total_ram = random.randint(profile["ram_range"][0], profile["ram_range"][1])
    
    return {
        'game_name': "free fire",
        'some_flag': 1,
        'os_info': profile["android_ver"],
        'device_type': "Handheld",
        'carrier': random.choice(carriers),
        'connection': "WIFI",
        'screen_width': profile["screen_width"],
        'screen_height': profile["screen_height"],
        'dpi': profile["dpi"],
        'cpu_info': profile["cpu"],
        'total_ram': total_ram,
        'gpu': profile["gpu"],
        'gpu_version': profile["gl_version"],
        'google_account': f"Google|{binascii.hexlify(os.urandom(16)).decode()}",
        'language': "en",
        'device_category': "Handheld",
        'device_model': profile["model"],
        'unknown30': 1,
        'carrier2': random.choice(carriers),
        'connection2': "WIFI",
        'session_id': binascii.hexlify(os.urandom(16)).decode(),
        'val60': random.randint(90000, 110000),
        'val61': random.randint(40000, 60000),
        'val62': random.randint(500, 1000),
        'val64': random.randint(40000, 60000),
        'val65': random.randint(90000, 110000),
        'val66': random.randint(40000, 60000),
        'val67': random.randint(90000, 110000),
        'val73': random.randint(1, 5),
        'lib_path': "/data/app/com.dts.freefireth-1/lib/arm/",
        'val76': 1,
        'apk_signature': "2087f61c19f57f2af4e7feff0b24d9d9|/data/app/~~jHEWM3xbT9VVYUy8eZmOiA==/com.dts.freefireth-B_KiZCdyGM6n3eXaOUmALA==/base.apk",
        'val78': 3,
        'val79': 2,
        'arch': profile["arch"],
        'version_code': "2019119621",
        'gfx_renderer': "OpenGLES2",
        'max_texture_size': 16383,
        'cores': 4,
        'unknown92': 2950,
        'platform': "android",
        'signature': "KqsHTxnXXUCG8sxXFVB2j0AUs3+0cvY/WgLeTdfTE/KPENeJPpny2EPnJDs8C8cBVMcd1ApAoCmM9MhzDDXabISdK31SKSFSr06eVCZ4D2Yj/C7G",
        'total_storage': 111117,
        'refresh_rate_json': '{"cur_rate":[60,90,120]}',
        'loading_time_ms': profile["loading_time_ms"],
        # RANKED FIX #2: Add ranked-specific location fields
        'ip_city': random.choice(ranked_cities),
        'ip_subdivision': random.choice(ranked_subdivisions),
        # RANKED FIX #2: Add release channel (Google Play is most common)
        'release_channel': random.choice(["Google Play", ""]),
        'unknown97': 1,
        'unknown98': 1,
        'raw_bytes': b"\x13RFC\x07\x0e\\Q1"
    }

def get_spoofed_device_for_logevent(flow: http.HTTPFlow = None):
    """
    Retorna valores spoofados para usar em LogEvents (JSON).
    RANKED FIX #1: Uses session-consistent profile.
    """
    # RANKED FIX #1: Get session-consistent profile
    if flow is not None:
        profile = get_session_profile(flow)
    else:
        # Fallback if no flow provided
        profile = get_consistent_device_profile()
    
    return {
        'system_software': profile["android_ver"],
        'cpu_hardware': profile["cpu"],
        'gl_render': profile["gpu"],
        'gl_version': profile["gl_version"],
        'device_model': profile["model"],
        'screen_width': profile["screen_width"],
        'screen_hight': profile["screen_height"],  # Nota: o jogo usa "hight" em vez de "height" (typo)
        'memory': random.randint(profile["ram_range"][0], profile["ram_range"][1]),
        'dpi': profile["dpi"],
    }

def spoof_logevent_json(json_data, flow: http.HTTPFlow = None):
    """
    Modifica campos do dispositivo em LogEvents JSON para usar valores spoofados.
    RANKED FIX #1: Uses session-consistent profile via flow parameter.
    """
    try:
        import json
        
        # Se tem event_payload (string JSON dentro de JSON)
        if 'event_payload' in json_data and isinstance(json_data['event_payload'], str):
            try:
                # Parsear o event_payload (Ã© uma string JSON)
                payload = json.loads(json_data['event_payload'])
                
                # Obter valores spoofados (session-consistent)
                spoofed = get_spoofed_device_for_logevent(flow)
                
                # Modificar campos do dispositivo se existirem
                if 'cpu_hardware' in payload:
                    payload['cpu_hardware'] = spoofed['cpu_hardware']
                if 'gl_render' in payload:
                    payload['gl_render'] = spoofed['gl_render']
                if 'gl_version' in payload:
                    payload['gl_version'] = spoofed['gl_version']
                if 'device_model' in payload:
                    payload['device_model'] = spoofed['device_model']
                if 'system_software' in payload:
                    payload['system_software'] = spoofed['system_software']
                if 'system_hardware' in payload:
                    payload['system_hardware'] = 'Handheld'
                if 'screen_width' in payload:
                    payload['screen_width'] = spoofed['screen_width']
                if 'screen_hight' in payload:
                    payload['screen_hight'] = spoofed['screen_hight']
                if 'screen_height' in payload:  # Caso tenha o nome correto tambÃ©m
                    payload['screen_height'] = spoofed['screen_hight']
                if 'memory' in payload:
                    payload['memory'] = spoofed['memory']
                if 'dpi' in payload:
                    payload['dpi'] = spoofed['dpi']
                
                # Re-serializar o event_payload
                json_data['event_payload'] = json.dumps(payload, ensure_ascii=False)
                
                return True
            except Exception as e:
                ctx.log.debug(f"Erro ao modificar event_payload: {e}")
                return False
        
        # Se os campos estÃ£o diretamente no JSON (nÃ£o em event_payload)
        spoofed = get_spoofed_device_for_logevent()
        modified = False
        
        if 'cpu_hardware' in json_data:
            json_data['cpu_hardware'] = spoofed['cpu_hardware']
            modified = True
        if 'gl_render' in json_data:
            json_data['gl_render'] = spoofed['gl_render']
            modified = True
        if 'gl_version' in json_data:
            json_data['gl_version'] = spoofed['gl_version']
            modified = True
        if 'device_model' in json_data:
            json_data['device_model'] = spoofed['device_model']
            modified = True
        
        return modified
        
    except Exception as e:
        ctx.log.debug(f"Erro ao spoofar LogEvent JSON: {e}")
        return False

def block_android_detection_event(json_data):
    """
    FIX #5: Detects EventTypeAndroidApplicationDetection and MODIFIES it instead of blocking.
    Instead of blocking the packet (which is suspicious), we clear the detected apps list
    so the server receives a "Clean" report.
    
    Retorna:
        - json_data modificado: Com lista de apps detectados limpa
        - json_data original: Se nÃ£o hÃ¡ eventos desse tipo
    """
    try:
        import json
        
        # Verificar se Ã© um dicionÃ¡rio
        if isinstance(json_data, dict):
            event_type = json_data.get('event_type') or json_data.get('eventType') or json_data.get('EventType')
            
            # Verificar pelo nome do evento
            if event_type == 'EventTypeAndroidApplicationDetection' or 'AndroidApplicationDetection' in str(event_type):
                ctx.log.warn("  [FIX #5] EventTypeAndroidApplicationDetection detectado - LIMPANDO lista de apps!")
                ctx.log.warn(f"     Evento: {event_type}")
                
                # Limpar a lista de apps detectados ao invÃ©s de bloquear
                if 'event_payload' in json_data or 'eventPayload' in json_data:
                    payload_key = 'event_payload' if 'event_payload' in json_data else 'eventPayload'
                    payload = json_data[payload_key]
                    
                    # Se payload Ã© string JSON, parsear
                    if isinstance(payload, str):
                        try:
                            payload_dict = json.loads(payload)
                            # Limpar campo 'detection' ou 'Detection' (enviar lista vazia)
                            if 'detection' in payload_dict:
                                payload_dict['detection'] = []
                                ctx.log.info("     Cleared 'detection' field (sent empty list)")
                            if 'Detection' in payload_dict:
                                payload_dict['Detection'] = []
                                ctx.log.info("     Cleared 'Detection' field (sent empty list)")
                            if 'detected_apps' in payload_dict:
                                payload_dict['detected_apps'] = []
                                ctx.log.info("     Cleared 'detected_apps' field (sent empty list)")
                            if 'detectedApps' in payload_dict:
                                payload_dict['detectedApps'] = []
                                ctx.log.info("     Cleared 'detectedApps' field (sent empty list)")
                            
                            # Re-serializar o payload
                            json_data[payload_key] = json.dumps(payload_dict, ensure_ascii=False)
                        except Exception as parse_e:
                            ctx.log.debug(f"Error parsing event_payload: {parse_e}")
                    elif isinstance(payload, dict):
                        # Payload jÃ¡ Ã© dict
                        if 'detection' in payload:
                            payload['detection'] = []
                        if 'Detection' in payload:
                            payload['Detection'] = []
                        if 'detected_apps' in payload:
                            payload['detected_apps'] = []
                        if 'detectedApps' in payload:
                            payload['detectedApps'] = []
                
                # TambÃ©m limpar no nÃ­vel raiz se existir
                if 'detection' in json_data:
                    json_data['detection'] = []
                if 'Detection' in json_data:
                    json_data['Detection'] = []
                if 'detected_apps' in json_data:
                    json_data['detected_apps'] = []
                if 'detectedApps' in json_data:
                    json_data['detectedApps'] = []
                
                ctx.log.info("  [FIX #5] âœ… Packet modified to send CLEAN report (empty detection list)")
                return json_data  # Retornar modificado, nÃ£o bloquear
        
        # Se Ã© uma lista de eventos
        if isinstance(json_data, list):
            modified = False
            
            for item in json_data:
                if isinstance(item, dict):
                    item_event_type = item.get('event_type') or item.get('eventType') or item.get('EventType')
                    
                    # Se encontrar o evento de detecÃ§Ã£o, limpar ao invÃ©s de remover
                    if item_event_type == 'EventTypeAndroidApplicationDetection' or 'AndroidApplicationDetection' in str(item_event_type):
                        ctx.log.warn(f"  [FIX #5] Evento na lista detectado - LIMPANDO: {item_event_type}")
                        
                        # Limpar campos de detecÃ§Ã£o
                        if 'event_payload' in item or 'eventPayload' in item:
                            payload_key = 'event_payload' if 'event_payload' in item else 'eventPayload'
                            payload = item[payload_key]
                            
                            if isinstance(payload, str):
                                try:
                                    payload_dict = json.loads(payload)
                                    if 'detection' in payload_dict:
                                        payload_dict['detection'] = []
                                    if 'Detection' in payload_dict:
                                        payload_dict['Detection'] = []
                                    if 'detected_apps' in payload_dict:
                                        payload_dict['detected_apps'] = []
                                    if 'detectedApps' in payload_dict:
                                        payload_dict['detectedApps'] = []
                                    item[payload_key] = json.dumps(payload_dict, ensure_ascii=False)
                                except:
                                    pass
                            elif isinstance(payload, dict):
                                if 'detection' in payload:
                                    payload['detection'] = []
                                if 'Detection' in payload:
                                    payload['Detection'] = []
                                if 'detected_apps' in payload:
                                    payload['detected_apps'] = []
                                if 'detectedApps' in payload:
                                    payload['detectedApps'] = []
                        
                        # Limpar no nÃ­vel raiz tambÃ©m
                        if 'detection' in item:
                            item['detection'] = []
                        if 'Detection' in item:
                            item['Detection'] = []
                        if 'detected_apps' in item:
                            item['detected_apps'] = []
                        if 'detectedApps' in item:
                            item['detectedApps'] = []
                        
                        modified = True
            
            if modified:
                ctx.log.info("  [FIX #5] âœ… Modified detection events in list to send CLEAN reports")
            
            return json_data  # Retornar lista modificada, nÃ£o bloquear
        
        # Nenhum evento de detecÃ§Ã£o encontrado
        return json_data
        
    except Exception as e:
        ctx.log.debug(f"Error in block_android_detection_event: {e}")
        return json_data

def spoof_datadome_form_data(form_data_str):
    """
    Modifica dados do dispositivo em requisiÃ§Ãµes DataDome (form URL-encoded)
    """
    try:
        from urllib.parse import parse_qs, urlencode, unquote, quote
        
        # Parsear dados URL-encoded
        parsed = parse_qs(form_data_str, keep_blank_values=True)
        modified = False
        
        # Obter valores spoofados
        spoofed = get_spoofed_device_for_logevent()
        spoofed_model = spoofed.get('device_model', 'Samsung SM-G998B')  # Usar o modelo jÃ¡ escolhido aleatoriamente
        
        # Modificar campos de dispositivo
        if 'ua' in parsed:
            # User-Agent: GarenaMSDK/4.0.39(ONEPLUS A5000 ;Android 7.1.1;pt;BR;)
            original_ua = parsed['ua'][0] if isinstance(parsed['ua'], list) else parsed['ua']
            # Extrair modelo e modificar
            if 'ONEPLUS A5000' in original_ua:
                new_ua = original_ua.replace('ONEPLUS A5000', spoofed_model.replace(' ', '_').upper())
                parsed['ua'] = [new_ua]
                modified = True
        
        if 'mdl' in parsed:
            # mdl=ONEPLUS A5000 -> modelo spoofado
            parsed['mdl'] = [spoofed_model.replace(' ', '_').upper()]
            modified = True
        
        if 'prd' in parsed:
            # prd=OnePlus5 -> extrair do modelo spoofado
            if 'OnePlus' in spoofed_model:
                parsed['prd'] = ['OnePlus' + spoofed_model.split()[-1][-1] if len(spoofed_model.split()) > 1 else 'OnePlus5']
            elif 'Samsung' in spoofed_model:
                parsed['prd'] = ['Galaxy' + spoofed_model.split()[-1]]
            elif 'Xiaomi' in spoofed_model:
                parsed['prd'] = ['Mi' + spoofed_model.split()[-1]]
            elif 'Pixel' in spoofed_model:
                parsed['prd'] = ['Pixel' + spoofed_model.split()[-2] + spoofed_model.split()[-1]]
            modified = True
        
        if 'mnf' in parsed:
            # mnf=OnePlus -> fabricante
            if 'OnePlus' in spoofed_model:
                parsed['mnf'] = ['OnePlus']
            elif 'Samsung' in spoofed_model:
                parsed['mnf'] = ['samsung']
            elif 'Xiaomi' in spoofed_model:
                parsed['mnf'] = ['Xiaomi']
            elif 'Pixel' in spoofed_model:
                parsed['mnf'] = ['Google']
            modified = True
        
        if 'dev' in parsed:
            # dev=OnePlus5 -> mesmo que prd
            if 'prd' in parsed:
                parsed['dev'] = parsed['prd']
            modified = True
        
        if 'fgp' in parsed:
            # fgp=OnePlus/OnePlus5/OnePlus5:7.1.1/NMF26X/10171617:user/release-keys
            original_fgp = parsed['fgp'][0] if isinstance(parsed['fgp'], list) else parsed['fgp']
            parts = original_fgp.split(':')
            if len(parts) > 0:
                # Modificar primeira parte (OnePlus/OnePlus5/OnePlus5)
                fgp_parts = parts[0].split('/')
                if len(fgp_parts) >= 1:
                    if 'OnePlus' in spoofed_model:
                        new_fgp = f"OnePlus/{fgp_parts[1] if len(fgp_parts) > 1 else 'OnePlus5'}/{fgp_parts[2] if len(fgp_parts) > 2 else 'OnePlus5'}"
                    elif 'Samsung' in spoofed_model:
                        new_fgp = f"samsung/{fgp_parts[1] if len(fgp_parts) > 1 else 'SM-G998B'}/{fgp_parts[2] if len(fgp_parts) > 2 else 'SM-G998B'}"
                    elif 'Xiaomi' in spoofed_model:
                        new_fgp = f"Xiaomi/{fgp_parts[1] if len(fgp_parts) > 1 else '2211133G'}/{fgp_parts[2] if len(fgp_parts) > 2 else '2211133G'}"
                    elif 'Pixel' in spoofed_model:
                        new_fgp = f"google/{fgp_parts[1] if len(fgp_parts) > 1 else 'Pixel7Pro'}/{fgp_parts[2] if len(fgp_parts) > 2 else 'Pixel7Pro'}"
                    else:
                        new_fgp = parts[0]
                    
                    # Reconstruir com resto original
                    if len(parts) > 1:
                        new_fgp = f"{new_fgp}:{':'.join(parts[1:])}"
                    parsed['fgp'] = [new_fgp]
                    modified = True
        
        # Modificar resoluÃ§Ã£o se muito baixa (emulador tÃ­pico)
        if 'screen_x' in parsed:
            screen_x = int(parsed['screen_x'][0]) if parsed['screen_x'] else 1280
            if screen_x < 1920:  # Se for baixa, modificar
                parsed['screen_x'] = ['2412']
                modified = True
        
        if 'screen_y' in parsed:
            screen_y = int(parsed['screen_y'][0]) if parsed['screen_y'] else 720
            if screen_y < 1080:  # Se for baixa, modificar
                parsed['screen_y'] = ['1080']
                modified = True
        
        if 'screen_d' in parsed:
            screen_d = int(parsed['screen_d'][0]) if parsed['screen_d'] else 240
            if screen_d < 400:  # Se for baixa, modificar
                parsed['screen_d'] = ['480']
                modified = True
        
        if modified:
            # Re-serializar form data
            new_form_data = urlencode(parsed, doseq=True)
            return new_form_data
        
        return None
        
    except Exception as e:
        ctx.log.debug(f"Erro ao spoofar DataDome form data: {e}")
        return None

class LoginInterceptor:
    def load(self, loader):
        ctx.log.info(f"Interceptor loaded on {LISTEN_HOST}:{LISTEN_PORT}")
        
        # Validar protobuf fields ao iniciar
        if PROTO_VALIDATOR_AVAILABLE:
            try:
                check_proto_changes_on_startup()
            except Exception as e:
                ctx.log.warn(f"Erro na validaÃ§Ã£o de protobuf: {e}")
        
        threading.Thread(target=self._load_uids_background, daemon=True).start()
        threading.Thread(target=self._sync_uids_loop, daemon=True).start()

    def _load_uids_background(self):
        try:
            fetch_uids()
        except Exception as e:
            ctx.log.error(f"Background loading error: {e}")

    def _sync_uids_loop(self):
        """Mantem cache de UIDs sincronizado periodicamente."""
        while True:
            try:
                fetch_uids()
            except Exception as e:
                ctx.log.debug(f"UID sync loop error: {e}")
            time.sleep(DB_SYNC_INTERVAL)

    def request(self, flow: http.HTTPFlow) -> None:
        # FIX #7: Add small random delay to avoid timing pattern detection
        time.sleep(random.uniform(0.01, 0.08))
        
        try:
            if not flow.request.content:
                return
            try:
                client_ip = get_client_ip(flow)
                decrypted = aes_utils.decrypt_aes_cbc(flow.request.content)
                try:
                    login_req = proto_utils.decode_protobuf(decrypted, LoginRes_pb2.NewLoginReq)
                    
                    # SPOOFING APENAS NO MAJORLOGIN - verificar se Ã© /majorlogin
                    is_majorlogin = '/majorlogin' in flow.request.path.lower()
                    
                    # Verificar se nÃºmeros de campo ainda funcionam (apenas na primeira requisiÃ§Ã£o do MajorLogin)
                    if is_majorlogin and not hasattr(LoginInterceptor, '_field_verification_done'):
                        # Listar TODOS os campos disponÃ­veis na mensagem real
                        all_available_fields = list_all_protobuf_fields(login_req)
                        
                        # Mapeamento dos campos crÃ­ticos que usamos {nome_real_python: numero_protobuf}
                        # Usa os nomes REAIS do protobuf Python, nÃ£o os do .proto
                        critical_field_numbers = {
                            'device_model': 25,      # Campo 25
                            'os_info': 8,            # Campo 8 (no .proto Ã© system_software)
                            'cpu_info': 15,          # Campo 15 (no .proto Ã© cpu_hardware)
                            'lib_path': 74,          # Campo 74 (no .proto Ã© library_path)
                            'arch': 81,              # Campo 81 (no .proto Ã© cpu_architecture)
                            'screen_width': 12,      # Campo 12
                            'screen_height': 13,     # Campo 13
                            'language': 21,          # Campo 21
                            'device_type': 9,        # Campo 9
                        }
                        
                        field_check = verify_protobuf_field_numbers(login_req, critical_field_numbers)
                        
                        # Mostrar resultados da verificaÃ§Ã£o
                        ctx.log.info("=" * 50)
                        ctx.log.info("VERIFICACAO DE CAMPOS PROTOBUF:")
                        ctx.log.info(f"  Total testado: {field_check['total']}")
                        ctx.log.info(f"  Funcionando: {len(field_check['working'])}")
                        
                        if field_check['missing']:
                            ctx.log.warn(f"  [X] Campos faltando ({len(field_check['missing'])}):")
                            for missing in field_check['missing'][:5]:  # Mostrar primeiros 5
                                ctx.log.warn(f"     - {missing}")
                            
                            # Tentar encontrar campos por nÃºmero ao invÃ©s de nome
                            if isinstance(all_available_fields, list) and len(all_available_fields) > 0:
                                if isinstance(all_available_fields[0], dict):
                                    # Campos com formato dict (do DESCRIPTOR)
                                    ctx.log.info("  [*] Procurando campos por numero...")
                                    for missing_field, expected_num in critical_field_numbers.items():
                                        if missing_field in [m.split(' (')[0] for m in field_check['missing']]:
                                            found_by_num = [f for f in all_available_fields if f.get('number') == expected_num]
                                            if found_by_num:
                                                ctx.log.info(f"     Campo #{expected_num} encontrado como: '{found_by_num[0]['name']}' (esperado: '{missing_field}')")
                        
                        if field_check['changed']:
                            ctx.log.warn(f"  [!] Campos com problema ({len(field_check['changed'])}):")
                            for changed in field_check['changed'][:5]:  # Mostrar primeiros 5
                                ctx.log.warn(f"     - {changed}")
                        
                        # Mostrar todos os campos disponÃ­veis (debug)
                        if isinstance(all_available_fields, list) and len(all_available_fields) > 0:
                            if isinstance(all_available_fields[0], dict):
                                ctx.log.info(f"  [*] Total de campos no protobuf: {len(all_available_fields)}")
                                ctx.log.info("  [*] Primeiros 10 campos disponiveis:")
                                for field in all_available_fields[:10]:
                                    ctx.log.info(f"     - {field.get('name')} (#{field.get('number')}) [{field.get('type')}]")
                            else:
                                ctx.log.info(f"  [*] Campos disponiveis (primeiros 15): {', '.join(all_available_fields[:15])}")
                        
                        if field_check['valid']:
                            ctx.log.info("  [OK] Todos os campos criticos estao funcionando!")
                        else:
                            ctx.log.warn(f"  [!] {len(field_check['missing']) + len(field_check['changed'])} campo(s) pode(m) ter mudado!")
                            ctx.log.warn("  [*] Dica: Verifique os nomes reais dos campos acima")
                        
                        ctx.log.info("=" * 50)
                        
                        LoginInterceptor._field_verification_done = True
                    
                    # APLICAR SPOOFING APENAS NO MAJORLOGIN
                    if is_majorlogin:
                        # RANKED FIX #1: Pass flow to get session-consistent profile
                        device_info = get_spoofed_device_info(flow)
                        
                        # Validar mensagem protobuf antes de modificar (campos crÃ­ticos)
                        # Usa nomes REAIS do protobuf Python
                        critical_fields = ['device_model', 'os_info', 'cpu_info', 'lib_path', 'arch']
                        if PROTO_VALIDATOR_AVAILABLE:
                            is_valid, missing = validate_protobuf_message(login_req, critical_fields)
                            if not is_valid and missing:
                                ctx.log.warn(f"âš ï¸  Campos crÃ­ticos faltando: {missing}")
                        
                        # FIX #1: Handle Field 94 (deviceData) BEFORE applying other spoofing
                        if hasattr(login_req, 'deviceData'):
                            try:
                                current_device_data = getattr(login_req, 'deviceData')
                                if current_device_data:
                                    spoofed_device_data = spoof_field_94_device_data(
                                        current_device_data, 
                                        device_info['device_model']
                                    )
                                    setattr(login_req, 'deviceData', spoofed_device_data)
                                    ctx.log.info(f"  [FIX #1] Spoofed Field 94 (deviceData) to match: {device_info['device_model']}")
                            except Exception as e:
                                ctx.log.debug(f"Error handling field 94: {e}")
                        
                        # FIX #4: Sanitize reserved fields to prevent device integer leaks
                        sanitize_reserved_fields(login_req)
                        
                        # FIX #3: Handle Field 102 (reserved20) checksum
                        handle_field_102_checksum(login_req)
                        
                        # Aplicar spoofing usando validaÃ§Ã£o segura se disponÃ­vel
                        spoofed_count = 0
                        for field, value in device_info.items():
                            if PROTO_VALIDATOR_AVAILABLE:
                                # Usa validaÃ§Ã£o segura com nomes alternativos
                                alternative_names = OPTIONAL_FIELDS.get(field, [])
                                if safe_set_protobuf_field(login_req, field, value, alternative_names):
                                    spoofed_count += 1
                            else:
                                # Fallback para mÃ©todo antigo
                                if hasattr(login_req, field):
                                    try:
                                        setattr(login_req, field, value)
                                        spoofed_count += 1
                                    except Exception as e:
                                        ctx.log.debug(f"Erro ao definir {field}: {e}")
                        
                        if spoofed_count > 0:
                            ctx.log.info(f"âœ… Spoofed device info from {client_ip} ({spoofed_count} campos) - Profile: {device_info['device_model']}")
                        
                        # Re-serializar e re-criptografar apenas no MajorLogin
                        flow.metadata["is_login_request"] = True
                        serialized = proto_utils.encode_protobuf(login_req)
                        encrypted = aes_utils.encrypt_aes_cbc(serialized)
                        flow.request.content = encrypted
                        flow.request.headers["Content-Length"] = str(len(flow.request.content))
                    else:
                        # Se nÃ£o for MajorLogin, apenas marca como nÃ£o Ã© login request
                        flow.metadata["is_login_request"] = False
                except Exception as e:
                    ctx.log.debug(f"Not login: {e}")
                    flow.metadata["is_login_request"] = False
            except Exception as de:
                ctx.log.debug(f"Decrypt failed: {de}")
                # Not encrypted, skip
                pass
            # Check if it's MajorLogin
            if '/majorlogin' in flow.request.path.lower():
                flow.metadata["is_major_login"] = True
                ctx.log.info("Detected MajorLogin request")
            else:
                flow.metadata["is_major_login"] = False
            
            # RANKED FIX #4: Detect ranked matchmaking endpoints
            ranked_paths = ['/v1/rank', '/matchmaking', '/match', '/queue', '/ranked']
            is_ranked_endpoint = any(path in flow.request.path.lower() for path in ranked_paths)
            if is_ranked_endpoint:
                flow.metadata["is_ranked_request"] = True
                ctx.log.info(f"[RANKED FIX #4] Detected ranked endpoint: {flow.request.path}")
                
                # Apply same spoofing to ranked endpoints
                try:
                    decrypted = aes_utils.decrypt_aes_cbc(flow.request.content)
                    try:
                        # Try to decode as protobuf and apply spoofing
                        login_req = proto_utils.decode_protobuf(decrypted, LoginRes_pb2.NewLoginReq)
                        
                        # RANKED FIX #1: Use session-consistent profile
                        device_info = get_spoofed_device_info(flow)
                        
                        # Apply spoofing to ranked request
                        spoofed_count = 0
                        for field, value in device_info.items():
                            if hasattr(login_req, field):
                                try:
                                    setattr(login_req, field, value)
                                    spoofed_count += 1
                                except Exception as e:
                                    ctx.log.debug(f"Error setting {field}: {e}")
                        
                        if spoofed_count > 0:
                            ctx.log.info(f"[RANKED FIX #4] Spoofed {spoofed_count} fields in ranked request")
                            
                            # Re-encrypt and update
                            serialized = proto_utils.encode_protobuf(login_req)
                            encrypted = aes_utils.encrypt_aes_cbc(serialized)
                            flow.request.content = encrypted
                            flow.request.headers["Content-Length"] = str(len(flow.request.content))
                    except Exception as e:
                        ctx.log.debug(f"Ranked endpoint not protobuf: {e}")
                except Exception as e:
                    ctx.log.debug(f"Ranked endpoint decrypt failed: {e}")
            else:
                flow.metadata["is_ranked_request"] = False
            
            # Interceptar TODOS os endpoints do Free Fire para mostrar campos
            freefire_domains = [
                'ggpolarbear.com',
                'freefiremobile.com',
                'ggblueshark.com',
                'garena.com',
                'datadome.co'
            ]
            
            is_freefire = any(domain in flow.request.pretty_host.lower() for domain in freefire_domains)
            
            # Interceptar TODOS os endpoints do Free Fire (incluindo os especÃ­ficos)
            if is_freefire and flow.request.content:
                # Interceptar todos os outros endpoints do Free Fire
                endpoint_name = f"{flow.request.pretty_host}{flow.request.path}"
                ctx.log.info("=" * 60)
                ctx.log.info(f"DETECTADO: Free Fire Endpoint - {endpoint_name}")
                ctx.log.info("=" * 60)
                
                try:
                    # FIX #5: Removed pre-blocking checks - we now modify the content instead of blocking
                    
                    # Tentar decriptar
                    try:
                        decrypted = aes_utils.decrypt_aes_cbc(flow.request.content)
                        ctx.log.info(f"  [*] Conteudo decriptado: {len(decrypted)} bytes")
                        
                        # Tentar decodificar como protobuf - tentar TODOS os tipos conhecidos
                        protobuf_decoded = False
                        pb_modules = [
                            ('LoginRes_pb2', LoginRes_pb2),
                            ('Login_pb2', Login_pb2),
                        ]
                        # Lista de tipos de mensagens para tentar
                        pb_type_names = [
                            'NewLoginReq', 'LoginReq', 'LoginReqNew', 'MajorLoginRes', 'MajorLoginResNew',
                            'LoginRes', 'LoginRes2', 'LoginDescRes', 'getUID'
                        ]
                        
                        for module_name, pb_module in pb_modules:
                            for pb_type_name in pb_type_names:
                                try:
                                    if hasattr(pb_module, pb_type_name):
                                        pb_type = getattr(pb_module, pb_type_name)
                                        decoded = proto_utils.decode_protobuf(decrypted, pb_type)
                                        
                                        all_fields = list_all_protobuf_fields(decoded)
                                        if isinstance(all_fields, list) and len(all_fields) > 0:
                                            ctx.log.info(f"  [*] Tipo: {module_name}.{pb_type_name} | Total campos: {len(all_fields)}")
                                            
                                            if isinstance(all_fields[0], dict):
                                                sorted_fields = sorted(all_fields, key=lambda x: x.get('number', 0))
                                                ctx.log.info("  [*] TODOS OS CAMPOS (ordenados por numero):")
                                                for field in sorted_fields:
                                                    field_name = field.get('name', 'unknown')
                                                    field_number = field.get('number', 0)
                                                    field_type = field.get('type', 'unknown')
                                                    try:
                                                        value = getattr(decoded, field_name, None)
                                                        if value is None or value == "" or value == 0:
                                                            value_str = "<vazio>"
                                                        elif isinstance(value, bytes):
                                                            value_str = f"<bytes:{len(value)}> {binascii.hexlify(value[:20]).decode()}..."
                                                        elif len(str(value)) > 80:
                                                            value_str = str(value)[:77] + "..."
                                                        else:
                                                            value_str = str(value)
                                                        ctx.log.info(f"     #{field_number:3d}: {field_name:30s} [{field_type:15s}] = {value_str}")
                                                    except Exception as field_e:
                                                        ctx.log.debug(f"     #{field_number:3d}: {field_name:30s} [<erro>] = erro ao ler: {field_e}")
                                            protobuf_decoded = True
                                            break
                                except Exception as pb_e:
                                    ctx.log.debug(f"  [*] Falhou ao decodificar como {module_name}.{pb_type_name}: {pb_e}")
                                    continue
                            
                            if protobuf_decoded:
                                break
                        
                        # Se nÃ£o decodificou como protobuf, continuar com JSON/texto
                        if not protobuf_decoded:
                            try:
                                import json
                                json_data = json.loads(decrypted.decode('utf-8'))
                                
                                # FIX #5: Modificar eventos EventTypeAndroidApplicationDetection (nÃ£o bloquear)
                                json_data = block_android_detection_event(json_data)
                                
                                # Re-criptografar e atualizar o conteÃºdo se foi modificado
                                modified_content = json.dumps(json_data, ensure_ascii=False).encode('utf-8')
                                if modified_content != decrypted:
                                    encrypted_modified = aes_utils.encrypt_aes_cbc(modified_content)
                                    flow.request.content = encrypted_modified
                                    flow.request.headers["Content-Length"] = str(len(flow.request.content))
                                    ctx.log.info("  [FIX #5] âœ… Modified and re-encrypted request content")
                                
                                json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
                                ctx.log.info("  [*] Conteudo JSON (COMPLETO):")
                                # Mostrar JSON completo em mÃºltiplas linhas
                                for line in json_str.split('\n'):
                                    ctx.log.info(f"     {line}")
                                
                                # Salvar JSON em arquivo .txt
                                save_json_to_file(json_data, flow.request.path, flow.request.pretty_host)
                            except:
                                text = decrypted.decode('utf-8', errors='ignore')
                                
                                # Verificar se Ã© texto legÃ­vel ou binÃ¡rio (pode ser protobuf)
                                is_binary = False
                                if text:
                                    printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text)
                                    if printable_ratio < 0.7:  # Menos de 70% imprimÃ­vel = provavelmente binÃ¡rio
                                        is_binary = True
                                
                                if is_binary:
                                    # Provavelmente protobuf ou outro formato binÃ¡rio
                                    ctx.log.info(f"  [*] Dados binarios (pos-prototobuf): {len(decrypted)} bytes")
                                    ctx.log.info(f"  [*] Hex dump (primeiros 200 bytes):")
                                    hex_str = binascii.hexlify(decrypted[:200]).decode()
                                    for i in range(0, len(hex_str), 64):
                                        ctx.log.info(f"     {hex_str[i:i+64]}")
                                elif text.strip():
                                    ctx.log.info(f"  [*] Texto (COMPLETO):")
                                    for line in text.split('\n')[:50]:  # Limitar a 50 linhas
                                        ctx.log.info(f"     {line}")
                    except:
                        # Se nÃ£o for AES, tentar como JSON/texto direto
                        try:
                            import json
                            json_data = json.loads(flow.request.content.decode('utf-8'))
                            
                            # FIX #5: Modificar eventos EventTypeAndroidApplicationDetection (nÃ£o bloquear)
                            json_data = block_android_detection_event(json_data)
                            
                            # Atualizar o conteÃºdo se foi modificado
                            modified_content = json.dumps(json_data, ensure_ascii=False).encode('utf-8')
                            if modified_content != flow.request.content:
                                flow.request.content = modified_content
                                flow.request.headers["Content-Length"] = str(len(flow.request.content))
                                ctx.log.info("  [FIX #5] âœ… Modified request content (unencrypted)")
                            
                            json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
                            ctx.log.info("  [*] Conteudo JSON (nao criptografado - COMPLETO):")
                            # Mostrar JSON completo em mÃºltiplas linhas
                            for line in json_str.split('\n'):
                                ctx.log.info(f"     {line}")
                            
                            # Salvar JSON em arquivo .txt
                            save_json_to_file(json_data, flow.request.path, flow.request.pretty_host)
                        except:
                            text = flow.request.content.decode('utf-8', errors='ignore')
                            
                            # Verificar se Ã© realmente texto legÃ­vel ou binÃ¡rio
                            is_binary = False
                            printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text) if text else 0
                            if len(text) > 0 and printable_ratio < 0.7:  # Menos de 70% dos caracteres sÃ£o imprimÃ­veis
                                is_binary = True
                            
                            if is_binary:
                                # Dados binÃ¡rios - mostrar como hex
                                ctx.log.info(f"  [*] Dados binarios/criptografados: {len(flow.request.content)} bytes")
                                ctx.log.info(f"  [*] Hex dump (primeiros 200 bytes):")
                                hex_str = binascii.hexlify(flow.request.content[:200]).decode()
                                for i in range(0, len(hex_str), 64):
                                    ctx.log.info(f"     {hex_str[i:i+64]}")
                            elif text.strip() and len(text) < 5000:  # Mostrar se nÃ£o for muito grande
                                ctx.log.info(f"  [*] Texto (COMPLETO):")
                                for line in text.split('\n')[:100]:  # Limitar a 100 linhas
                                    ctx.log.info(f"     {line}")
                except Exception as e:
                    ctx.log.debug(f"  [*] Erro ao processar: {e}")
                
                ctx.log.info("=" * 60)
            
            # Interceptar MajorRegister para debug
            if '/majorregister' in flow.request.path.lower():
                ctx.log.info("=" * 60)
                ctx.log.info("DETECTADO: MajorRegister (REQUEST)")
                ctx.log.info("=" * 60)
                
                try:
                    # Tentar decriptar
                    if flow.request.content:
                        decrypted = aes_utils.decrypt_aes_cbc(flow.request.content)
                        ctx.log.info(f"  [*] Conteudo decriptado: {len(decrypted)} bytes")
                        
                        # Tentar decodificar como protobuf
                        try:
                            for pb_type_name in ['NewLoginReq', 'LoginReq']:
                                try:
                                    if hasattr(LoginRes_pb2, pb_type_name):
                                        pb_type = getattr(LoginRes_pb2, pb_type_name)
                                        decoded = proto_utils.decode_protobuf(decrypted, pb_type)
                                        
                                        all_fields = list_all_protobuf_fields(decoded)
                                        ctx.log.info(f"  [*] Tipo: {pb_type_name} | Total campos: {len(all_fields)}")
                                        
                                        if isinstance(all_fields, list) and len(all_fields) > 0 and isinstance(all_fields[0], dict):
                                            sorted_fields = sorted(all_fields, key=lambda x: x.get('number', 0))
                                            ctx.log.info("  [*] TODOS OS CAMPOS ENVIADOS:")
                                            for field in sorted_fields:
                                                field_name = field.get('name', 'unknown')
                                                field_number = field.get('number', 0)
                                                try:
                                                    value = getattr(decoded, field_name, None)
                                                    value_str = "<vazio>" if not value else (str(value)[:80] if len(str(value)) <= 80 else str(value)[:77] + "...")
                                                    ctx.log.info(f"     {field_number:3d}. {field_name:25s} = {value_str}")
                                                except:
                                                    ctx.log.info(f"     {field_number:3d}. {field_name:25s} = <erro>")
                                        break
                                except Exception as pb_e:
                                    ctx.log.debug(f"  [*] Falhou como {pb_type_name}: {pb_e}")
                        except Exception as decode_e:
                            ctx.log.warn(f"  [!] Erro ao decodificar: {decode_e}")
                except Exception as e:
                    ctx.log.warn(f"  [!] Erro ao processar MajorRegister: {e}")
                
                ctx.log.info("=" * 60)
            
            # Interceptar NetworkLogEvent para debug
            if '/networklogevent' in flow.request.path.lower() or ('ggblueshark.com' in flow.request.pretty_host.lower() and 'network' in flow.request.path.lower()):
                if flow.request.content:  # SÃ³ mostrar se tiver conteÃºdo
                    ctx.log.info("=" * 60)
                    ctx.log.info(f"DETECTADO: NetworkLogEvent - {flow.request.pretty_host}{flow.request.path}")
                    ctx.log.info("=" * 60)
                    
                    try:
                        # Tentar decriptar
                        try:
                            decrypted = aes_utils.decrypt_aes_cbc(flow.request.content)
                            ctx.log.info(f"  [*] Conteudo decriptado: {len(decrypted)} bytes")
                            
                            # Tentar decodificar como protobuf
                            try:
                                for pb_type_name in ['NewLoginReq', 'LoginReq']:
                                    try:
                                        if hasattr(LoginRes_pb2, pb_type_name):
                                            pb_type = getattr(LoginRes_pb2, pb_type_name)
                                            decoded = proto_utils.decode_protobuf(decrypted, pb_type)
                                            
                                            all_fields = list_all_protobuf_fields(decoded)
                                            ctx.log.info(f"  [*] Tipo: {pb_type_name} | Total campos: {len(all_fields)}")
                                            
                                            if isinstance(all_fields, list) and len(all_fields) > 0 and isinstance(all_fields[0], dict):
                                                sorted_fields = sorted(all_fields, key=lambda x: x.get('number', 0))
                                                ctx.log.info("  [*] TODOS OS CAMPOS ENVIADOS:")
                                                for field in sorted_fields:
                                                    field_name = field.get('name', 'unknown')
                                                    field_number = field.get('number', 0)
                                                    field_type = field.get('type', 'unknown')
                                                    try:
                                                        value = getattr(decoded, field_name, None)
                                                        if value is None or value == "":
                                                            value_str = "<vazio>"
                                                        elif isinstance(value, str) and len(value) > 80:
                                                            value_str = value[:77] + "..."
                                                        elif isinstance(value, bytes):
                                                            value_str = f"<bytes:{len(value)}> {binascii.hexlify(value[:20]).decode()}..."
                                                        else:
                                                            value_str = str(value)
                                                        ctx.log.info(f"     {field_number:3d}. {field_name:25s} [{field_type:15s}] = {value_str}")
                                                    except:
                                                        ctx.log.info(f"     {field_number:3d}. {field_name:25s} [{field_type:15s}] = <erro>")
                                            break
                                    except Exception as pb_e:
                                        ctx.log.debug(f"  [*] Falhou como {pb_type_name}: {pb_e}")
                            except Exception as decode_e:
                                ctx.log.warn(f"  [!] Erro ao decodificar protobuf: {decode_e}")
                                # Se nÃ£o for protobuf, tentar como JSON ou texto
                                try:
                                    import json
                                    json_data = json.loads(decrypted.decode('utf-8'))
                                    
                                    # FIX #5: Modificar eventos EventTypeAndroidApplicationDetection (nÃ£o bloquear)
                                    json_data = block_android_detection_event(json_data)
                                    
                                    # Re-criptografar e atualizar o conteÃºdo se foi modificado
                                    modified_content = json.dumps(json_data, ensure_ascii=False).encode('utf-8')
                                    if modified_content != decrypted:
                                        encrypted_modified = aes_utils.encrypt_aes_cbc(modified_content)
                                        flow.request.content = encrypted_modified
                                        flow.request.headers["Content-Length"] = str(len(flow.request.content))
                                        ctx.log.info("  [FIX #5] âœ… Modified and re-encrypted request content")
                                    
                                    json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
                                    ctx.log.info("  [*] Conteudo JSON (COMPLETO):")
                                    # Mostrar JSON completo em mÃºltiplas linhas
                                    for line in json_str.split('\n'):
                                        ctx.log.info(f"     {line}")
                                    
                                    # Salvar JSON em arquivo .txt
                                    save_json_to_file(json_data, flow.request.path, flow.request.pretty_host)
                                except:
                                    try:
                                        text = decrypted.decode('utf-8', errors='ignore')
                                        if text.strip():
                                            ctx.log.info(f"  [*] Conteudo texto: {text[:200]}")
                                    except:
                                        ctx.log.info(f"  [*] Hex dump: {binascii.hexlify(decrypted[:200]).decode()}")
                        except Exception as decrypt_e:
                            # Se nÃ£o for AES, tentar como JSON/texto direto
                            ctx.log.info(f"  [*] Conteudo nao criptografado (ou erro AES): {len(flow.request.content)} bytes")
                            try:
                                import json
                                json_data = json.loads(flow.request.content.decode('utf-8'))
                                
                                # FIX #5: Modificar eventos EventTypeAndroidApplicationDetection (nÃ£o bloquear)
                                json_data = block_android_detection_event(json_data)
                                
                                # Atualizar o conteÃºdo se foi modificado
                                modified_content = json.dumps(json_data, ensure_ascii=False).encode('utf-8')
                                if modified_content != flow.request.content:
                                    flow.request.content = modified_content
                                    flow.request.headers["Content-Length"] = str(len(flow.request.content))
                                    ctx.log.info("  [FIX #5] âœ… Modified request content (unencrypted)")
                                
                                json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
                                ctx.log.info("  [*] Conteudo JSON (COMPLETO):")
                                json_data = blocked_json
                                
                                json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
                                ctx.log.info("  [*] Conteudo JSON (COMPLETO):")
                                # Mostrar JSON completo em mÃºltiplas linhas
                                for line in json_str.split('\n'):
                                    ctx.log.info(f"     {line}")
                                
                                # Salvar JSON em arquivo .txt
                                save_json_to_file(json_data, flow.request.path, flow.request.pretty_host)
                            except:
                                try:
                                    text = flow.request.content.decode('utf-8', errors='ignore')
                                    if text.strip():
                                        ctx.log.info(f"  [*] Conteudo texto: {text[:300]}")
                                except:
                                    ctx.log.info(f"  [*] Hex dump: {binascii.hexlify(flow.request.content[:200]).decode()}")
                    except Exception as e:
                        ctx.log.warn(f"  [!] Erro ao processar NetworkLogEvent: {e}")
                    
                    ctx.log.info("=" * 60)
            
            # Interceptar GetAccountBriefInfoBeforeLogin para debug
            if '/getaccountbriefinfobeforelogin' in flow.request.path.lower():
                ctx.log.info("=" * 60)
                ctx.log.info("DETECTADO: GetAccountBriefInfoBeforeLogin")
                ctx.log.info("=" * 60)
                
                try:
                    # Tentar decriptar
                    if flow.request.content:
                        decrypted = aes_utils.decrypt_aes_cbc(flow.request.content)
                        ctx.log.info(f"  [*] Conteudo decriptado: {len(decrypted)} bytes")
                        
                        # Tentar decodificar como protobuf
                        try:
                            # Tentar diferentes tipos de mensagem
                            for pb_type_name in ['NewLoginReq', 'LoginReq']:
                                try:
                                    if hasattr(LoginRes_pb2, pb_type_name):
                                        pb_type = getattr(LoginRes_pb2, pb_type_name)
                                        decoded = proto_utils.decode_protobuf(decrypted, pb_type)
                                        
                                        # Listar todos os campos
                                        all_fields = list_all_protobuf_fields(decoded)
                                        ctx.log.info(f"  [*] Tipo de mensagem: {pb_type_name}")
                                        ctx.log.info(f"  [*] Total de campos: {len(all_fields)}")
                                        ctx.log.info("  [*] Campos disponiveis:")
                                        
                                        if isinstance(all_fields, list) and len(all_fields) > 0:
                                            if isinstance(all_fields[0], dict):
                                                # Campos com formato dict (do DESCRIPTOR)
                                                # Ordenar por nÃºmero de campo
                                                sorted_fields = sorted(all_fields, key=lambda x: x.get('number', 0))
                                                
                                                ctx.log.info("  [*] TODOS OS CAMPOS (ordenados por numero):")
                                                for field in sorted_fields:
                                                    field_name = field.get('name', 'unknown')
                                                    field_number = field.get('number', 0)
                                                    field_type = field.get('type', 'unknown')
                                                    
                                                    # Tentar obter valor do campo
                                                    try:
                                                        value = getattr(decoded, field_name, None)
                                                        
                                                        # Formatar valor
                                                        if value is None or value == "":
                                                            value_str = "<vazio>"
                                                        elif isinstance(value, str):
                                                            if len(value) > 80:
                                                                value_str = value[:77] + "..."
                                                            else:
                                                                value_str = value
                                                        elif isinstance(value, bytes):
                                                            if len(value) > 50:
                                                                value_str = f"<bytes:{len(value)}> {binascii.hexlify(value[:20]).decode()}..."
                                                            else:
                                                                value_str = f"<bytes:{len(value)}> {binascii.hexlify(value).decode()}"
                                                        elif isinstance(value, (int, float, bool)):
                                                            value_str = str(value)
                                                        elif isinstance(value, list):
                                                            value_str = f"<lista[{len(value)}]> {str(value[:5])[:50]}..."
                                                        else:
                                                            value_str = str(value)[:80]
                                                        
                                                        ctx.log.info(f"     {field_number:3d}. {field_name:25s} [{field_type:15s}] = {value_str}")
                                                    except Exception as e:
                                                        ctx.log.info(f"     {field_number:3d}. {field_name:25s} [{field_type:15s}] = <erro: {e}>")
                                                break
                                            else:
                                                # Lista simples de nomes
                                                for field_name in all_fields:
                                                    try:
                                                        value = getattr(decoded, field_name, None)
                                                        value_str = str(value)[:50] if value else "None"
                                                        ctx.log.info(f"     - {field_name}: {value_str}")
                                                    except:
                                                        ctx.log.info(f"     - {field_name}: <campo>")
                                        else:
                                            # Fallback: usar dir()
                                            ctx.log.info("  [*] Usando dir() para listar campos:")
                                            for attr in dir(decoded):
                                                if not attr.startswith('_') and not callable(getattr(decoded, attr, None)):
                                                    try:
                                                        value = getattr(decoded, attr)
                                                        value_str = str(value)[:50] if value else "None"
                                                        ctx.log.info(f"     - {attr}: {value_str}")
                                                    except:
                                                        pass
                                        break
                                except Exception as pb_e:
                                    ctx.log.debug(f"  [*] Falhou ao decodificar como {pb_type_name}: {pb_e}")
                            else:
                                ctx.log.warn("  [!] Nao foi possivel decodificar como nenhum tipo de mensagem conhecido")
                                ctx.log.info(f"  [*] Hex dump (primeiros 200 bytes):")
                                hex_str = binascii.hexlify(decrypted[:200]).decode()
                                for i in range(0, len(hex_str), 64):
                                    ctx.log.info(f"     {hex_str[i:i+64]}")
                        except Exception as decode_e:
                            ctx.log.warn(f"  [!] Erro ao decodificar protobuf: {decode_e}")
                except Exception as e:
                    ctx.log.warn(f"  [!] Erro ao processar GetAccountBriefInfoBeforeLogin: {e}")
                
                ctx.log.info("=" * 60)
        except Exception as e:
            ctx.log.error(f"Request error: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            if not flow.response.content:
                return
            client_ip = get_client_ip(flow)
            
            # Interceptar resposta do MajorRegister para debug
            if '/majorregister' in flow.request.path.lower():
                ctx.log.info("=" * 60)
                ctx.log.info(f"DETECTADO: MajorRegister (RESPONSE) - Status: {flow.response.status_code}")
                ctx.log.info("=" * 60)
                
                try:
                    ctx.log.info(f"  [*] Status: {flow.response.status_code}")
                    ctx.log.info(f"  [*] Tamanho resposta: {len(flow.response.content)} bytes")
                    
                    if flow.response.status_code >= 400:
                        ctx.log.warn(f"  [!] ERRO {flow.response.status_code} detectado!")
                        if flow.response.content:
                            try:
                                # Tentar decriptar se for AES
                                try:
                                    decrypted = aes_utils.decrypt_aes_cbc(flow.response.content)
                                    ctx.log.info(f"  [*] Conteudo decriptado: {len(decrypted)} bytes")
                                    ctx.log.info(f"  [*] Hex (primeiros 200 bytes): {binascii.hexlify(decrypted[:200]).decode()}")
                                    
                                    # Tentar decodificar como texto
                                    try:
                                        text = decrypted.decode('utf-8', errors='ignore')
                                        ctx.log.info(f"  [*] Texto: {text[:200]}")
                                    except:
                                        pass
                                except:
                                    # Se nÃ£o for AES, tentar como texto direto
                                    try:
                                        text = flow.response.content.decode('utf-8', errors='ignore')
                                        ctx.log.info(f"  [*] Texto (sem decrypt): {text[:200]}")
                                    except:
                                        ctx.log.info(f"  [*] Hex (raw): {binascii.hexlify(flow.response.content[:200]).decode()}")
                            except Exception as e:
                                ctx.log.warn(f"  [!] Erro ao analisar resposta: {e}")
                    else:
                        # Sucesso - tentar decodificar UID
                        ctx.log.info("  [*] Resposta OK - tentando extrair UID...")
                        
                except Exception as e:
                    ctx.log.warn(f"  [!] Erro ao processar resposta MajorRegister: {e}")
                
                ctx.log.info("=" * 60)
            
            # Interceptar resposta do LoginGetDesc para ver os campos
            if '/logingetdesc' in flow.request.path.lower():
                ctx.log.info("=" * 60)
                ctx.log.info(f"DETECTADO: LoginGetDesc (RESPONSE) - Status: {flow.response.status_code}")
                ctx.log.info("=" * 60)
                
                try:
                    ctx.log.info(f"  [*] Status: {flow.response.status_code}")
                    ctx.log.info(f"  [*] Tamanho resposta: {len(flow.response.content)} bytes")
                    
                    if flow.response.status_code == 200 and flow.response.content:
                        # Tentar decriptar se for AES
                        try:
                            decrypted = aes_utils.decrypt_aes_cbc(flow.response.content)
                            ctx.log.info(f"  [*] Conteudo decriptado: {len(decrypted)} bytes")
                            
                            # Tentar decodificar como protobuf (LoginRes ou LoginResNew)
                            from proto_utils import ProtobufUtils
                            proto_utils = ProtobufUtils()
                            
                            protobuf_decoded = False
                            for pb_type, pb_type_name in [
                                (LoginResNew_pb2.LoginRes, "LoginRes"),
                                (LoginResNew_pb2.MajorLoginRes, "MajorLoginRes"),
                            ]:
                                try:
                                    decoded = proto_utils.decode_protobuf(decrypted, pb_type)
                                    ctx.log.info(f"  [*] Decodificado como {pb_type_name}!")
                                    
                                    # Listar todos os campos
                                    ctx.log.info("  [*] Campos da resposta (ordenados por numero):")
                                    fields = list_all_protobuf_fields(decoded)
                                    
                                    # Processar campos: pode ser lista de dicts ou lista de strings
                                    field_list = []
                                    for field in fields:
                                        if isinstance(field, dict):
                                            field_num = field.get('number', 0)
                                            field_name = field.get('name', 'unknown')
                                            field_type = field.get('type', 'unknown')
                                            # Tentar obter o valor do campo
                                            try:
                                                field_value = getattr(decoded, field_name, None)
                                            except:
                                                field_value = None
                                            field_list.append((field_num, field_name, field_type, field_value))
                                        elif isinstance(field, str):
                                            # Fallback: apenas nome do campo
                                            try:
                                                field_value = getattr(decoded, field, None)
                                                field_list.append((0, field, 'unknown', field_value))
                                            except:
                                                pass
                                    
                                    # Ordenar por nÃºmero e exibir
                                    field_list.sort(key=lambda x: x[0])
                                    for field_num, field_name, field_type, field_value in field_list:
                                        value_str = str(field_value)[:100] if field_value is not None else "None"
                                        ctx.log.info(f"     #{field_num}: {field_name} ({field_type}) = {value_str}")
                                    
                                    protobuf_decoded = True
                                    break
                                except Exception as pb_e:
                                    ctx.log.debug(f"  [*] Falhou ao decodificar como {pb_type_name}: {pb_e}")
                            
                            if not protobuf_decoded:
                                # Tentar como JSON ou texto
                                try:
                                    import json
                                    json_data = json.loads(decrypted.decode('utf-8'))
                                    json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
                                    ctx.log.info("  [*] Conteudo JSON:")
                                    for line in json_str.split('\n'):
                                        ctx.log.info(f"     {line}")
                                except:
                                    text = decrypted.decode('utf-8', errors='ignore')
                                    if text.strip() and len(text) < 1000:
                                        ctx.log.info(f"  [*] Texto: {text}")
                                    else:
                                        ctx.log.info(f"  [*] Hex dump (primeiros 200 bytes):")
                                        hex_str = binascii.hexlify(decrypted[:200]).decode()
                                        for i in range(0, len(hex_str), 64):
                                            ctx.log.info(f"     {hex_str[i:i+64]}")
                        except Exception as decrypt_e:
                            # Se nÃ£o for AES, tentar como texto direto
                            try:
                                text = flow.response.content.decode('utf-8', errors='ignore')
                                if text.strip() and len(text) < 1000:
                                    ctx.log.info(f"  [*] Texto (sem decrypt): {text}")
                                else:
                                    ctx.log.info(f"  [*] Hex dump (raw, primeiros 200 bytes):")
                                    hex_str = binascii.hexlify(flow.response.content[:200]).decode()
                                    for i in range(0, len(hex_str), 64):
                                        ctx.log.info(f"     {hex_str[i:i+64]}")
                            except Exception as e2:
                                ctx.log.warn(f"  [!] Erro ao processar resposta: {e2}")
                    
                except Exception as e:
                    ctx.log.warn(f"  [!] Erro ao processar resposta LoginGetDesc: {e}")
                
                ctx.log.info("=" * 60)
            
            # Interceptar resposta do bifrostAndroid para ver os campos
            if '/bifrostandroid' in flow.request.path.lower() or 'bifrostandroid' in flow.request.pretty_host.lower():
                ctx.log.info("=" * 60)
                ctx.log.info(f"DETECTADO: bifrostAndroid (RESPONSE) - Status: {flow.response.status_code}")
                ctx.log.info("=" * 60)
                
                try:
                    ctx.log.info(f"  [*] Status: {flow.response.status_code}")
                    ctx.log.info(f"  [*] Tamanho resposta: {len(flow.response.content)} bytes")
                    
                    if flow.response.status_code == 200 and flow.response.content:
                        # Tentar decriptar se for AES
                        try:
                            decrypted = aes_utils.decrypt_aes_cbc(flow.response.content)
                            ctx.log.info(f"  [*] Conteudo decriptado: {len(decrypted)} bytes")
                            
                            # Tentar decodificar como protobuf (vÃ¡rios tipos possÃ­veis)
                            from proto_utils import ProtobufUtils
                            proto_utils = ProtobufUtils()
                            
                            protobuf_decoded = False
                            for pb_type, pb_type_name in [
                                (LoginResNew_pb2.LoginRes, "LoginRes"),
                                (LoginResNew_pb2.MajorLoginRes, "MajorLoginRes"),
                            ]:
                                try:
                                    decoded = proto_utils.decode_protobuf(decrypted, pb_type)
                                    ctx.log.info(f"  [*] Decodificado como {pb_type_name}!")
                                    
                                    # Listar todos os campos
                                    ctx.log.info("  [*] Campos da resposta (ordenados por numero):")
                                    fields = list_all_protobuf_fields(decoded)
                                    
                                    # Processar campos: pode ser lista de dicts ou lista de strings
                                    field_list = []
                                    for field in fields:
                                        if isinstance(field, dict):
                                            field_num = field.get('number', 0)
                                            field_name = field.get('name', 'unknown')
                                            field_type = field.get('type', 'unknown')
                                            # Tentar obter o valor do campo
                                            try:
                                                field_value = getattr(decoded, field_name, None)
                                            except:
                                                field_value = None
                                            field_list.append((field_num, field_name, field_type, field_value))
                                        elif isinstance(field, str):
                                            # Fallback: apenas nome do campo
                                            try:
                                                field_value = getattr(decoded, field, None)
                                                field_list.append((0, field, 'unknown', field_value))
                                            except:
                                                pass
                                    
                                    # Ordenar por nÃºmero e exibir
                                    field_list.sort(key=lambda x: x[0])
                                    for field_num, field_name, field_type, field_value in field_list:
                                        value_str = str(field_value)[:100] if field_value is not None else "None"
                                        ctx.log.info(f"     #{field_num}: {field_name} ({field_type}) = {value_str}")
                                    
                                    protobuf_decoded = True
                                    break
                                except Exception as pb_e:
                                    ctx.log.debug(f"  [*] Falhou ao decodificar como {pb_type_name}: {pb_e}")
                            
                            if not protobuf_decoded:
                                # Tentar como JSON ou texto
                                try:
                                    import json
                                    json_data = json.loads(decrypted.decode('utf-8'))
                                    json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
                                    ctx.log.info("  [*] Conteudo JSON:")
                                    for line in json_str.split('\n'):
                                        ctx.log.info(f"     {line}")
                                    
                                    # Salvar JSON em arquivo
                                    save_json_to_file(json_data, flow.request.path, flow.request.pretty_host)
                                except:
                                    text = decrypted.decode('utf-8', errors='ignore')
                                    
                                    # Verificar se Ã© binÃ¡rio
                                    is_binary = False
                                    if text:
                                        printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text)
                                        if printable_ratio < 0.7:
                                            is_binary = True
                                    
                                    if is_binary:
                                        ctx.log.info(f"  [*] Dados binarios: {len(decrypted)} bytes")
                                        ctx.log.info(f"  [*] Hex dump (primeiros 200 bytes):")
                                        hex_str = binascii.hexlify(decrypted[:200]).decode()
                                        for i in range(0, len(hex_str), 64):
                                            ctx.log.info(f"     {hex_str[i:i+64]}")
                                    elif text.strip() and len(text) < 1000:
                                        ctx.log.info(f"  [*] Texto: {text}")
                                    else:
                                        ctx.log.info(f"  [*] Hex dump (primeiros 200 bytes):")
                                        hex_str = binascii.hexlify(decrypted[:200]).decode()
                                        for i in range(0, len(hex_str), 64):
                                            ctx.log.info(f"     {hex_str[i:i+64]}")
                        except Exception as decrypt_e:
                            # Se nÃ£o for AES, tentar como texto direto
                            try:
                                text = flow.response.content.decode('utf-8', errors='ignore')
                                
                                # Verificar se Ã© binÃ¡rio
                                is_binary = False
                                if text:
                                    printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text)
                                    if printable_ratio < 0.7:
                                        is_binary = True
                                
                                if is_binary:
                                    ctx.log.info(f"  [*] Dados binarios (raw): {len(flow.response.content)} bytes")
                                    ctx.log.info(f"  [*] Hex dump (primeiros 200 bytes):")
                                    hex_str = binascii.hexlify(flow.response.content[:200]).decode()
                                    for i in range(0, len(hex_str), 64):
                                        ctx.log.info(f"     {hex_str[i:i+64]}")
                                elif text.strip() and len(text) < 1000:
                                    ctx.log.info(f"  [*] Texto (sem decrypt): {text}")
                                else:
                                    ctx.log.info(f"  [*] Hex dump (raw, primeiros 200 bytes):")
                                    hex_str = binascii.hexlify(flow.response.content[:200]).decode()
                                    for i in range(0, len(hex_str), 64):
                                        ctx.log.info(f"     {hex_str[i:i+64]}")
                            except Exception as e2:
                                ctx.log.warn(f"  [!] Erro ao processar resposta: {e2}")
                    
                except Exception as e:
                    ctx.log.warn(f"  [!] Erro ao processar resposta bifrostAndroid: {e}")
                
                ctx.log.info("=" * 60)
            
            self._handle_login_response(flow, client_ip)
        except Exception as e:
            ctx.log.error(f"Response error: {e}")

    def _handle_login_response(self, flow: http.HTTPFlow, client_ip: str) -> None:
        # Only auth UID for login responses
        if not flow.metadata.get("is_login_request", False):
            return

        # Force cache initialization if not done
        if not cache_initialized:
            try:
                fetch_uids()
            except Exception as load_e:
                ctx.log.error(f"Force load error: {load_e}")

        try:
            # Method 1: Extract UID from login response
            uid_found = False
            try:
                decoded_body = proto_utils.decode_protobuf(flow.response.content, Login_pb2.getUID)
                if hasattr(decoded_body, 'uid'):
                    actual_uid = str(decoded_body.uid)
                    ctx.log.info(f"SUCCESS: UID {actual_uid} from getUID")
                    uid_found = True
            except Exception as uid_e:
                ctx.log.info(f"getUID decode failed: {uid_e}")
            if not uid_found:
                try:
                    decoded_body = proto_utils.decode_protobuf(flow.response.content, LoginResNew_pb2.MajorLoginRes)
                    if hasattr(decoded_body, 'uid'):
                        actual_uid = str(decoded_body.uid)
                        ctx.log.info(f"SUCCESS: UID {actual_uid} from MajorLoginRes")
                        uid_found = True
                except Exception as ml_e:
                    ctx.log.info(f"MajorLoginRes decode failed: {ml_e}")
            if not uid_found:
                try:
                    decoded_body = proto_utils.decode_protobuf(flow.response.content, LoginResNew_pb2.LoginRes)
                    if hasattr(decoded_body, 'uid'):
                        actual_uid = str(decoded_body.uid)
                        ctx.log.info(f"SUCCESS: UID {actual_uid} from LoginRes")
                        uid_found = True
                except Exception as lr_e:
                    ctx.log.info(f"LoginRes decode failed: {lr_e}")
            if not uid_found:
                ctx.log.info("No UID found in response, allowing login")
                return
            
            is_authorized, needs_message, status_info = check_uid_exists(actual_uid, client_ip)
            
            if flow.metadata.get("is_major_login", False) and not is_authorized:
                ctx.log.warn(f"Blocked unauthorized UID {actual_uid}")
                
                # Determinar mensagem baseada no status
                error_message = WHITELIST_MSG.format(uid=actual_uid).encode()
                
                if status_info:
                    status = status_info.get('status', 'unknown')
                    
                    if status == 'expired':
                        expired_at = status_info.get('expired_at', 'N/A')
                        error_message = WHITELIST_MSG_EXPIRED.format(
                            uid=actual_uid,
                            expired_at=expired_at
                        ).encode()
                    elif status == 'banned':
                        banned_until = status_info.get('banned_until', 'N/A')
                        error_message = WHITELIST_MSG_BANNED.format(
                            uid=actual_uid,
                            banned_until=banned_until
                        ).encode()
                    elif status == 'paused':
                        paused_until = status_info.get('paused_until', 'N/A')
                        error_message = WHITELIST_MSG_PAUSED.format(
                            uid=actual_uid,
                            paused_until=paused_until
                        ).encode()
                    elif status == 'maintenance':
                        maintenance_until = status_info.get('maintenance_until', 'N/A')
                        error_message = WHITELIST_MSG_MAINTENANCE.format(
                            uid=actual_uid,
                            maintenance_until=maintenance_until
                        ).encode()
                
                flow.response.content = error_message
                flow.response.status_code = 400
                flow.response.headers["Content-Type"] = "text/plain"
                return
            
            ctx.log.info(f"ALLOWED: UID {actual_uid}")
            return
            
            if flow.metadata.get("is_major_login", False) and not is_authorized:
                ctx.log.warn(f"Blocked unauthorized UID {actual_uid}")
                
                # Determinar mensagem baseada no status
                error_message = WHITELIST_MSG.format(uid=actual_uid).encode()
                
                if status_info:
                    status = status_info.get('status', 'unknown')
                    
                    if status == 'expired':
                        expired_at = status_info.get('expired_at', 'N/A')
                        error_message = WHITELIST_MSG_EXPIRED.format(
                            uid=actual_uid,
                            expired_at=expired_at
                        ).encode()
                    elif status == 'banned':
                        banned_until = status_info.get('banned_until', 'N/A')
                        error_message = WHITELIST_MSG_BANNED.format(
                            uid=actual_uid,
                            banned_until=banned_until
                        ).encode()
                    elif status == 'paused':
                        paused_until = status_info.get('paused_until', 'N/A')
                        error_message = WHITELIST_MSG_PAUSED.format(
                            uid=actual_uid,
                            paused_until=paused_until
                        ).encode()
                    elif status == 'maintenance':
                        maintenance_until = status_info.get('maintenance_until', 'N/A')
                        error_message = WHITELIST_MSG_MAINTENANCE.format(
                            uid=actual_uid,
                            maintenance_until=maintenance_until
                        ).encode()
                
                flow.response.content = error_message
                flow.response.status_code = 400
                flow.response.headers["Content-Type"] = "text/plain"
                return
            
            ctx.log.info(f"ALLOWED: UID {actual_uid}")
            return

        except Exception as e:
            ctx.log.error(f"Critical login response error: {e}")

addons = [LoginInterceptor()]

if __name__ == "__main__":
    import sys
    
    # Verifica se a porta estÃ¡ disponÃ­vel
    actual_port = LISTEN_PORT
    if not is_port_available(LISTEN_PORT):
        print(f"âš ï¸  Porta {LISTEN_PORT} estÃ¡ em uso!")
        print("ðŸ” Procurando porta alternativa...")
        alternative_port = find_available_port(LISTEN_PORT)
        if alternative_port:
            actual_port = alternative_port
            print(f"âœ… Usando porta alternativa: {actual_port}")
        else:
            print(f"âŒ NÃ£o foi possÃ­vel encontrar uma porta disponÃ­vel.")
            print(f"ðŸ’¡ Feche outros programas usando a porta {LISTEN_PORT} ou altere LISTEN_PORT no cÃ³digo.")
            sys.exit(1)
    
    sys.argv = [
        "mitmdump",
        "-s", __file__,
        "-p", str(actual_port),
        "--listen-host", LISTEN_HOST,
        "--set", "block_global=false",
        "--set", "ssl_insecure=true",
    ]
    local_ip = get_local_ip()
    public_ip = get_public_ip()
    print("=" * 60)
    print(f"ðŸš€ MITM Proxy em execuÃ§Ã£o")
    print("=" * 60)
    print(f"ðŸ“¡ Ouvindo em: {LISTEN_HOST}:{actual_port}")
    print(f"ðŸ“ Arquivo UID: {UID_FILE}")
    print("-" * 60)
    print("ðŸŒ ConfiguraÃ§Ã£o para compartilhar com amigos:")
    print("")
    print("   ðŸ“ IP LOCAL (mesma rede WiFi):")
    print(f"      Host: {local_ip}")
    print(f"      Porta: {actual_port}")
    print("")
    if public_ip:
        print("   ðŸŒ IP PÃšBLICO (redes diferentes - via internet):")
        print(f"      Host: {public_ip}")
        print(f"      Porta: {actual_port}")
        print("      âš ï¸  Nota: Precisa configurar port forwarding no roteador")
    else:
        print("   ðŸŒ IP PÃºblico: NÃ£o foi possÃ­vel obter")
    print("")
    print("   ðŸ“‹ Para seu amigo configurar:")
    print(f"      â€¢ Se estiver na mesma rede: {local_ip}:{actual_port}")
    if public_ip:
        print(f"      â€¢ Se estiver em outra rede: {public_ip}:{actual_port} (requer port forwarding)")
    print("=" * 60)
    try:
        mitmdump()
    except KeyboardInterrupt:
        print("Shutdown...")

