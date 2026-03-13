"""
Protobuf Field Validator
Valida se os campos usados no spoofing ainda existem nos arquivos .proto
"""
import os
import re
from typing import Dict, Set, Tuple, List
from mitmproxy import ctx

# Mapeamento dos campos que usamos no código para os campos do protobuf
FIELD_MAPPING = {
    # Campos conhecidos do LoginReq (baseado em Login.proto)
    'system_software': ('system_software', 8),  # Nome no proto: system_software, Número: 8
    'system_hardware': ('system_hardware', 9),
    'telecom_operator': ('telecom_operator', 10),
    'network_type': ('network_type', 11),
    'screen_width': ('screen_width', 12),
    'screen_height': ('screen_height', 13),
    'screen_dpi': ('screen_dpi', 14),
    'cpu_hardware': ('cpu_hardware', 15),
    'memory_mb': ('memory_mb', 16),
    'gl_renderer': ('gl_renderer', 17),
    'gl_version': ('gl_version', 18),
    'device_id': ('device_id', 19),
    'client_ip': ('client_ip', 20),
    'language': ('language', 21),
    'device_type': ('device_type', 24),
    'device_model': ('device_model', 25),
    'cpu_architecture': ('cpu_architecture', 81),
    'client_version_code': ('client_version_code', 83),
    'system_graphics_api': ('system_graphics_api', 86),
    'library_path': ('library_path', 74),
    'signature_md5': ('signature_md5', 57),
}

# Campos que podem ter nomes diferentes em diferentes versões
OPTIONAL_FIELDS = {
    'os_info': ['system_software', 'os_version'],
    'cpu_info': ['cpu_hardware', 'cpu_info'],
    'total_ram': ['memory_mb', 'total_ram'],
    'gpu': ['gl_renderer', 'gpu'],
    'gpu_version': ['gl_version', 'gpu_version'],
    'apk_signature': ['signature_md5', 'apk_signature'],
    'lib_path': ['library_path', 'lib_path'],
    'arch': ['cpu_architecture', 'arch'],
}


def parse_proto_file(proto_path: str) -> Dict[str, int]:
    """
    Faz parse de um arquivo .proto e retorna um dicionário {nome_campo: numero_campo}
    """
    if not os.path.exists(proto_path):
        ctx.log.warn(f"Proto file não encontrado: {proto_path}")
        return {}
    
    field_map = {}
    
    try:
        with open(proto_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Regex para encontrar campos: tipo nome = numero;
        pattern = r'(\w+)\s+(\w+)\s*=\s*(\d+);'
        matches = re.findall(pattern, content)
        
        for match in matches:
            field_type, field_name, field_number = match
            field_map[field_name] = int(field_number)
            
        ctx.log.debug(f"Parsed {len(field_map)} fields from {proto_path}")
        
    except Exception as e:
        ctx.log.error(f"Erro ao fazer parse de {proto_path}: {e}")
    
    return field_map


def validate_protobuf_message(message_obj, required_fields: List[str]) -> Tuple[bool, List[str]]:
    """
    Valida se uma mensagem protobuf contém todos os campos requeridos
    
    Returns:
        (is_valid, missing_fields)
    """
    missing_fields = []
    
    for field in required_fields:
        if not hasattr(message_obj, field):
            missing_fields.append(field)
    
    is_valid = len(missing_fields) == 0
    
    if not is_valid and is_debug_enabled():
        ctx.log.warn(f"⚠️  Campos faltando na mensagem protobuf: {missing_fields}")
    
    return is_valid, missing_fields


def validate_spoofing_fields(proto_dir: str = ".") -> Dict[str, any]:
    """
    Valida se os campos usados no spoofing existem nos arquivos .proto
    
    Returns:
        Dict com resultados da validação
    """
    results = {
        'valid': True,
        'warnings': [],
        'errors': [],
        'checked_files': [],
        'missing_fields': {},
        'field_changes': {}
    }
    
    proto_files = [
        'Login.proto',
        'LoginRes.proto',
        'LoginResNew.proto'
    ]
    
    for proto_file in proto_files:
        proto_path = os.path.join(proto_dir, proto_file)
        if os.path.exists(proto_path):
            results['checked_files'].append(proto_file)
            field_map = parse_proto_file(proto_path)
            
            # Verificar campos conhecidos
            for our_field, (proto_field, expected_number) in FIELD_MAPPING.items():
                if proto_field not in field_map:
                    results['errors'].append(
                        f"{proto_file}: Campo '{proto_field}' não encontrado!"
                    )
                    results['valid'] = False
                elif field_map[proto_field] != expected_number:
                    results['field_changes'][proto_field] = {
                        'old': expected_number,
                        'new': field_map[proto_field],
                        'file': proto_file
                    }
                    results['warnings'].append(
                        f"{proto_file}: Campo '{proto_field}' mudou número de {expected_number} para {field_map[proto_field]}!"
                    )
    
    return results


def safe_set_protobuf_field(message_obj, field_name: str, value: any, alternative_names: List[str] = None) -> bool:
    """
    Tenta definir um campo no protobuf de forma segura, verificando múltiplos nomes possíveis
    
    Returns:
        True se conseguiu definir o campo, False caso contrário
    """
    # Tenta o nome exato primeiro
    if hasattr(message_obj, field_name):
        try:
            setattr(message_obj, field_name, value)
            return True
        except Exception as e:
            ctx.log.debug(f"Erro ao definir {field_name}: {e}")
            return False
    
    # Tenta nomes alternativos
    if alternative_names:
        for alt_name in alternative_names:
            if hasattr(message_obj, alt_name):
                try:
                    setattr(message_obj, alt_name, value)
                    ctx.log.debug(f"Usando campo alternativo '{alt_name}' para '{field_name}'")
                    return True
                except Exception as e:
                    ctx.log.debug(f"Erro ao definir {alt_name}: {e}")
    
    # Campo não encontrado
    if is_debug_enabled():
        ctx.log.debug(f"Campo '{field_name}' não encontrado na mensagem protobuf")
    
    return False


def is_debug_enabled():
    """Check if debug mode is enabled via external file"""
    try:
        if os.path.exists("debug_enabled.txt"):
            with open("debug_enabled.txt", 'r') as f:
                content = f.read().strip().lower()
                return content in ['true', '1', 'yes', 'on']
    except:
        pass
    return False


def check_proto_changes_on_startup():
    """
    Verifica mudanças nos arquivos .proto ao iniciar o bypass
    """
    results = validate_spoofing_fields()
    
    if not results['valid']:
        ctx.log.error("⚠️  VALIDAÇÃO DE PROTOBUF FALHOU!")
        for error in results['errors']:
            ctx.log.error(f"  ❌ {error}")
    
    if results['warnings']:
        ctx.log.warn("⚠️  AVISOS DE VALIDAÇÃO:")
        for warning in results['warnings']:
            ctx.log.warn(f"  ⚠️  {warning}")
    
    if results['field_changes']:
        ctx.log.warn("⚠️  CAMPOS MUDARAM NÚMEROS:")
        for field, change in results['field_changes'].items():
            ctx.log.warn(f"  {field}: {change['old']} → {change['new']} ({change['file']})")
    
    if results['valid'] and not results['warnings']:
        ctx.log.info("✅ Validação de protobuf: OK")
    
    return results



