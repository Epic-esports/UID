#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script standalone para verificar mudanças nos arquivos .proto
Execute: python check_proto_changes.py
"""
import os
import sys
import re
from typing import Dict

# Mapeamento esperado dos campos
EXPECTED_FIELDS = {
    'LoginReq': {
        'system_software': 8,
        'system_hardware': 9,
        'telecom_operator': 10,
        'network_type': 11,
        'screen_width': 12,
        'screen_height': 13,
        'screen_dpi': 14,
        'cpu_hardware': 15,
        'memory_mb': 16,
        'gl_renderer': 17,
        'gl_version': 18,
        'device_id': 19,
        'client_ip': 20,
        'language': 21,
        'device_type': 24,
        'device_model': 25,
        'library_path': 74,
        'signature_md5': 57,
        'cpu_architecture': 81,
        'client_version_code': 83,
        'system_graphics_api': 86,
    }
}


def parse_proto_file(proto_path: str) -> Dict[str, Dict[str, int]]:
    """Parse arquivo .proto e retorna campos por mensagem"""
    if not os.path.exists(proto_path):
        return {}
    
    result = {}
    
    try:
        with open(proto_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Encontrar mensagens
        message_pattern = r'message\s+(\w+)\s*\{'
        messages = re.finditer(message_pattern, content)
        
        for msg_match in messages:
            msg_name = msg_match.group(1)
            msg_start = msg_match.end()
            
            # Encontrar fim da mensagem
            brace_count = 1
            msg_end = msg_start
            for i, char in enumerate(content[msg_start:], msg_start):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        msg_end = i
                        break
            
            msg_content = content[msg_start:msg_end]
            
            # Extrair campos da mensagem
            fields = {}
            field_pattern = r'(\w+)\s+(\w+)\s*=\s*(\d+);'
            matches = re.finditer(field_pattern, msg_content)
            
            for match in matches:
                field_type, field_name, field_number = match.groups()
                fields[field_name] = int(field_number)
            
            result[msg_name] = fields
            
    except Exception as e:
        print(f"[ERRO] Erro ao fazer parse de {proto_path}: {e}")
    
    return result


def check_proto_files(proto_dir: str = ".") -> Dict:
    """Verifica mudanças nos arquivos .proto"""
    results = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'field_changes': {},
        'missing_fields': {},
        'new_fields': {}
    }
    
    proto_files = ['Login.proto']
    
    print("=" * 60)
    print("[*] Verificando arquivos .proto...")
    print("=" * 60)
    
    for proto_file in proto_files:
        proto_path = os.path.join(proto_dir, proto_file)
        
        if not os.path.exists(proto_path):
            print(f"[!] Arquivo nao encontrado: {proto_path}")
            continue
        
        print(f"\n[*] Analisando: {proto_file}")
        
        parsed = parse_proto_file(proto_path)
        
        # Verificar LoginReq
        if 'LoginReq' in parsed and 'LoginReq' in EXPECTED_FIELDS:
            actual_fields = parsed['LoginReq']
            expected_fields = EXPECTED_FIELDS['LoginReq']
            
            # Verificar campos faltando
            missing = set(expected_fields.keys()) - set(actual_fields.keys())
            if missing:
                results['missing_fields']['LoginReq'] = list(missing)
                results['errors'].append(f"Campos faltando em LoginReq: {missing}")
                results['valid'] = False
                print(f"  [X] Campos faltando: {missing}")
            
            # Verificar mudanças de números
            for field_name, expected_number in expected_fields.items():
                if field_name in actual_fields:
                    actual_number = actual_fields[field_name]
                    if actual_number != expected_number:
                        results['field_changes'][field_name] = {
                            'old': expected_number,
                            'new': actual_number,
                            'file': proto_file
                        }
                        results['warnings'].append(
                            f"{field_name}: numero mudou de {expected_number} para {actual_number}"
                        )
                        print(f"  [!] {field_name}: {expected_number} -> {actual_number}")
            
            # Verificar novos campos
            new = set(actual_fields.keys()) - set(expected_fields.keys())
            if new:
                results['new_fields']['LoginReq'] = list(new)
                print(f"  [+] Novos campos encontrados: {new}")
        
        print(f"  [*] Total de campos: {len(parsed.get('LoginReq', {}))}")
    
    print("\n" + "=" * 60)
    
    # Resumo
    if results['valid'] and not results['warnings']:
        print("[OK] VALIDACAO OK - Nenhuma mudanca detectada!")
    else:
        if results['errors']:
            print(f"[ERRO] {len(results['errors'])} ERRO(S) encontrado(s):")
            for error in results['errors']:
                print(f"   - {error}")
        
        if results['warnings']:
            print(f"[AVISO] {len(results['warnings'])} AVISO(S):")
            for warning in results['warnings']:
                print(f"   - {warning}")
    
    print("=" * 60)
    
    return results


if __name__ == "__main__":
    print("Protobuf Validator - Verificador de Mudancas\n")
    
    proto_dir = os.path.dirname(os.path.abspath(__file__))
    results = check_proto_files(proto_dir)
    
    # Retornar código de saída baseado em erros
    sys.exit(0 if results['valid'] else 1)
