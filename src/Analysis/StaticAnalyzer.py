"""
Static Analysis Module - Phân tích tĩnh nâng cao
Bao gồm: YARA, Hash, PE Analysis, Strings, Capa
"""
import os
import hashlib
from typing import Dict, List, Optional, Any
import yara

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

# Capa integration - Cần cài đặt riêng
# Cài đặt: pip install git+https://github.com/mandiant/capa.git#subdirectory=capa
CAPA_AVAILABLE = False
try:
    import capa.main
    from capa.main import get_rules, find_capabilities
    CAPA_AVAILABLE = True
except ImportError:
    CAPA_AVAILABLE = False
    # Capa không bắt buộc, có thể bỏ qua
    pass


class StaticAnalyzer:
    """Phân tích tĩnh nâng cao cho malware"""
    
    def __init__(self, yara_rules=None):
        self.yara_rules = yara_rules
        self.pefile_available = PEFILE_AVAILABLE
        self.capa_available = CAPA_AVAILABLE
    
    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """
        Phân tích toàn diện một file
        
        Returns:
            Dict chứa kết quả phân tích:
            - hashes: SHA256, MD5, SHA1
            - yara_matches: YARA rule matches
            - pe_info: PE file metadata (nếu là PE)
            - strings: Suspicious strings
            - capabilities: Capa detected capabilities
        """
        results = {
            "filepath": filepath,
            "hashes": self._calculate_hashes(filepath),
            "yara_matches": [],
            "pe_info": None,
            "strings": [],
            "capabilities": [],
            "file_size": os.path.getsize(filepath) if os.path.exists(filepath) else 0,
            "file_type": self._detect_file_type(filepath)
        }
        
        # YARA Analysis
        if self.yara_rules:
            results["yara_matches"] = self._yara_scan(filepath)
        
        # PE Analysis (cho Windows executables)
        if self.pefile_available and results["file_type"] == "PE":
            results["pe_info"] = self._analyze_pe(filepath)
        
        # Strings Analysis
        results["strings"] = self._extract_strings(filepath)
        
        # Capa Analysis (nếu có)
        if self.capa_available and results["file_type"] == "PE":
            results["capabilities"] = self._capa_analysis(filepath)
        
        return results
    
    def _calculate_hashes(self, filepath: str) -> Dict[str, str]:
        """Tính các loại hash: SHA256, MD5, SHA1"""
        hashes = {
            "sha256": None,
            "md5": None,
            "sha1": None
        }
        
        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    sha256.update(chunk)
                    md5.update(chunk)
                    sha1.update(chunk)
            
            hashes["sha256"] = sha256.hexdigest()
            hashes["md5"] = md5.hexdigest()
            hashes["sha1"] = sha1.hexdigest()
        except Exception as e:
            print(f"Error calculating hashes: {e}")
        
        return hashes
    
    def _yara_scan(self, filepath: str) -> List[Dict[str, Any]]:
        """Quét YARA rules"""
        matches = []
        
        if not self.yara_rules:
            return matches
        
        try:
            yara_matches = self.yara_rules.match(filepath)
            for match in yara_matches:
                match_info = {
                    "rule": match.rule,
                    "tags": list(match.tags) if hasattr(match, 'tags') else [],
                    "meta": dict(match.meta) if hasattr(match, 'meta') else {},
                    "strings": []
                }
                
                # Extract matched strings
                if hasattr(match, 'strings'):
                    for string_match in match.strings:
                        match_info["strings"].append({
                            "identifier": string_match[1],
                            "offset": string_match[0]
                        })
                
                matches.append(match_info)
        except Exception as e:
            print(f"YARA scan error: {e}")
        
        return matches
    
    def _detect_file_type(self, filepath: str) -> str:
        """Phát hiện loại file"""
        try:
            with open(filepath, "rb") as f:
                magic = f.read(4)
                
                if magic[:2] == b'MZ':
                    return "PE"
                elif magic[:4] == b'\x7fELF':
                    return "ELF"
                elif magic[:4] == b'\xca\xfe\xba\xbe' or magic[:2] == b'PK':
                    return "JAR"
                elif magic[:4] == b'%PDF':
                    return "PDF"
                else:
                    return "UNKNOWN"
        except Exception:
            return "UNKNOWN"
    
    def _analyze_pe(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Phân tích PE file"""
        if not self.pefile_available:
            return None
        
        try:
            pe = pefile.PE(filepath)
            
            pe_info = {
                "machine": pe.FILE_HEADER.Machine,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "sections": [],
                "imports": [],
                "exports": [],
                "suspicious_features": []
            }
            
            # Extract sections
            for section in pe.sections:
                section_info = {
                    "name": section.Name.decode('utf-8').rstrip('\x00'),
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": section.get_entropy()
                }
                pe_info["sections"].append(section_info)
                
                # Detect suspicious entropy (packed)
                if section_info["entropy"] > 7.0:
                    pe_info["suspicious_features"].append("High entropy section (possibly packed)")
            
            # Extract imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8')
                    for imp in entry.imports:
                        if imp.name:
                            pe_info["imports"].append({
                                "dll": dll_name,
                                "function": imp.name.decode('utf-8')
                            })
            
            # Extract exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        pe_info["exports"].append(exp.name.decode('utf-8'))
            
            pe.close()
            return pe_info
            
        except Exception as e:
            print(f"PE analysis error: {e}")
            return None
    
    def _extract_strings(self, filepath: str, min_length: int = 4) -> List[str]:
        """Trích xuất strings từ file"""
        strings = []
        
        try:
            with open(filepath, "rb") as f:
                data = f.read()
                
            current_string = b""
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string.decode('utf-8', errors='ignore'))
                    current_string = b""
            
            # Check for suspicious strings
            suspicious_keywords = [
                "cmd.exe", "powershell", "wscript", "cscript",
                "http://", "https://", "registry", "shellcode",
                "base64", "decode", "encrypt", "decrypt"
            ]
            
            suspicious_strings = [
                s for s in strings 
                if any(keyword.lower() in s.lower() for keyword in suspicious_keywords)
            ]
            
            return suspicious_strings[:100]  # Limit to 100 strings
            
        except Exception as e:
            print(f"String extraction error: {e}")
            return []
    
    def _capa_analysis(self, filepath: str) -> List[Dict[str, Any]]:
        """Phân tích capabilities với Capa"""
        if not self.capa_available:
            return []
        
        try:
            # Capa cần được gọi qua command line hoặc sử dụng đúng API
            # Tạm thời return empty, sẽ implement sau khi cài đặt capa
            import subprocess
            import json
            import tempfile
            
            # Thử gọi capa qua command line
            output_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            output_file.close()
            
            result = subprocess.run(
                ['capa', '-j', filepath, '-o', output_file.name],
                capture_output=True,
                timeout=60
            )
            
            if result.returncode == 0 and os.path.exists(output_file.name):
                with open(output_file.name, 'r') as f:
                    capa_result = json.load(f)
                
                os.unlink(output_file.name)
                
                # Parse capa results
                capabilities = []
                for rule_name, rule_info in capa_result.get('rules', {}).items():
                    capabilities.append({
                        "rule": rule_name,
                        "namespace": rule_info.get('namespace', ''),
                        "description": rule_info.get('meta', {}).get('description', ''),
                        "att&ck": rule_info.get('meta', {}).get('att&ck', [])
                    })
                
                return capabilities
            else:
                if os.path.exists(output_file.name):
                    os.unlink(output_file.name)
                return []
                
        except FileNotFoundError:
            # Capa không được cài đặt
            return []
        except Exception as e:
            print(f"Capa analysis error: {e}")
            return []


def create_static_analyzer(yara_rules_path: str = None) -> StaticAnalyzer:
    """Factory function để tạo StaticAnalyzer"""
    yara_rules = None
    
    if yara_rules_path and os.path.exists(yara_rules_path):
        try:
            yara_rules = yara.compile(filepath=yara_rules_path)
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
    
    return StaticAnalyzer(yara_rules=yara_rules)

