"""
Static Analyzer Implementation - Extract strings, PE info, capabilities
"""
import re
import pefile
import lief
from typing import Dict, Any, List, Optional
from pathlib import Path


class StaticAnalyzer:
    """Static analyzer để extract strings, PE info từ files"""
    
    def __init__(self):
        self.min_string_length = 4
        self.max_string_length = 200
        
        # Patterns để detect suspicious strings
        self.suspicious_patterns = [
            r'http[s]?://[^\s]+',  # URLs
            r'ftp://[^\s]+',  # FTP URLs
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
            r'[A-Z]:\\[^\\s]+',  # Windows paths
            r'\\\\[^\\s]+',  # UNC paths
            r'HKEY_[A-Z_]+',  # Registry keys
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[0-9a-fA-F]{32,}',  # Long hex strings (hashes)
            r'cmd\.exe|powershell|wscript|cscript',  # Command execution
            r'CreateRemoteThread|VirtualAlloc|WriteProcessMemory',  # API calls
            r'base64|Base64',  # Encoding
            r'password|pwd|passwd|secret|key',  # Credentials
            r'\.dll|\.exe|\.sys|\.bat|\.ps1',  # Executable extensions
        ]
        
        # Suspicious keywords
        self.suspicious_keywords = [
            'malware', 'trojan', 'virus', 'backdoor', 'keylogger',
            'ransomware', 'spyware', 'rootkit', 'botnet', 'exploit',
            'payload', 'shellcode', 'inject', 'hook', 'bypass',
            'disable', 'delete', 'kill', 'terminate', 'remove',
            'registry', 'startup', 'autostart', 'persistence',
            'crypto', 'encrypt', 'decrypt', 'ransom', 'bitcoin',
            'c2', 'command', 'control', 'server', 'connect',
            'download', 'upload', 'exfiltrate', 'steal', 'collect'
        ]
    
    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """
        Phân tích file và extract thông tin
        
        Returns:
            Dict với keys: hashes, yara_matches, pe_info, strings, capabilities
        """
        filepath_obj = Path(filepath)
        if not filepath_obj.exists():
            return self._empty_result()
        
        try:
            # Read file content
            with open(filepath, 'rb') as f:
                file_content = f.read()
            
            result = {
                "hashes": self._calculate_hashes(filepath),
                "yara_matches": [],  # Sẽ được fill bởi YaraService
                "pe_info": None,
                "strings": [],
                "capabilities": []
            }
            
            # Extract strings
            result["strings"] = self._extract_strings(file_content)
            
            # Try to parse as PE file
            try:
                pe_info = self._analyze_pe_file(filepath, file_content)
                if pe_info:
                    result["pe_info"] = pe_info
                    result["capabilities"] = self._extract_capabilities(pe_info)
            except Exception as e:
                print(f"[StaticAnalyzer] Not a PE file or error parsing: {e}")
            
            return result
            
        except Exception as e:
            print(f"[StaticAnalyzer] Error analyzing {filepath}: {e}")
            import traceback
            traceback.print_exc()
            return self._empty_result()
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure"""
        return {
            "hashes": {"sha256": None, "md5": None},
            "yara_matches": [],
            "pe_info": None,
            "strings": [],
            "capabilities": []
        }
    
    def _calculate_hashes(self, filepath: str) -> Dict[str, Optional[str]]:
        """Calculate file hashes"""
        try:
            import hashlib
            
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
            
            return {
                "sha256": sha256_hash.hexdigest(),
                "md5": md5_hash.hexdigest()
            }
        except Exception as e:
            print(f"[StaticAnalyzer] Error calculating hashes: {e}")
            return {"sha256": None, "md5": None}
    
    def _extract_strings(self, content: bytes) -> List[str]:
        """
        Extract printable strings từ binary content
        Filter các strings đáng nghi ngờ
        """
        strings = []
        seen = set()
        
        # Extract ASCII strings (4+ characters)
        current_string = []
        for byte in content:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= self.min_string_length:
                    s = ''.join(current_string)
                    if len(s) <= self.max_string_length and s not in seen:
                        seen.add(s)
                        # Check if suspicious
                        if self._is_suspicious_string(s):
                            strings.append(s)
                current_string = []
        
        # Check last string
        if len(current_string) >= self.min_string_length:
            s = ''.join(current_string)
            if len(s) <= self.max_string_length and s not in seen:
                seen.add(s)
                if self._is_suspicious_string(s):
                    strings.append(s)
        
        # Extract Unicode strings (UTF-16 LE)
        try:
            unicode_content = content.decode('utf-16le', errors='ignore')
            for match in re.finditer(r'[\x20-\x7E]{4,}', unicode_content):
                s = match.group()
                if len(s) <= self.max_string_length and s not in seen:
                    seen.add(s)
                    if self._is_suspicious_string(s):
                        strings.append(s)
        except:
            pass
        
        # Sort by length (longer strings first) and limit
        strings.sort(key=len, reverse=True)
        return strings[:100]  # Limit to 100 most suspicious strings
    
    def _is_suspicious_string(self, s: str) -> bool:
        """Check if string is suspicious"""
        s_lower = s.lower()
        
        # Check patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, s, re.IGNORECASE):
                return True
        
        # Check keywords
        for keyword in self.suspicious_keywords:
            if keyword in s_lower:
                return True
        
        # Check for high entropy (random-looking strings)
        if len(s) >= 16 and self._has_high_entropy(s):
            return True
        
        return False
    
    def _has_high_entropy(self, s: str) -> bool:
        """Check if string has high entropy (random-looking)"""
        import math
        if not s:
            return False
        
        # Calculate Shannon entropy
        entropy = 0
        for char in set(s):
            p = s.count(char) / len(s)
            if p > 0:
                entropy -= p * math.log2(p)
        
        # High entropy threshold (random strings have ~4.5-5.0 entropy for base64)
        return entropy > 4.0
    
    def _analyze_pe_file(self, filepath: str, content: bytes) -> Optional[Dict[str, Any]]:
        """Analyze PE file structure"""
        try:
            pe = pefile.PE(filepath, fast_load=True)
            
            pe_info = {
                "machine": pe.FILE_HEADER.Machine,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "sections": [],
                "imports": [],
                "exports": [],
                "suspicious_features": []
            }
            
            # Sections
            for section in pe.sections:
                try:
                    section_data = {
                        "name": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                        "virtual_address": section.VirtualAddress,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": self._calculate_entropy(section.get_data())
                    }
                    pe_info["sections"].append(section_data)
                    
                    # Check for high entropy (packed)
                    if section_data["entropy"] > 7.0:
                        pe_info["suspicious_features"].append("High entropy section (possibly packed)")
                except:
                    continue
            
            # Imports
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        for imp in entry.imports:
                            if imp.name:
                                pe_info["imports"].append({
                                    "dll": dll_name,
                                    "function": imp.name.decode('utf-8', errors='ignore')
                                })
            except:
                pass
            
            # Exports
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            pe_info["exports"].append(exp.name.decode('utf-8', errors='ignore'))
            except:
                pass
            
            pe.close()
            return pe_info
            
        except pefile.PEFormatError:
            return None
        except Exception as e:
            print(f"[StaticAnalyzer] Error analyzing PE: {e}")
            return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        import math
        if not data:
            return 0.0
        
        entropy = 0.0
        for byte in range(256):
            count = data.count(byte)
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _extract_capabilities(self, pe_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract capabilities from PE info"""
        capabilities = []
        
        if not pe_info or "imports" not in pe_info:
            return capabilities
        
        # Network capabilities
        network_dlls = ['ws2_32.dll', 'wininet.dll', 'winhttp.dll', 'urlmon.dll']
        network_functions = ['socket', 'connect', 'send', 'recv', 'http', 'download']
        
        # File system capabilities
        file_dlls = ['kernel32.dll']
        file_functions = ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'CopyFile']
        
        # Registry capabilities
        registry_functions = ['RegOpenKey', 'RegSetValue', 'RegCreateKey', 'RegDeleteKey']
        
        # Process manipulation
        process_functions = ['CreateProcess', 'CreateRemoteThread', 'OpenProcess', 'TerminateProcess']
        
        imports = pe_info.get("imports", [])
        
        # Check for network
        has_network = any(
            any(net_dll in imp.get("dll", "").lower() for net_dll in network_dlls) or
            any(net_func in imp.get("function", "").lower() for net_func in network_functions)
            for imp in imports
        )
        if has_network:
            capabilities.append({"type": "network", "description": "Network communication"})
        
        # Check for file operations
        has_file_ops = any(
            any(file_func in imp.get("function", "").lower() for file_func in file_functions)
            for imp in imports
        )
        if has_file_ops:
            capabilities.append({"type": "file_system", "description": "File system operations"})
        
        # Check for registry
        has_registry = any(
            any(reg_func in imp.get("function", "").lower() for reg_func in registry_functions)
            for imp in imports
        )
        if has_registry:
            capabilities.append({"type": "registry", "description": "Registry manipulation"})
        
        # Check for process manipulation
        has_process = any(
            any(proc_func in imp.get("function", "").lower() for proc_func in process_functions)
            for imp in imports
        )
        if has_process:
            capabilities.append({"type": "process_manipulation", "description": "Process manipulation"})
        
        return capabilities

