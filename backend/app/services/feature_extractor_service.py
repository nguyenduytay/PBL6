"""
Feature Extractor Service - Trích xuất features cho ML training
"""
import json
import hashlib
from typing import Dict, Any, List, Optional
from pathlib import Path


class FeatureExtractorService:
    """Service để trích xuất features từ analysis data cho ML"""
    
    def extract_features(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trích xuất features từ analysis data
        
        Args:
            analysis_data: Dữ liệu analysis từ database
            
        Returns:
            Dict chứa feature vector
        """
        features = {}
        
        # 1. File Features
        features['file_size'] = analysis_data.get('file_size', 0) or 0
        features['file_size_log'] = self._safe_log(features['file_size'])
        
        filename = analysis_data.get('filename', '')
        features['filename_length'] = len(filename)
        features['has_extension'] = 1 if '.' in filename else 0
        features['extension'] = self._get_extension(filename)
        
        # 2. Hash Features
        features['has_sha256'] = 1 if analysis_data.get('sha256') else 0
        features['has_md5'] = 1 if analysis_data.get('md5') else 0
        
        # 3. YARA Features
        yara_matches = analysis_data.get('yara_matches', []) or []
        features['yara_match_count'] = len(yara_matches) if isinstance(yara_matches, list) else 0
        features['has_yara_matches'] = 1 if features['yara_match_count'] > 0 else 0
        
        # YARA rule names (one-hot encoding)
        if isinstance(yara_matches, list):
            rule_names = [match.get('rule_name', match.get('rule', '')) for match in yara_matches if isinstance(match, dict)]
            features['yara_rule_count'] = len(set(rule_names))
            features['yara_rules'] = list(set(rule_names))[:10]  # Top 10 rules
        else:
            features['yara_rule_count'] = 0
            features['yara_rules'] = []
        
        # 4. PE Features
        pe_info = analysis_data.get('pe_info') or {}
        if isinstance(pe_info, str):
            try:
                pe_info = json.loads(pe_info)
            except:
                pe_info = {}
        
        features['is_pe_file'] = 1 if pe_info else 0
        features['pe_sections_count'] = len(pe_info.get('sections', [])) if isinstance(pe_info.get('sections'), list) else 0
        features['pe_imports_count'] = len(pe_info.get('imports', [])) if isinstance(pe_info.get('imports'), list) else 0
        features['pe_exports_count'] = len(pe_info.get('exports', [])) if isinstance(pe_info.get('exports'), list) else 0
        
        # PE suspicious indicators
        features['pe_has_suspicious_sections'] = self._check_suspicious_sections(pe_info)
        features['pe_has_packed'] = 1 if self._check_packed(pe_info) else 0
        features['pe_has_encrypted'] = 1 if self._check_encrypted(pe_info) else 0
        
        # 5. String Features
        suspicious_strings = analysis_data.get('suspicious_strings', []) or []
        if isinstance(suspicious_strings, str):
            try:
                suspicious_strings = json.loads(suspicious_strings)
            except:
                suspicious_strings = []
        
        features['suspicious_strings_count'] = len(suspicious_strings) if isinstance(suspicious_strings, list) else 0
        features['has_suspicious_strings'] = 1 if features['suspicious_strings_count'] > 0 else 0
        
        # Suspicious string patterns
        features['has_url_strings'] = self._check_pattern(suspicious_strings, ['http://', 'https://', 'ftp://'])
        features['has_ip_strings'] = self._check_pattern(suspicious_strings, ['192.168', '10.0', '172.16'])
        features['has_registry_strings'] = self._check_pattern(suspicious_strings, ['HKEY_', 'Registry', 'regedit'])
        features['has_crypto_strings'] = self._check_pattern(suspicious_strings, ['crypt', 'encrypt', 'decrypt', 'AES', 'RSA'])
        
        # 6. Capabilities Features
        capabilities = analysis_data.get('capabilities', []) or []
        if isinstance(capabilities, str):
            try:
                capabilities = json.loads(capabilities)
            except:
                capabilities = []
        
        features['capabilities_count'] = len(capabilities) if isinstance(capabilities, list) else 0
        features['has_network_capability'] = self._check_capability(capabilities, ['network', 'socket', 'http'])
        features['has_file_capability'] = self._check_capability(capabilities, ['file', 'read', 'write'])
        features['has_registry_capability'] = self._check_capability(capabilities, ['registry', 'reg'])
        features['has_process_capability'] = self._check_capability(capabilities, ['process', 'create', 'kill'])
        
        # 7. Analysis Features
        features['analysis_time'] = analysis_data.get('analysis_time', 0.0) or 0.0
        features['analysis_time_log'] = self._safe_log(features['analysis_time'])
        
        # 8. Label (target variable)
        features['label'] = 1 if analysis_data.get('malware_detected', False) else 0
        
        return features
    
    def extract_feature_vector(self, analysis_data: Dict[str, Any]) -> List[float]:
        """
        Trích xuất feature vector dạng số (cho ML models)
        
        Returns:
            List of numeric features
        """
        features = self.extract_features(analysis_data)
        
        # Chuyển đổi thành vector số
        vector = [
            features.get('file_size', 0),
            features.get('file_size_log', 0),
            features.get('filename_length', 0),
            features.get('has_extension', 0),
            features.get('has_sha256', 0),
            features.get('has_md5', 0),
            features.get('yara_match_count', 0),
            features.get('has_yara_matches', 0),
            features.get('yara_rule_count', 0),
            features.get('is_pe_file', 0),
            features.get('pe_sections_count', 0),
            features.get('pe_imports_count', 0),
            features.get('pe_exports_count', 0),
            features.get('pe_has_suspicious_sections', 0),
            features.get('pe_has_packed', 0),
            features.get('pe_has_encrypted', 0),
            features.get('suspicious_strings_count', 0),
            features.get('has_suspicious_strings', 0),
            features.get('has_url_strings', 0),
            features.get('has_ip_strings', 0),
            features.get('has_registry_strings', 0),
            features.get('has_crypto_strings', 0),
            features.get('capabilities_count', 0),
            features.get('has_network_capability', 0),
            features.get('has_file_capability', 0),
            features.get('has_registry_capability', 0),
            features.get('has_process_capability', 0),
            features.get('analysis_time', 0),
            features.get('analysis_time_log', 0),
        ]
        
        return vector
    
    def _safe_log(self, value: float) -> float:
        """Safe logarithm"""
        import math
        if value <= 0:
            return 0.0
        try:
            return math.log(value + 1)
        except:
            return 0.0
    
    def _get_extension(self, filename: str) -> str:
        """Lấy extension từ filename"""
        if '.' not in filename:
            return 'no_ext'
        return filename.split('.')[-1].lower()
    
    def _check_suspicious_sections(self, pe_info: Dict[str, Any]) -> int:
        """Kiểm tra có suspicious sections không"""
        sections = pe_info.get('sections', [])
        if not isinstance(sections, list):
            return 0
        
        suspicious_names = ['.packed', '.upx', '.vmp', '.themida', '.enigma']
        for section in sections:
            if isinstance(section, dict):
                name = section.get('name', '').lower()
                if any(sus in name for sus in suspicious_names):
                    return 1
        return 0
    
    def _check_packed(self, pe_info: Dict[str, Any]) -> bool:
        """Kiểm tra file có bị packed không"""
        sections = pe_info.get('sections', [])
        if not isinstance(sections, list):
            return False
        
        packed_indicators = ['.packed', '.upx', '.vmp', '.themida']
        for section in sections:
            if isinstance(section, dict):
                name = section.get('name', '').lower()
                if any(indicator in name for indicator in packed_indicators):
                    return True
        return False
    
    def _check_encrypted(self, pe_info: Dict[str, Any]) -> bool:
        """Kiểm tra file có encrypted không"""
        # Check entropy hoặc indicators
        sections = pe_info.get('sections', [])
        if not isinstance(sections, list):
            return False
        
        for section in sections:
            if isinstance(section, dict):
                entropy = section.get('entropy', 0)
                if entropy > 7.0:  # High entropy = likely encrypted
                    return True
        return False
    
    def _check_pattern(self, strings: List[str], patterns: List[str]) -> int:
        """Kiểm tra có pattern trong strings không"""
        if not isinstance(strings, list):
            return 0
        
        for string in strings:
            if isinstance(string, str):
                string_lower = string.lower()
                if any(pattern.lower() in string_lower for pattern in patterns):
                    return 1
        return 0
    
    def _check_capability(self, capabilities: List[Any], keywords: List[str]) -> int:
        """Kiểm tra có capability không"""
        if not isinstance(capabilities, list):
            return 0
        
        for cap in capabilities:
            if isinstance(cap, dict):
                cap_str = json.dumps(cap).lower()
                if any(keyword.lower() in cap_str for keyword in keywords):
                    return 1
            elif isinstance(cap, str):
                if any(keyword.lower() in cap.lower() for keyword in keywords):
                    return 1
        return 0

