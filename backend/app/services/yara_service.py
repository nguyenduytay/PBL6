"""
YARA Service - Quét file bằng YARA rules
Load và compile YARA rules, quét file để phát hiện patterns malware
"""
from typing import List, Dict, Any, Optional
import yara
from app.core.config import settings

class YaraService:
    """Service xử lý YARA scanning"""
    
    def __init__(self):
        self.rules = settings.get_yara_rules()
        if self.rules:
            try:
                rule_count = len(list(self.rules))
                print(f"[YARA] YaraService initialized with {rule_count} rules")
            except Exception as e:
                print(f"[YARA] WARNING: Could not count rules: {e}")
        else:
            print("[YARA] WARNING: YaraService initialized but no rules loaded!")
    
    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Scan file với YARA rules
        
        Returns:
            List of match results
        """
        if not self.rules:
            print(f"[YARA] WARNING: YARA rules not loaded, skipping scan for {filepath}")
            return []
        
        try:
            print(f"[YARA] Scanning file: {filepath}")
            matches = self.rules.match(filepath)
            if not matches:
                print(f"[YARA] No matches found for {filepath}")
                return []
            
            print(f"[YARA] Found {len(matches)} matches for {filepath}")
            
            results = []
            match_details = []
            
            # Tạo danh sách match đơn giản cho hiển thị
            for match in matches:
                rule_info = str(match.rule)
                
                # Thêm tags nếu có
                if hasattr(match, 'tags') and match.tags:
                    rule_info += f" (tags: {', '.join(match.tags)})"
                
                # Thêm mô tả nếu có
                if hasattr(match, 'meta') and match.meta:
                    if 'description' in match.meta:
                        rule_info += f" - {match.meta['description']}"
                
                match_details.append(rule_info)
            
            # Tạo danh sách match chi tiết để lưu database
            detailed_matches = []
            for match in matches:
                match_obj = {
                    "rule_name": str(match.rule),
                    "tags": list(match.tags) if hasattr(match, 'tags') and match.tags else [],
                    "description": None,
                    "author": None,
                    "reference": None,
                    "matched_strings": []
                }
                
                # Lấy thông tin meta (mô tả, tác giả, tham khảo)
                if hasattr(match, 'meta') and match.meta:
                    match_obj["description"] = match.meta.get('description')
                    match_obj["author"] = match.meta.get('author')
                    match_obj["reference"] = match.meta.get('reference')
                
                # Lấy các strings đã khớp
                if hasattr(match, 'strings') and match.strings:
                    for s in match.strings:
                        # yara.StringMatch có attributes: identifier, offset, data
                        string_info = {
                            "identifier": getattr(s, 'identifier', None),
                            "offset": getattr(s, 'offset', None),
                            "data": None,
                            "data_preview": None
                        }
                        
                        # Lấy data (bytes)
                        data = getattr(s, 'data', None)
                        if data:
                            if isinstance(data, bytes):
                                string_info["data"] = data.hex()
                                # Thử decode thành string để preview
                                try:
                                    decoded = data.decode('ascii', errors='ignore')
                                    if decoded and decoded.isprintable() and len(decoded) > 0:
                                        string_info["data_preview"] = decoded[:100]  # Giới hạn preview
                                except:
                                    pass
                            else:
                                string_info["data"] = str(data)
                        
                        match_obj["matched_strings"].append(string_info)
                
                detailed_matches.append(match_obj)
            
            results.append({
                "type": "yara",
                "file": filepath,
                "matches": ", ".join(match_details),
                "rule_count": len(matches),
                "detailed_matches": detailed_matches,  # Để lưu database
                "infoUrl": None  # Sẽ được điền bởi analyzer service
            })
            
            return results
            
        except Exception as e:
            print(f"[YARA] ERROR scanning {filepath}: {e}")
            import traceback
            traceback.print_exc()
            return [{
                "type": "yara_error",
                "message": f"Lỗi quét YARA: {str(e)}",
                "infoUrl": None
            }]
    
    def is_loaded(self) -> bool:
        """Kiểm tra YARA rules đã được load chưa"""
        return self.rules is not None
    
    def get_rule_count(self) -> int:
        """Lấy số lượng rules đã load"""
        if not self.rules:
            return 0
        try:
            return len(list(self.rules))
        except:
            return 0

