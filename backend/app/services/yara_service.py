"""
YARA Service - Xử lý YARA rules và scanning
"""
from typing import List, Dict, Any, Optional
import yara
from app.core.config import settings

class YaraService:
    """Service xử lý YARA scanning"""
    
    def __init__(self):
        self.rules = settings.get_yara_rules()
    
    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Scan file với YARA rules
        
        Returns:
            List of match results
        """
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(filepath)
            if not matches:
                return []
            
            results = []
            match_details = []
            
            for match in matches:
                rule_info = str(match.rule)
                
                # Add tags if available
                if hasattr(match, 'tags') and match.tags:
                    rule_info += f" (tags: {', '.join(match.tags)})"
                
                # Add description if available
                if hasattr(match, 'meta') and match.meta:
                    if 'description' in match.meta:
                        rule_info += f" - {match.meta['description']}"
                
                match_details.append(rule_info)
            
            results.append({
                "type": "yara",
                "file": filepath,
                "matches": ", ".join(match_details),
                "rule_count": len(matches),
                "infoUrl": None  # Will be filled by analyzer service
            })
            
            return results
            
        except Exception as e:
            print(f"YARA scan error for {filepath}: {e}")
            return [{
                "type": "yara_error",
                "message": f"Loi quet YARA: {str(e)}",
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

