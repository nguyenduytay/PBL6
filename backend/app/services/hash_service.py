"""
Hash Service - Phát hiện malware dựa trên hash
Tính SHA256/MD5 và so sánh với malware database để phát hiện file đã biết
"""

import hashlib
from typing import List, Dict, Any, Optional


def sha256_hash(filepath: str) -> Optional[str]:
    """
    Calculate SHA256 hash of a file
    
    Args:
        filepath: Path to file
        
    Returns:
        SHA256 hash string or None if error
    """
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        print(f"[WARN] Error calculating SHA256: {e}")
        return None


class HashService:
    """Service for hash-based malware detection"""
    
    async def check_hash(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Check if file hash exists in malware database
        
        Args:
            filepath: Path to file to check
            
        Returns:
            List of malware matches
        """
        results = []
        
        # Calculate SHA256
        sha256 = sha256_hash(filepath)
        if not sha256:
            return results
        
        # Database check temporarily disabled - src folder removed during refactoring
        # malwares = await get_malware_by_list_sha256([sha256])
        # if malwares:
        #     for malware in malwares:
        #         results.append({
        #             "type": "hash",
        #             "sha256": malware.sha256,
        #             "uri": filepath,
        #             "malwareType": malware.malwareType,
        #             "firstSeen": malware.firstSeen,
        #             "infoUrl": f"https://bazaar.abuse.ch/sample/{malware.sha256}/"
        #         })
        
        return results
    
    def calculate_hash(self, filepath: str) -> Optional[str]:
        """
        Calculate SHA256 hash of file
        
        Args:
            filepath: Path to file
            
        Returns:
            SHA256 hash string or None
        """
        return sha256_hash(filepath)

