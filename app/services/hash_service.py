"""
Hash Service
Handles hash-based malware detection
"""

from typing import List, Dict, Any, Optional
from src.Utils.Utils import sha256_hash
from src.Database.Malware import get_malware_by_list_sha256


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
        
        # Check in database
        malwares = await get_malware_by_list_sha256([sha256])
        if malwares:
            for malware in malwares:
                results.append({
                    "type": "hash",
                    "sha256": malware.sha256,
                    "uri": filepath,
                    "malwareType": malware.malwareType,
                    "firstSeen": malware.firstSeen,
                    "infoUrl": f"https://bazaar.abuse.ch/sample/{malware.sha256}/"
                })
        
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

