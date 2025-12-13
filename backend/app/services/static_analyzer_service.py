"""
Static Analyzer Service
Handles static analysis of PE files
"""

from typing import Dict, Any, Optional
from app.core.config import settings


class StaticAnalyzerService:
    """Service for static analysis of files"""
    
    def __init__(self):
        self.static_analyzer = settings.get_static_analyzer()
    
    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """
        Perform static analysis on file
        
        Args:
            filepath: Path to file to analyze
            
        Returns:
            Dictionary containing static analysis results
        """
        if not self.static_analyzer:
            return {
                "hashes": {"sha256": None, "md5": None},
                "yara_matches": [],
                "pe_info": None,
                "strings": [],
                "capabilities": []
            }
        
        try:
            # Perform static analysis
            result = self.static_analyzer.analyze_file(filepath)
            return result
        except Exception as e:
            print(f"Static analyzer error for {filepath}: {e}")
            return {
                "hashes": {"sha256": None, "md5": None},
                "yara_matches": [],
                "pe_info": None,
                "strings": [],
                "capabilities": []
            }
    
    def get_analyzer(self):
        """Get static analyzer instance"""
        return self.static_analyzer

