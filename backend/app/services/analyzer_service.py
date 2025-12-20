"""
Analyzer Service - Điều phối phân tích malware
Orchestrator chính: kết hợp YARA, Hash, EMBER, Static Analysis để phát hiện malware
"""
import os
import sys
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.core.config import settings
from app.services.yara_service import YaraService
from app.services.hash_service import HashService
from app.services.static_analyzer_service import StaticAnalyzerService
from app.services.analysis_service import AnalysisService
# Sử dụng ML module mới
from app.ml.ember_model import EmberModel

class AnalyzerService:
    """Service xử lý phân tích malware"""
    
    def __init__(self):
        self.yara_service = YaraService()
        self.hash_service = HashService()
        self.static_analyzer_service = StaticAnalyzerService()
        self.ember_model = EmberModel()  # Sử dụng ML module mới
        self.analysis_service = AnalysisService()
    
    async def analyze_single_file(self, filepath: str, scan_modules: List[str] = None) -> List[Dict[str, Any]]:
        """
        Phân tích một file đơn lẻ
        
        Args:
            filepath: Đường dẫn file
            scan_modules: List các modules chạy ["yara", "ember", "hash"]. Default None = Run All.

        Returns:
            List of analysis results
        """
        if scan_modules is None:
            scan_modules = ["hash", "yara", "ember"]

        results = []
        sha256 = None  # Chỉ tính khi cần
        
        # 1) Hash-based detection (chỉ chạy nếu "hash" trong scan_modules)
        if "hash" in scan_modules:
            hash_results = await self.hash_service.check_hash(filepath)
            results.extend(hash_results)
        
        if "yara" in scan_modules:
            # 2) YARA scan - Tính SHA256 chỉ khi cần cho YARA results
            if sha256 is None:
                sha256 = self.hash_service.calculate_hash(filepath)
            
            yara_results = self.yara_service.scan_file(filepath)
            
            # Add SHA256 to YARA results for infoUrl
            if yara_results and sha256:
                for result in yara_results:
                    if result.get("type") == "yara" and not result.get("infoUrl"):
                        result["infoUrl"] = f"https://bazaar.abuse.ch/sample/{sha256}/"
            
            results.extend(yara_results)

        if "ember" in scan_modules:
            # 3) EMBER scan - Sử dụng ML module mới
            ember_result = self.ember_model.predict(filepath)
            
            # Luôn trả về kết quả EMBER (có score) dù có phát hiện malware hay không
            if ember_result.get("error"):
                results.append({
                    "type": "ember_error",
                    "message": f"[ERROR] EMBER prediction failed: {ember_result.get('error')}",
                    "score": 0.0,
                    "infoUrl": None
                })
            elif ember_result.get("is_malware"):
                results.append({
                    "type": "model",
                    "subtype": "ember",
                    "message": f"[MALWARE] EMBER detection (Score: {ember_result['score']:.4f})",
                    "score": ember_result['score'],
                    "threshold": self.ember_model.threshold,
                    "infoUrl": None 
                })
            else:
                # File sạch nhưng vẫn trả về score để người dùng biết
                results.append({
                    "type": "model",
                    "subtype": "ember",
                    "message": f"[CLEAN] EMBER analysis (Score: {ember_result['score']:.4f}, Threshold: {self.ember_model.threshold:.4f})",
                    "score": ember_result['score'],
                    "threshold": self.ember_model.threshold,
                    "infoUrl": None
                })
        
        # 4) Nếu không phát hiện gì (không có module nào chạy hoặc tất cả đều clean)
        if not results:
            results.append({
                "type": "clean",
                "message": "[OK] Khong phat hien malware",
                "infoUrl": None
            })
        
        return results
    
    async def analyze_and_save(self, filepath: str, filename: str, scan_modules: List[str] = None) -> Dict[str, Any]:
        """
        Phân tích file và lưu kết quả vào database
        
        Returns:
            Dict chứa analysis_id và results
        """
        import time
        import os
        from datetime import datetime
        
        start_time = time.time()
        
        # Phân tích file
        results = await self.analyze_single_file(filepath, scan_modules)
        static_analysis = self.analyze_with_static_analyzer(filepath)
        
        elapsed = time.time() - start_time
        
        # Xác định có malware không
        # Chỉ các type "hash", "yara", "model" được coi là malware
        # "ember_error", "yara_error", "clean" không phải malware
        malware_detected = any(
            result.get("type") in ["hash", "yara", "model"] 
            for result in results
        )
        
        # Lấy thông tin file
        file_size = os.path.getsize(filepath) if os.path.exists(filepath) else None
        sha256 = self.hash_service.calculate_hash(filepath)
        md5 = static_analysis.get("hashes", {}).get("md5")
        
        # Chuẩn bị dữ liệu để lưu
        analysis_data = {
            'filename': filename,
            'sha256': sha256,
            'md5': md5,
            'file_size': file_size,
            'upload_time': datetime.now(),
            'analysis_time': elapsed,
            'malware_detected': malware_detected,
            'yara_matches': static_analysis.get("yara_matches", []),
            'pe_info': static_analysis.get("pe_info"),
            'suspicious_strings': static_analysis.get("strings", [])[:20],  # Limit 20
            'capabilities': static_analysis.get("capabilities", [])
        }
        
        # Lưu vào database
        try:
            analysis_id = await self.analysis_service.create(analysis_data)
            analysis_data['id'] = analysis_id
            analysis_data['results'] = results
            return analysis_data
        except Exception as e:
            print(f"[WARN] Failed to save analysis to database: {e}")
            # Vẫn trả về kết quả dù không lưu được
            analysis_data['results'] = results
            return analysis_data
    
    async def analyze_folder(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Phân tích một folder chứa nhiều files
        
        Returns:
            List of analysis results
        """
        all_results = []
        malware_files = []
        clean_files = []
        
        for filepath in file_paths:
            try:
                file_results = await self.analyze_single_file(filepath)
                has_malware = any(result["type"] in ["hash", "yara", "model"] for result in file_results)
                
                if has_malware:
                    malware_files.append({
                        "filepath": filepath,
                        "results": file_results
                    })
                else:
                    clean_files.append(filepath)
            except Exception as e:
                print(f"Error analyzing {filepath}: {e}")
                continue
        
        # Tạo kết quả tổng hợp
        if malware_files:
            all_results.append({
                "type": "folder_summary",
                "message": f"[WARN] Phat hien {len(malware_files)} file chua malware trong {len(file_paths)} files",
                "malware_count": len(malware_files),
                "total_count": len(file_paths),
                "clean_count": len(clean_files)
            })
            
            # Thêm chi tiết từng file malware
            for malware_file in malware_files:
                all_results.extend(malware_file["results"])
        else:
            all_results.append({
                "type": "clean",
                "message": f"[OK] Folder sach - khong phat hien malware trong {len(file_paths)} files",
                "infoUrl": None
            })
        
        return all_results
    
    def analyze_with_static_analyzer(self, filepath: str) -> Dict[str, Any]:
        """
        Phân tích file với Static Analyzer (PE, strings, capabilities)
        
        Returns:
            Dict với keys: hashes, yara_matches, pe_info, strings, capabilities
        """
        return self.static_analyzer_service.analyze_file(filepath)

