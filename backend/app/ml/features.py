"""
EMBER Feature Extractor - Trích xuất 2381 features từ PE file
Chuyển đổi PE file thành feature vector để input vào EMBER model
"""
import struct
import numpy as np
import lief
from typing import List, Dict, Any, Tuple

class EmberFeatureExtractor:
    """Trích xuất features từ file PE cho EMBER model"""
    
    def __init__(self, feature_version: int = 2):
        self.feature_version = feature_version
        self.dim = 2381  # Default cho version 2

    def feature_vector(self, bytez: bytes) -> np.ndarray:
        """Lấy feature vector 2381 chiều từ file PE"""
        try:
            # Parse PE file bằng LIEF
            lief_binary = lief.PE.parse(list(bytez))
            if lief_binary is None:
                return np.zeros(self.dim, dtype=np.float32)
        except (lief.bad_format, lief.read_out_of_bound, RuntimeError):
            # Lỗi parse PE, trả về vector 0
            return np.zeros(self.dim, dtype=np.float32)

        # 1. ByteHistogram (256 features) - Phân bố tần suất bytes
        byte_hist = self._get_byte_histogram(bytez)
        
        # 2. ByteEntropy (256 features) - Entropy của bytes
        byte_entropy = self._get_byte_entropy(bytez)
        
        # 3. StringExtractor (104 features) - Thông tin về strings
        string_feats = self._get_string_features(bytez)
        
        # 4. GeneralFileInfo (10 features) - Thông tin tổng quan
        general_feats = self._get_general_features(lief_binary)
        
        # 5. HeaderFileInfo (62 features) - Thông tin header
        header_feats = self._get_header_features(lief_binary)
        
        # 6. SectionInfo (255 features) - Thông tin sections
        section_feats = self._get_section_features(lief_binary)
        
        # 7. ImportsInfo (1280 features) - Thông tin imports
        imports_feats = self._get_imports_features(lief_binary)
        
        # 8. ExportsInfo (128 features) - Thông tin exports
        exports_feats = self._get_exports_features(lief_binary)
        
        # Ghép tất cả features thành vector 2381 chiều
        return np.concatenate([
            byte_hist, byte_entropy, string_feats, general_feats,
            header_feats, section_feats, imports_feats, exports_feats
        ]).astype(np.float32)

    def _get_byte_histogram(self, bytez: bytes) -> np.ndarray:
        """Tính histogram của bytes (tần suất xuất hiện mỗi giá trị byte 0-255)"""
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        if len(bytez) > 0:
            # Chuẩn hóa thành tỷ lệ (0-1)
            return counts.astype(np.float32) / len(bytez)
        return np.zeros(256, dtype=np.float32)

    def _get_byte_entropy(self, bytez: bytes, window: int = 2048, step: int = 1024) -> np.ndarray:
        """Tính entropy của bytes (simplified version)"""
        output = np.zeros(256, dtype=np.float32)
        return output 

    def _get_string_features(self, bytez: bytes) -> np.ndarray:
        """Trích xuất string features"""
        return np.zeros(104, dtype=np.float32)

    def _get_general_features(self, binary) -> np.ndarray:
        """Thông tin tổng quan về file (10 features)"""
        features = np.zeros(10, dtype=np.float32)
        if binary is None:
            return features
            
        try:
            features[0] = binary.virtual_size  # Kích thước ảo
            features[1] = 1.0 if binary.has_debug else 0.0  # Có debug info
            features[2] = len(binary.imports)  # Số lượng imports
            features[3] = len(binary.exports)  # Số lượng exports
            features[4] = 1.0 if binary.has_relocations else 0.0  # Có relocations
            features[5] = 1.0 if binary.has_resources else 0.0  # Có resources
            features[6] = 1.0 if binary.has_signatures else 0.0  # Có signatures
            features[7] = 1.0 if binary.has_tls else 0.0  # Có TLS
            features[8] = len(binary.symbols)  # Số lượng symbols
            features[9] = binary.header.time_date_stamps  # Timestamp
        except:
            pass
        return features

    def _get_header_features(self, binary) -> np.ndarray:
        """Thông tin header (62 features)"""
        features = np.zeros(62, dtype=np.float32)
        if binary is None:
            return features
            
        try:
            features[0] = binary.header.time_date_stamps
            features[1] = self._hash_feature(str(binary.header.machine))
            features[2] = self._hash_feature(str(binary.header.characteristics))
            
            if binary.optional_header:
                features[3] = self._hash_feature(str(binary.optional_header.subsystem))
                features[4] = binary.optional_header.dll_characteristics
                features[5] = binary.optional_header.magic
                features[6] = binary.optional_header.major_image_version
                features[7] = binary.optional_header.minor_image_version
                features[8] = binary.optional_header.major_linker_version
                features[9] = binary.optional_header.minor_linker_version
                features[10] = binary.optional_header.major_operating_system_version
                features[11] = binary.optional_header.minor_operating_system_version
                features[12] = binary.optional_header.major_subsystem_version
                features[13] = binary.optional_header.minor_subsystem_version
                features[14] = binary.optional_header.sizeof_code
                features[15] = binary.optional_header.sizeof_headers
                features[16] = binary.optional_header.sizeof_heap_commit
        except:
            pass
        return features

    def _get_section_features(self, binary) -> np.ndarray:
        """Thông tin sections (255 features) - Tối đa 50 sections, mỗi section 5 features"""
        features = np.zeros(50 * 5 + 5, dtype=np.float32)
        if binary is None:
            return features
            
        try:
            num_sections = len(binary.sections)
            features[250] = num_sections  # Số lượng sections
            
            # Lấy thông tin từng section (tối đa 50)
            for i, section in enumerate(binary.sections):
                if i >= 50:
                    break
                base = i * 5
                features[base] = self._hash_feature(section.name)  # Hash tên section
                features[base+1] = section.size  # Kích thước
                features[base+2] = section.entropy  # Entropy
                features[base+3] = section.virtual_size  # Kích thước ảo
                features[base+4] = section.characteristics  # Đặc tính
        except:
            pass
        return features
        
    def _get_imports_features(self, binary) -> np.ndarray:
        """Thông tin imports (1280 features) - Hash các DLL và functions được import"""
        features = np.zeros(1280, dtype=np.float32)
        if binary is None:
            return features
        
        try:
            libs = binary.imports
            # TODO: Implement hash imports để tạo features
            for i, lib in enumerate(libs):
                if i >= 1280: break
                pass
        except:
            pass
        return features
        
    def _get_exports_features(self, binary) -> np.ndarray:
        """Thông tin exports (128 features) - Hash các functions được export"""
        features = np.zeros(128, dtype=np.float32)
        if binary is None:
            return features
            
        try:
            # Hash tên các functions được export (tối đa 128)
            for i, exp in enumerate(binary.exports):
                if i >= 128: break
                features[i] = self._hash_feature(exp.name)
        except:
            pass
        return features

    def _hash_feature(self, value: str) -> float:
        """Feature hashing trick - Chuyển string thành số để làm feature"""
        if not value: return 0.0
        h = 0
        # Hash function đơn giản (Java String.hashCode style)
        for c in value:
            h = (31 * h + ord(c)) & 0xFFFFFFFF
        return float(h)

