"""
EKM Storage Manager - High-Quality Knowledge Module Storage
Stores all harvested knowledge as structured EKM modules in M: Drive

Author: Commander Bobby Don McWilliams II
Authority: Level 11.0 SOVEREIGN
Storage Path: M:\MEMORY_ORCHESTRATION\L9_EKM\EKM_MODULES\
"""

import json
import hashlib
import logging
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import asyncio
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class EKMMetadata:
    """High-quality EKM metadata structure"""
    ModuleID: str
    FileCount: int
    Embeddings: int
    TextFiles: int
    SizeMB: float
    CompletionScore: int
    QualityScore: int
    Status: str
    Hash: str
    CreatedDate: str
    HarvesterType: str
    KnowledgeDomain: str
    AuthorityLevel: float
    GS343Protection: bool
    VectorDimensions: int
    SourceCount: int


class EKMStorageManager:
    """
    High-Quality EKM Storage Manager
    
    Creates structured EKM modules following the standard format:
    M:\MEMORY_ORCHESTRATION\L9_EKM\EKM_MODULES\{ModuleID}\
        ├── embedded/
        │   └── vector_chunks.npy
        ├── responses/
        │   └── (AI responses if any)
        ├── sources/
        │   ├── source_001.txt
        │   ├── source_002.txt
        │   └── ...
        ├── commands.json
        ├── log.json
        ├── meta.json
        └── voice_bind.txt
    """
    
    def __init__(
        self,
        base_path: str = r"M:\MEMORY_ORCHESTRATION\L9_EKM\EKM_MODULES",
        min_quality_score: int = 70,
        authority_level: float = 11.0
    ):
        self.base_path = Path(base_path)
        self.min_quality_score = min_quality_score
        self.authority_level = authority_level
        self.logger = logging.getLogger(f"{__name__}.EKMStorageManager")
        
        # Create base directory if doesn't exist
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.modules_created = 0
        self.total_size_mb = 0.0
        self.quality_scores = []
        
        self.logger.info(f"✅ EKM Storage Manager initialized: {self.base_path}")
    
    
    def _generate_module_id(self, harvester_type: str, domain: str) -> str:
        """Generate unique EKM module ID"""
        # Format: XXX_HarvesterType_Domain_Timestamp
        # Example: 012_WebHarvester_AI_20251027_143022
        
        # Get next module number
        existing_modules = list(self.base_path.glob("*"))
        module_numbers = []
        for mod in existing_modules:
            try:
                num = int(mod.name.split("_")[0])
                module_numbers.append(num)
            except:
                pass
        
        next_num = max(module_numbers, default=0) + 1
        
        # Clean domain name (remove special chars)
        clean_domain = "".join(c for c in domain if c.isalnum())[:20]
        clean_harvester = harvester_type.replace("Harvester", "").replace("_", "")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        module_id = f"{next_num:03d}_{clean_harvester}_{clean_domain}_{timestamp}"
        
        return module_id
    
    
    def _calculate_content_hash(self, content: str) -> str:
        """Calculate MD5 hash of content"""
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    
    def _calculate_quality_score(self, ekm_data: Dict) -> int:
        """
        Calculate quality score (0-100)
        
        Factors:
        - Content length (20 points)
        - Source reliability (20 points)
        - Data completeness (20 points)
        - Metadata richness (20 points)
        - Embedding quality (20 points)
        """
        score = 0
        
        # Content length score (max 20)
        content = ekm_data.get('content', '')
        if len(content) > 1000:
            score += 20
        elif len(content) > 500:
            score += 15
        elif len(content) > 200:
            score += 10
        elif len(content) > 50:
            score += 5
        
        # Source reliability (max 20)
        source_score = ekm_data.get('source_reliability', 50)
        score += int(source_score * 0.2)
        
        # Data completeness (max 20)
        required_fields = ['title', 'content', 'url', 'timestamp', 'harvester_type']
        present_fields = sum(1 for field in required_fields if ekm_data.get(field))
        score += int((present_fields / len(required_fields)) * 20)
        
        # Metadata richness (max 20)
        metadata_fields = ['keywords', 'category', 'author', 'domain', 'tags']
        present_metadata = sum(1 for field in metadata_fields if ekm_data.get(field))
        score += int((present_metadata / len(metadata_fields)) * 20)
        
        # Embedding quality (max 20)
        if ekm_data.get('embeddings') and len(ekm_data['embeddings']) > 0:
            score += 20
        
        return min(score, 100)
    
    
    async def create_ekm_module(
        self,
        ekm_data: Dict[str, Any],
        harvester_type: str,
        knowledge_domain: str
    ) -> Optional[str]:
        """
        Create a high-quality EKM module
        
        Args:
            ekm_data: Dictionary containing knowledge data
            harvester_type: Type of harvester (Web, News, TOR, etc.)
            knowledge_domain: Domain/category (AI, Cybersecurity, etc.)
        
        Returns:
            Module ID if successful, None if failed
        """
        try:
            # Calculate quality score
            quality_score = self._calculate_quality_score(ekm_data)
            
            # Reject low-quality content
            if quality_score < self.min_quality_score:
                self.logger.warning(
                    f"Rejected low-quality content: {quality_score}/100 "
                    f"(min: {self.min_quality_score})"
                )
                return None
            
            # Generate module ID
            module_id = self._generate_module_id(harvester_type, knowledge_domain)
            module_path = self.base_path / module_id
            
            # Create directory structure
            module_path.mkdir(parents=True, exist_ok=True)
            (module_path / "embedded").mkdir(exist_ok=True)
            (module_path / "responses").mkdir(exist_ok=True)
            (module_path / "sources").mkdir(exist_ok=True)
            
            # Save source content
            content = ekm_data.get('content', '')
            source_file = module_path / "sources" / "source_001.txt"
            with open(source_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Save additional sources if present
            additional_sources = ekm_data.get('additional_sources', [])
            for idx, source in enumerate(additional_sources, start=2):
                source_file = module_path / "sources" / f"source_{idx:03d}.txt"
                with open(source_file, 'w', encoding='utf-8') as f:
                    f.write(source)
            
            # Save embeddings if present
            embeddings = ekm_data.get('embeddings', [])
            embedding_count = 0
            vector_dims = 0
            if embeddings and len(embeddings) > 0:
                embedding_array = np.array(embeddings)
                vector_file = module_path / "embedded" / "vector_chunks.npy"
                np.save(vector_file, embedding_array)
                embedding_count = len(embeddings)
                vector_dims = embedding_array.shape[-1] if len(embedding_array.shape) > 1 else len(embedding_array)
            
            # Calculate content hash
            content_hash = self._calculate_content_hash(content)
            
            # Calculate size
            total_size = sum(
                f.stat().st_size for f in module_path.rglob('*') if f.is_file()
            )
            size_mb = total_size / (1024 * 1024)
            
            # Count files
            text_files = len(list((module_path / "sources").glob("*.txt")))
            total_files = len(list(module_path.rglob('*')))
            
            # Determine status based on quality
            if quality_score >= 90:
                status = "✅ Premium Quality"
            elif quality_score >= 80:
                status = "✅ High Quality"
            elif quality_score >= 70:
                status = "✅ Good Quality"
            else:
                status = "⚠️ Acceptable"
            
            # Create metadata
            metadata = EKMMetadata(
                ModuleID=module_id,
                FileCount=total_files,
                Embeddings=embedding_count,
                TextFiles=text_files,
                SizeMB=round(size_mb, 3),
                CompletionScore=quality_score,
                QualityScore=quality_score,
                Status=status,
                Hash=content_hash,
                CreatedDate=datetime.now().isoformat(),
                HarvesterType=harvester_type,
                KnowledgeDomain=knowledge_domain,
                AuthorityLevel=self.authority_level,
                GS343Protection=True,
                VectorDimensions=vector_dims,
                SourceCount=text_files
            )
            
            # Save meta.json
            meta_file = module_path / "meta.json"
            with open(meta_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(metadata), f, indent=2)
            
            # Create log.json with creation event
            log_data = {
                "created": datetime.now().isoformat(),
                "harvester": harvester_type,
                "quality_score": quality_score,
                "authority": self.authority_level,
                "events": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event": "EKM_CREATED",
                        "quality": quality_score,
                        "status": status
                    }
                ]
            }
            log_file = module_path / "log.json"
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(log_data, f, indent=2)
            
            # Create empty commands.json
            commands_file = module_path / "commands.json"
            with open(commands_file, 'w', encoding='utf-8') as f:
                json.dump({"commands": []}, f, indent=2)
            
            # Create voice_bind.txt with module name
            voice_file = module_path / "voice_bind.txt"
            with open(voice_file, 'w', encoding='utf-8') as f:
                f.write(f"{knowledge_domain}\n")
            
            # Update statistics
            self.modules_created += 1
            self.total_size_mb += size_mb
            self.quality_scores.append(quality_score)
            
            self.logger.info(
                f"✅ Created EKM: {module_id} | "
                f"Quality: {quality_score}/100 | "
                f"Size: {size_mb:.2f}MB | "
                f"Sources: {text_files} | "
                f"Embeddings: {embedding_count}"
            )
            
            return module_id
            
        except Exception as e:
            self.logger.error(f"Failed to create EKM module: {e}", exc_info=True)
            return None
    
    
    async def batch_create_ekm_modules(
        self,
        ekm_data_list: List[Dict[str, Any]],
        harvester_type: str,
        knowledge_domain: str
    ) -> List[str]:
        """Create multiple EKM modules in batch"""
        tasks = []
        for ekm_data in ekm_data_list:
            task = self.create_ekm_module(ekm_data, harvester_type, knowledge_domain)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out None and exceptions
        successful_ids = [
            r for r in results 
            if r is not None and not isinstance(r, Exception)
        ]
        
        self.logger.info(
            f"✅ Batch created {len(successful_ids)}/{len(ekm_data_list)} EKM modules"
        )
        
        return successful_ids
    
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get storage statistics"""
        avg_quality = (
            sum(self.quality_scores) / len(self.quality_scores)
            if self.quality_scores else 0
        )
        
        return {
            "modules_created": self.modules_created,
            "total_size_mb": round(self.total_size_mb, 2),
            "average_quality": round(avg_quality, 1),
            "storage_path": str(self.base_path),
            "min_quality_threshold": self.min_quality_score
        }
    
    
    async def verify_module(self, module_id: str) -> bool:
        """Verify EKM module integrity"""
        try:
            module_path = self.base_path / module_id
            
            if not module_path.exists():
                return False
            
            # Check required structure
            required_items = [
                "embedded",
                "responses",
                "sources",
                "meta.json",
                "log.json",
                "commands.json",
                "voice_bind.txt"
            ]
            
            for item in required_items:
                if not (module_path / item).exists():
                    self.logger.warning(f"Missing {item} in {module_id}")
                    return False
            
            # Verify meta.json is valid
            with open(module_path / "meta.json", 'r') as f:
                metadata = json.load(f)
                if not metadata.get('ModuleID') == module_id:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Module verification failed: {e}")
            return False


# Global EKM storage instance
_ekm_storage = None


def get_ekm_storage() -> EKMStorageManager:
    """Get global EKM storage manager instance"""
    global _ekm_storage
    if _ekm_storage is None:
        _ekm_storage = EKMStorageManager()
    return _ekm_storage


# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def test_ekm_storage():
        """Test EKM storage system"""
        storage = EKMStorageManager()
        
        # Create test EKM
        test_data = {
            'title': 'Quantum Computing Breakthrough 2025',
            'content': '''
            Researchers at MIT have achieved a significant breakthrough in quantum computing,
            demonstrating a 1000-qubit system with unprecedented coherence times. This advancement
            could revolutionize cryptography, drug discovery, and artificial intelligence.
            The team overcame previous limitations by implementing novel error correction codes.
            ''',
            'url': 'https://example.com/quantum-breakthrough',
            'timestamp': datetime.now().isoformat(),
            'harvester_type': 'WebHarvester',
            'keywords': ['quantum computing', 'MIT', 'qubits', 'breakthrough'],
            'category': 'Quantum Technology',
            'author': 'Dr. Jane Smith',
            'domain': 'Quantum Computing',
            'tags': ['science', 'technology', 'quantum'],
            'source_reliability': 95,
            'embeddings': np.random.rand(384).tolist()  # Simulated embedding
        }
        
        # Create EKM module
        module_id = await storage.create_ekm_module(
            test_data,
            harvester_type="WebHarvester",
            knowledge_domain="QuantumComputing"
        )
        
        if module_id:
            print(f"✅ Created test EKM: {module_id}")
            
            # Verify module
            is_valid = await storage.verify_module(module_id)
            print(f"✅ Module verification: {'PASSED' if is_valid else 'FAILED'}")
            
            # Show statistics
            stats = storage.get_statistics()
            print(f"\n📊 Storage Statistics:")
            for key, value in stats.items():
                print(f"   {key}: {value}")
    
    asyncio.run(test_ekm_storage())
