"""
🎖️ ENHANCED EKM STORAGE MANAGER - High-Quality Knowledge Storage
Implements the exact structure specified in CLINE_EKM_INTEGRATION_TASK.md

Author: Commander Bobby Don McWilliams II
Authority Level: 11.0 SOVEREIGN
Storage Path: M:\MEMORY_ORCHESTRATION\L9_EKM\EKM_MODULES\
"""

import json
import hashlib
import logging
import sqlite3
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import asyncio
from sentence_transformers import SentenceTransformer
import spacy

logger = logging.getLogger(__name__)

class EnhancedEKMStorageManager:
    """
    High-quality EKM storage for harvested knowledge
    Follows exact specification from CLINE_EKM_INTEGRATION_TASK.md
    """
    
    def __init__(self):
        self.ekm_root = Path("M:/MEMORY_ORCHESTRATION/L9_EKM/EKM_MODULES")
        self.index_db = Path("M:/MEMORY_ORCHESTRATION/L9_EKM/ekm_index.db")
        self.next_ekm_number = self._load_next_number()
        
        # Initialize models
        try:
            self.embedding_model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
            logger.info("✅ Sentence transformer model loaded")
        except Exception as e:
            logger.warning(f"Could not load sentence transformer: {e}")
            self.embedding_model = None
            
        try:
            self.nlp = spacy.load("en_core_web_sm")
            logger.info("✅ SpaCy NLP model loaded")
        except Exception as e:
            logger.warning(f"Could not load spaCy model: {e}")
            self.nlp = None
            
        # Create directories and initialize database
        self.ekm_root.mkdir(parents=True, exist_ok=True)
        self._initialize_index_db()
        
        logger.info(f"✅ Enhanced EKM Storage Manager initialized: {self.ekm_root}")
    
    def _load_next_number(self) -> int:
        """Load next EKM number from existing modules"""
        try:
            existing_modules = list(self.ekm_root.glob("*"))
            module_numbers = []
            for mod in existing_modules:
                try:
                    num = int(mod.name.split("_")[0])
                    module_numbers.append(num)
                except:
                    pass
            return max(module_numbers, default=0) + 1
        except Exception as e:
            logger.error(f"Error loading next EKM number: {e}")
            return 1
    
    def _initialize_index_db(self):
        """Initialize SQLite index database"""
        try:
            conn = sqlite3.connect(self.index_db)
            cursor = conn.cursor()
            
            # Create main index table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ekm_index (
                    ekm_id TEXT PRIMARY KEY,
                    ekm_number INTEGER,
                    title TEXT,
                    description TEXT,
                    category TEXT,
                    tags TEXT,
                    source TEXT,
                    quality_score REAL,
                    created TEXT,
                    updated TEXT,
                    embedding BLOB,
                    access_count INTEGER DEFAULT 0,
                    last_accessed TEXT
                )
            ''')
            
            # Create connections table for graph relationships
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ekm_connections (
                    source_ekm TEXT,
                    target_ekm TEXT,
                    relationship_type TEXT,
                    strength REAL,
                    FOREIGN KEY (source_ekm) REFERENCES ekm_index (ekm_id),
                    FOREIGN KEY (target_ekm) REFERENCES ekm_index (ekm_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("✅ EKM index database initialized")
        except Exception as e:
            logger.error(f"Error initializing index database: {e}")
    
    def _extract_entities_concepts(self, text: str) -> Dict[str, List[str]]:
        """Extract entities and concepts using NLP"""
        entities = []
        concepts = []
        
        if self.nlp and text:
            try:
                doc = self.nlp(text)
                entities = [ent.text for ent in doc.ents]
                # Extract noun phrases as concepts
                concepts = [chunk.text for chunk in doc.noun_chunks][:10]  # Limit to top 10
            except Exception as e:
                logger.warning(f"NLP processing failed: {e}")
        
        return {
            "entities": entities,
            "key_concepts": concepts
        }
    
    def _calculate_quality_score(self, data: Dict) -> float:
        """Calculate quality score (0-1.0)"""
        score = 0.0
        
        # Content length (0.2 points)
        content = data.get('content', '')
        if len(content) > 1000:
            score += 0.2
        elif len(content) > 500:
            score += 0.15
        elif len(content) > 200:
            score += 0.1
        elif len(content) > 50:
            score += 0.05
        
        # Metadata completeness (0.3 points)
        required_fields = ['title', 'content', 'source', 'category']
        present_fields = sum(1 for field in required_fields if data.get(field))
        score += (present_fields / len(required_fields)) * 0.3
        
        # Source reliability (0.2 points)
        source_reliability = data.get('source_reliability', 0.5)
        score += source_reliability * 0.2
        
        # Entity/concept richness (0.3 points)
        if data.get('entities') and data.get('key_concepts'):
            entity_count = len(data.get('entities', []))
            concept_count = len(data.get('key_concepts', []))
            richness = min((entity_count + concept_count) / 20, 1.0)  # Normalize
            score += richness * 0.3
        
        return min(score, 1.0)
    
    def _find_related_ekms(self, embedding: np.ndarray, top_k: int = 5) -> List[str]:
        """Find related EKMs using semantic similarity"""
        try:
            conn = sqlite3.connect(self.index_db)
            cursor = conn.cursor()
            
            # Get all embeddings from database
            cursor.execute("SELECT ekm_id, embedding FROM ekm_index WHERE embedding IS NOT NULL")
            results = cursor.fetchall()
            
            similarities = []
            for ekm_id, stored_embedding_blob in results:
                if stored_embedding_blob:
                    stored_embedding = np.frombuffer(stored_embedding_blob, dtype=np.float32)
                    similarity = np.dot(embedding, stored_embedding) / (
                        np.linalg.norm(embedding) * np.linalg.norm(stored_embedding)
                    )
                    similarities.append((ekm_id, similarity))
            
            # Sort by similarity and return top_k
            similarities.sort(key=lambda x: x[1], reverse=True)
            return [ekm_id for ekm_id, sim in similarities[:top_k]]
            
        except Exception as e:
            logger.error(f"Error finding related EKMs: {e}")
            return []
        finally:
            conn.close()
    
    async def store_knowledge(self, harvested_data: Dict) -> str:
        """Store harvested knowledge as high-quality EKM module"""
        try:
            # Generate EKM ID
            ekm_number = self.next_ekm_number
            self.next_ekm_number += 1
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_title = "".join(c for c in harvested_data.get('title', 'Unknown') if c.isalnum())[:20]
            ekm_id = f"{ekm_number:03d}_{clean_title}_{timestamp}"
            
            # Extract entities and concepts
            nlp_results = self._extract_entities_concepts(harvested_data.get('content', ''))
            
            # Generate embedding
            embedding = None
            if self.embedding_model:
                try:
                    text_to_embed = f"{harvested_data.get('title', '')} {harvested_data.get('content', '')}"
                    embedding = self.embedding_model.encode(text_to_embed)
                except Exception as e:
                    logger.warning(f"Embedding generation failed: {e}")
            
            # Calculate quality score
            quality_score = self._calculate_quality_score(harvested_data)
            
            # Find related EKMs
            related_ekms = []
            if embedding is not None:
                related_ekms = self._find_related_ekms(embedding)
            
            # Create EKM structure
            ekm_structure = {
                "ekm_id": ekm_id,
                "ekm_number": f"{ekm_number:03d}",
                "version": "1.0.0",
                "created": datetime.now().isoformat(),
                "updated": datetime.now().isoformat(),
                
                "metadata": {
                    "title": harvested_data.get('title', 'Unknown'),
                    "description": harvested_data.get('description', harvested_data.get('content', '')[:200]),
                    "category": harvested_data.get('category', 'General'),
                    "tags": harvested_data.get('tags', []),
                    "source": harvested_data.get('source', 'Unknown'),
                    "source_url": harvested_data.get('source_url', ''),
                    "authority_level": 11.0,
                    "gs343_protected": True,
                    "quality_score": quality_score
                },
                
                "knowledge": {
                    "summary": harvested_data.get('summary', harvested_data.get('content', '')[:500]),
                    "content": harvested_data.get('content', ''),
                    "key_concepts": nlp_results['key_concepts'],
                    "entities": nlp_results['entities'],
                    "relationships": [
                        {"from": concept, "to": entity, "type": "related_to"} 
                        for concept in nlp_results['key_concepts'][:3] 
                        for entity in nlp_results['entities'][:3]
                    ][:10]  # Limit relationships
                },
                
                "embeddings": {
                    "vector_file": f"embeddings/{ekm_number:03d}_vector.npy",
                    "model": "sentence-transformers/all-MiniLM-L6-v2",
                    "dimensions": embedding.shape[0] if embedding is not None else 0
                },
                
                "connections": {
                    "related_ekms": [ekm.split('_')[0] for ekm in related_ekms],
                    "parent_ekm": None,
                    "child_ekms": []
                },
                
                "usage": {
                    "access_count": 0,
                    "last_accessed": None,
                    "used_by": []
                }
            }
            
            # Create directory structure
            ekm_path = self.ekm_root / ekm_id
            ekm_path.mkdir(parents=True, exist_ok=True)
            (ekm_path / "embeddings").mkdir(exist_ok=True)
            
            # Save JSON
            with open(ekm_path / "ekm.json", 'w', encoding='utf-8') as f:
                json.dump(ekm_structure, f, indent=2, ensure_ascii=False)
            
            # Save embedding
            if embedding is not None:
                np.save(ekm_path / "embeddings" / f"{ekm_number:03d}_vector.npy", embedding)
            
            # Update index database
            self._update_index_database(ekm_structure, embedding)
            
            logger.info(f"✅ Created EKM: {ekm_id} | Quality: {quality_score:.2f}")
            return ekm_id
            
        except Exception as e:
            logger.error(f"Failed to store knowledge: {e}", exc_info=True)
            return None
    
    def _update_index_database(self, ekm_data: Dict, embedding: Optional[np.ndarray] = None):
        """Update SQLite index database"""
        try:
            conn = sqlite3.connect(self.index_db)
            cursor = conn.cursor()
            
            # Prepare embedding blob
            embedding_blob = embedding.tobytes() if embedding is not None else None
            
            cursor.execute('''
                INSERT OR REPLACE INTO ekm_index 
                (ekm_id, ekm_number, title, description, category, tags, source, 
                 quality_score, created, updated, embedding)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ekm_data['ekm_id'],
                int(ekm_data['ekm_number']),
                ekm_data['metadata']['title'],
                ekm_data['metadata']['description'],
                ekm_data['metadata']['category'],
                json.dumps(ekm_data['metadata']['tags']),
                ekm_data['metadata']['source'],
                ekm_data['metadata']['quality_score'],
                ekm_data['created'],
                ekm_data['updated'],
                embedding_blob
            ))
            
            # Update connections
            for related_ekm in ekm_data['connections']['related_ekms']:
                cursor.execute('''
                    INSERT OR IGNORE INTO ekm_connections 
                    (source_ekm, target_ekm, relationship_type, strength)
                    VALUES (?, ?, ?, ?)
                ''', (ekm_data['ekm_id'], related_ekm, 'semantic_similarity', 0.8))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating index database: {e}")
    
    async def retrieve_knowledge(self, query: str, top_k: int = 10) -> List[Dict]:
        """Fast knowledge lookup by semantic search"""
        try:
            if not self.embedding_model:
                return await self._text_search(query, top_k)
            
            # Generate query embedding
            query_embedding = self.embedding_model.encode(query)
            
            # Search database
            conn = sqlite3.connect(self.index_db)
            cursor = conn.cursor()
            
            cursor.execute("SELECT ekm_id, embedding FROM ekm_index WHERE embedding IS NOT NULL")
            results = cursor.fetchall()
            
            similarities = []
            for ekm_id, stored_embedding_blob in results:
                if stored_embedding_blob:
                    stored_embedding = np.frombuffer(stored_embedding_blob, dtype=np.float32)
                    similarity = np.dot(query_embedding, stored_embedding) / (
                        np.linalg.norm(query_embedding) * np.linalg.norm(stored_embedding)
                    )
                    similarities.append((ekm_id, similarity))
            
            # Sort by similarity and get top_k
            similarities.sort(key=lambda x: x[1], reverse=True)
            top_ekms = similarities[:top_k]
            
            # Load EKM data
            ekm_results = []
            for ekm_id, similarity in top_ekms:
                ekm_path = self.ekm_root / ekm_id / "ekm.json"
                if ekm_path.exists():
                    with open(ekm_path, 'r', encoding='utf-8') as f:
                        ekm_data = json.load(f)
                        ekm_data['similarity_score'] = float(similarity)
                        ekm_results.append(ekm_data)
            
            conn.close()
            return ekm_results
            
        except Exception as e:
            logger.error(f"Error retrieving knowledge: {e}")
            return await self._text_search(query, top_k)
    
    async def _text_search(self, query: str, top_k: int = 10) -> List[Dict]:
        """Fallback text search if embeddings are unavailable"""
        try:
            conn = sqlite3.connect(self.index_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT ekm_id FROM ekm_index 
                WHERE title LIKE ? OR description LIKE ? OR tags LIKE ?
                ORDER BY quality_score DESC
                LIMIT ?
            ''', (f'%{query}%', f'%{query}%', f'%{query}%', top_k))
            
            results = cursor.fetchall()
            ekm_results = []
            
            for (ekm_id,) in results:
                ekm_path = self.ekm_root / ekm_id / "ekm.json"
                if ekm_path.exists():
                    with open(ekm_path, 'r', encoding='utf-8') as f:
                        ekm_data = json.load(f)
                        ekm_results.append(ekm_data)
            
            conn.close()
            return ekm_results
            
        except Exception as e:
            logger.error(f"Error in text search: {e}")
            return []
    
    async def find_related(self, ekm_id: str, top_k: int = 5) -> List[str]:
        """Find related EKM modules"""
        try:
            conn = sqlite3.connect(self.index_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT target_ekm, strength FROM ekm_connections 
                WHERE source_ekm = ? 
                ORDER BY strength DESC
                LIMIT ?
            ''', (ekm_id, top_k))
            
            results = cursor.fetchall()
            conn.close()
            
            return [ekm for ekm, strength in results]
            
        except Exception as e:
            logger.error(f"Error finding related EKMs: {e}")
            return []
    
    async def update_ekm(self, ekm_id: str, new_data: Dict):
        """Update existing EKM (versioned)"""
        try:
            ekm_path = self.ekm_root / ekm_id / "ekm.json"
            if not ekm_path.exists():
                raise ValueError(f"EKM not found: {ekm_id}")
            
            with open(ekm_path, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
            
            # Update fields
            existing_data['updated'] = datetime.now().isoformat()
            existing_data['version'] = self._increment_version(existing_data['version'])
            
            # Update metadata if provided
            if 'metadata' in new_data:
                existing_data['metadata'].update(new_data['metadata'])
            
            # Update knowledge if provided
            if 'knowledge' in new_data:
                existing_data['knowledge'].update(new_data['knowledge'])
            
            # Save updated EKM
            with open(ekm_path, 'w', encoding='utf-8') as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)
            
            # Update index
            self._update_index_database(existing_data)
            
            logger.info(f"✅ Updated EKM: {ekm_id}")
            
        except Exception as e:
            logger.error(f"Error updating EKM: {e}")
    
    def _increment_version(self, version: str) -> str:
        """Increment version number (simple implementation)"""
        try:
            major, minor, patch = map(int, version.split('.'))
            return f"{major}.{minor}.{patch + 1}"
        except:
            return "1.0.1"


# Global instance
_enhanced_ekm_storage = None

def get_enhanced_ekm_storage() -> EnhancedEKMStorageManager:
    """Get global enhanced EKM storage manager instance"""
    global _enhanced_ekm_storage
    if _enhanced_ekm_storage is None:
        _enhanced_ekm_storage = EnhancedEKMStorageManager()
    return _enhanced_ekm_storage


# Test function
async def test_enhanced_ekm_storage():
    """Test the enhanced EKM storage system"""
    storage = EnhancedEKMStorageManager()
    
    test_data = {
        'title': 'Quantum Computing Breakthrough 2025',
        'content': '''Researchers at MIT have achieved a significant breakthrough in quantum computing,
        demonstrating a 1000-qubit system with unprecedented coherence times. This advancement
        could revolutionize cryptography, drug discovery, and artificial intelligence.''',
        'source': 'MIT Research',
        'category': 'Quantum Technology',
        'tags': ['quantum', 'computing', 'breakthrough', 'MIT'],
        'source_reliability': 0.95
    }
    
    ekm_id = await storage.store_knowledge(test_data)
    if ekm_id:
        print(f"✅ Created test EKM: {ekm_id}")
        
        # Test retrieval
        results = await storage.retrieve_knowledge("quantum computing")
        print(f"✅ Found {len(results)} relevant EKMs")
        
        # Test related search
        related = await storage.find_related(ekm_id)
        print(f"✅ Found {len(related)} related EKMs")


if __name__ == "__main__":
    asyncio.run(test_enhanced_ekm_storage())
