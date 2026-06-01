"""
Module de sécurité des embeddings avec signatures et vérification d'intégrité
"""
import hashlib
import hmac
import json
import logging
import os
from typing import List, Dict, Any, Optional, Tuple
from cryptography.fernet import Fernet
import numpy as np
from sentence_transformers import SentenceTransformer

# Configuration locale — peut être surchargée via variables d'environnement.
# L'import relatif `..config` a été supprimé : ce module est conçu pour être
# utilisé de manière autonome ou importé dans un package qui fournit sa propre config.
class _DefaultConfig:
    """Configuration par défaut lorsqu'aucun module de config parent n'est disponible."""
    ENCRYPTION_KEY: str = os.environ.get("AETHERIUM_ENCRYPTION_KEY", Fernet.generate_key().decode())
    EMBEDDING_SIGNATURES: Dict[str, Any] = {
        "algorithm": "HMAC-SHA256",
        "verify_integrity": True,
        "cache_signed_embeddings": False,
    }

try:
    # Tentative d'import du module de config parent s'il existe
    from ..config import config  # type: ignore[import]
except ImportError:
    config = _DefaultConfig()

logger = logging.getLogger(__name__)

class EmbeddingSecurity:
    """Gestionnaire de sécurité pour les embeddings"""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialise le gestionnaire de sécurité des embeddings
        
        Args:
            model_name: Nom du modèle d'embedding à utiliser
        """
        try:
            self.model = SentenceTransformer(model_name)
            self.encryption_key = config.ENCRYPTION_KEY.encode()
            self.fernet = Fernet(self.encryption_key)
            
            # Cache pour les embeddings signés
            self.signed_embeddings_cache = {}
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de la sécurité des embeddings: {e}")
            raise
    
    def generate_embedding(self, text: str) -> np.ndarray:
        """
        Génère un embedding pour le texte donné
        
        Args:
            text: Texte à encoder
            
        Returns:
            Embedding vectorisé
        """
        try:
            embedding = self.model.encode(text)
            return embedding
        except Exception as e:
            logger.error(f"Erreur lors de la génération d'embedding: {e}")
            raise
    
    def sign_embedding(self, embedding: np.ndarray, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Signe un embedding avec HMAC
        
        Args:
            embedding: Embedding à signer
            metadata: Métadonnées associées
            
        Returns:
            Embedding signé avec métadonnées
        """
        try:
            # Conversion en bytes pour le hachage
            embedding_bytes = embedding.tobytes()
            
            # Génération de la signature HMAC
            signature = hmac.new(
                self.encryption_key,
                embedding_bytes,
                hashlib.sha256
            ).hexdigest()
            
            # Création du payload signé
            signed_payload = {
                'embedding': embedding.tolist(),
                'metadata': metadata,
                'signature': signature,
                'algorithm': config.EMBEDDING_SIGNATURES['algorithm'],
                'timestamp': self._get_timestamp()
            }
            
            return signed_payload
            
        except Exception as e:
            logger.error(f"Erreur lors de la signature de l'embedding: {e}")
            raise
    
    def verify_embedding_integrity(self, signed_embedding: Dict[str, Any]) -> bool:
        """
        Vérifie l'intégrité d'un embedding signé
        
        Args:
            signed_embedding: Embedding signé à vérifier
            
        Returns:
            True si l'intégrité est vérifiée, False sinon
        """
        try:
            if not config.EMBEDDING_SIGNATURES['verify_integrity']:
                return True
            
            # Extraction des composants
            embedding = np.array(signed_embedding['embedding'])
            provided_signature = signed_embedding['signature']
            
            # Régénération de la signature
            embedding_bytes = embedding.tobytes()
            expected_signature = hmac.new(
                self.encryption_key,
                embedding_bytes,
                hashlib.sha256
            ).hexdigest()
            
            # Comparaison sécurisée des signatures
            return hmac.compare_digest(provided_signature, expected_signature)
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification d'intégrité: {e}")
            return False
    
    def encrypt_embedding(self, signed_embedding: Dict[str, Any]) -> bytes:
        """
        Chiffre un embedding signé
        
        Args:
            signed_embedding: Embedding signé à chiffrer
            
        Returns:
            Embedding chiffré
        """
        try:
            # Sérialisation JSON
            json_data = json.dumps(signed_embedding).encode()
            
            # Chiffrement
            encrypted_data = self.fernet.encrypt(json_data)
            
            return encrypted_data
            
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement de l'embedding: {e}")
            raise
    
    def decrypt_embedding(self, encrypted_data: bytes) -> Dict[str, Any]:
        """
        Déchiffre un embedding
        
        Args:
            encrypted_data: Données chiffrées
            
        Returns:
            Embedding déchiffré
        """
        try:
            # Déchiffrement
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            # Désérialisation JSON
            signed_embedding = json.loads(decrypted_data.decode())
            
            return signed_embedding
            
        except Exception as e:
            logger.error(f"Erreur lors du déchiffrement de l'embedding: {e}")
            raise
    
    def store_secure_embedding(self, text: str, metadata: Dict[str, Any]) -> str:
        """
        Stocke un embedding de manière sécurisée
        
        Args:
            text: Texte à encoder
            metadata: Métadonnées associées
            
        Returns:
            ID de stockage de l'embedding
        """
        try:
            # Génération de l'embedding
            embedding = self.generate_embedding(text)
            
            # Signature
            signed_embedding = self.sign_embedding(embedding, metadata)
            
            # Chiffrement
            encrypted_embedding = self.encrypt_embedding(signed_embedding)
            
            # Génération d'un ID unique
            storage_id = hashlib.sha256(
                f"{text}{metadata.get('source', '')}{self._get_timestamp()}".encode()
            ).hexdigest()
            
            # Cache si configuré
            if config.EMBEDDING_SIGNATURES['cache_signed_embeddings']:
                self.signed_embeddings_cache[storage_id] = {
                    'encrypted_data': encrypted_embedding,
                    'metadata': metadata
                }
            
            return storage_id
            
        except Exception as e:
            logger.error(f"Erreur lors du stockage sécurisé de l'embedding: {e}")
            raise
    
    def retrieve_secure_embedding(self, storage_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère un embedding stocké de manière sécurisée
        
        Args:
            storage_id: ID de stockage
            
        Returns:
            Embedding déchiffré et vérifié, ou None si non trouvé
        """
        try:
            # Récupération depuis le cache
            if storage_id in self.signed_embeddings_cache:
                cached_data = self.signed_embeddings_cache[storage_id]
                encrypted_data = cached_data['encrypted_data']
                
                # Déchiffrement
                signed_embedding = self.decrypt_embedding(encrypted_data)
                
                # Vérification d'intégrité
                if self.verify_embedding_integrity(signed_embedding):
                    return signed_embedding
                else:
                    logger.warning(f"Intégrité de l'embedding {storage_id} non vérifiée")
                    return None
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'embedding: {e}")
            return None
    
    def batch_process_embeddings(self, texts: List[str], metadata_list: List[Dict[str, Any]]) -> List[str]:
        """
        Traite un lot d'embeddings de manière sécurisée
        
        Args:
            texts: Liste des textes à traiter
            metadata_list: Liste des métadonnées correspondantes
            
        Returns:
            Liste des IDs de stockage
        """
        storage_ids = []
        
        for text, metadata in zip(texts, metadata_list):
            try:
                storage_id = self.store_secure_embedding(text, metadata)
                storage_ids.append(storage_id)
            except Exception as e:
                logger.error(f"Erreur lors du traitement de l'embedding pour le texte: {text[:50]}...")
                storage_ids.append(None)
        
        return storage_ids
    
    def verify_embedding_chain(self, storage_ids: List[str]) -> Dict[str, Any]:
        """
        Vérifie l'intégrité d'une chaîne d'embeddings
        
        Args:
            storage_ids: Liste des IDs à vérifier
            
        Returns:
            Résultat de la vérification
        """
        verification_results = {
            'total_embeddings': len(storage_ids),
            'verified_count': 0,
            'failed_count': 0,
            'failed_ids': [],
            'overall_integrity': True
        }
        
        for storage_id in storage_ids:
            if storage_id:
                embedding = self.retrieve_secure_embedding(storage_id)
                if embedding and self.verify_embedding_integrity(embedding):
                    verification_results['verified_count'] += 1
                else:
                    verification_results['failed_count'] += 1
                    verification_results['failed_ids'].append(storage_id)
                    verification_results['overall_integrity'] = False
        
        return verification_results
    
    def _get_timestamp(self) -> str:
        """Retourne le timestamp actuel"""
        from datetime import datetime
        return datetime.utcnow().isoformat()
