"""
CyberLab - Laboratório de Segurança Ofensiva e Defensiva

Módulos para análise, ataque simulado e defesa em ambiente controlado.
"""

__version__ = "1.0.0"
__author__ = "Yuri"
__license__ = "Educational - MIT"

import os
import sys
import logging
from pathlib import Path

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Diretórios principais
PROJECT_ROOT = Path(__file__).parent.parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"
LOGS_DIR = RESULTS_DIR / "logs"
WORDLISTS_DIR = PROJECT_ROOT / "wordlists"

# Criar diretórios se não existirem
RESULTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
WORDLISTS_DIR.mkdir(exist_ok=True)

logger.info(f"CyberLab v{__version__} inicializado")
logger.info(f"Raiz do projeto: {PROJECT_ROOT}")
logger.info(f"Diretório de resultados: {RESULTS_DIR}")
