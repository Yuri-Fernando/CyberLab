"""
scanner.py - Wrapper para Nmap

Realiza scanning de portas, enumeração de serviços e análise de surface de ataque.
"""

import json
import logging
import subprocess
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class NmapScanner:
    """Wrapper para automatizar scans Nmap."""

    def __init__(self, target: str, output_dir: Path = None):
        """
        Inicializa o scanner.

        Args:
            target: IP ou hostname do alvo
            output_dir: Diretório para salvar resultados
        """
        self.target = target
        self.output_dir = output_dir or Path("./results")
        self.output_dir.mkdir(exist_ok=True)
        self.results = {}

    def quick_scan(self) -> Dict:
        """
        Scan rápido (top 1000 portas).

        Returns:
            Dict com resultados do scan
        """
        logger.info(f"Iniciando quick scan em {self.target}")

        cmd = [
            "nmap",
            "-sV",
            "-sC",
            "--top-ports=1000",
            "-oX",
            str(self.output_dir / "quick_scan.xml"),
            self.target
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                logger.error(f"Nmap error: {result.stderr}")
                return {"status": "error", "message": result.stderr}

            self.results["quick_scan"] = self._parse_nmap_output(result.stdout)
            self._save_results("quick_scan")

            return self.results["quick_scan"]

        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timeout")
            return {"status": "error", "message": "Scan timeout"}
        except FileNotFoundError:
            logger.error("Nmap não encontrado. Instale: apt-get install nmap")
            return {"status": "error", "message": "Nmap não instalado"}
        except Exception as e:
            logger.error(f"Scanner error: {str(e)}")
            return {"status": "error", "message": str(e)}

    def full_scan(self) -> Dict:
        """
        Scan completo (todas as portas).

        Returns:
            Dict com resultados do scan
        """
        logger.info(f"Iniciando full scan em {self.target}")

        cmd = [
            "nmap",
            "-p-",
            "-sV",
            "-sC",
            "-A",
            "-oX",
            str(self.output_dir / "full_scan.xml"),
            self.target
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode != 0:
                logger.error(f"Nmap error: {result.stderr}")
                return {"status": "error", "message": result.stderr}

            self.results["full_scan"] = self._parse_nmap_output(result.stdout)
            self._save_results("full_scan")

            return self.results["full_scan"]

        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timeout")
            return {"status": "error", "message": "Scan timeout"}
        except Exception as e:
            logger.error(f"Scanner error: {str(e)}")
            return {"status": "error", "message": str(e)}

    def vuln_scan(self) -> Dict:
        """
        Scan de vulnerabilidades (NSE scripts).

        Returns:
            Dict com resultados
        """
        logger.info(f"Iniciando vulnerability scan em {self.target}")

        cmd = [
            "nmap",
            "-sV",
            "--script=vuln",
            "-oX",
            str(self.output_dir / "vuln_scan.xml"),
            self.target
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode != 0:
                logger.warning(f"Nmap warning: {result.stderr}")

            self.results["vuln_scan"] = self._parse_nmap_output(result.stdout)
            self._save_results("vuln_scan")

            return self.results["vuln_scan"]

        except Exception as e:
            logger.error(f"Vulnerability scan error: {str(e)}")
            return {"status": "error", "message": str(e)}

    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse output de Nmap em formato estruturado."""
        return {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "raw_output": output,
            "status": "completed"
        }

    def _save_results(self, scan_type: str):
        """Salva resultados em JSON."""
        output_file = self.output_dir / f"{scan_type}_results.json"

        try:
            with open(output_file, "w") as f:
                json.dump(self.results[scan_type], f, indent=2)
            logger.info(f"Resultados salvos em {output_file}")
        except Exception as e:
            logger.error(f"Erro ao salvar resultados: {str(e)}")

    def get_summary(self) -> Dict:
        """Retorna resumo dos scans realizados."""
        return {
            "target": self.target,
            "scans_completed": list(self.results.keys()),
            "timestamp": datetime.now().isoformat()
        }


def main():
    """Teste do scanner."""
    import sys

    if len(sys.argv) < 2:
        print("Uso: python scanner.py <target_ip> [quick|full|vuln]")
        sys.exit(1)

    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "quick"

    scanner = NmapScanner(target)

    if scan_type == "quick":
        result = scanner.quick_scan()
    elif scan_type == "full":
        result = scanner.full_scan()
    elif scan_type == "vuln":
        result = scanner.vuln_scan()
    else:
        print("Tipo de scan inválido")
        sys.exit(1)

    print(json.dumps(result, indent=2))
    print(json.dumps(scanner.get_summary(), indent=2))


if __name__ == "__main__":
    main()
