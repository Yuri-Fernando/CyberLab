"""
logs_analyzer.py - Análise de logs de ataque

Parse e análise de logs de sistema e ataques para gerar dashboards e estatísticas.
"""

import json
import logging
from typing import Dict, List
from pathlib import Path
from datetime import datetime
from collections import Counter

logger = logging.getLogger(__name__)


class LogsAnalyzer:
    """Analisa logs de ataque e sistema."""

    def __init__(self, log_dir: Path = None):
        """
        Inicializa analisador.

        Args:
            log_dir: Diretório contendo logs
        """
        self.log_dir = log_dir or Path("./results/logs")
        self.log_dir.mkdir(exist_ok=True)
        self.analysis = {}

    def analyze_attack_logs(self, log_file: str) -> Dict:
        """
        Analisa logs de ataque (Medusa, etc).

        Args:
            log_file: Arquivo de log de ataque

        Returns:
            Dict com análise
        """
        logger.info(f"Analisando log de ataque: {log_file}")

        analysis = {
            "file": log_file,
            "timestamp": datetime.now().isoformat(),
            "total_attempts": 0,
            "successful": False,
            "lines": 0,
            "patterns": {}
        }

        try:
            log_path = self.log_dir / log_file

            if not log_path.exists():
                logger.warning(f"Arquivo não encontrado: {log_path}")
                return {"status": "error", "message": "Arquivo não encontrado"}

            with open(log_path, "r") as f:
                lines = f.readlines()

            analysis["lines"] = len(lines)

            # Procurar por padrões
            success_keywords = ["SUCCESS", "FOUND", "Valid", "Correct"]
            failed_keywords = ["FAILED", "INVALID", "Incorrect", "DENIED"]

            for line in lines:
                if any(keyword in line for keyword in success_keywords):
                    analysis["successful"] = True
                    analysis["patterns"]["success"] = analysis["patterns"].get("success", 0) + 1

                if any(keyword in line for keyword in failed_keywords):
                    analysis["total_attempts"] += 1

            self.analysis["attacks"] = analysis
            self._save_analysis("attacks")

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing attack logs: {str(e)}")
            return {"status": "error", "message": str(e)}

    def analyze_system_logs(self, log_file: str) -> Dict:
        """
        Analisa logs de sistema para detectar ataques.

        Args:
            log_file: Arquivo de log de sistema

        Returns:
            Dict com análise
        """
        logger.info(f"Analisando log de sistema: {log_file}")

        analysis = {
            "file": log_file,
            "timestamp": datetime.now().isoformat(),
            "failed_logins": 0,
            "auth_attempts": 0,
            "unique_ips": set(),
            "suspicious_activity": []
        }

        try:
            log_path = self.log_dir / log_file

            if not log_path.exists():
                logger.warning(f"Arquivo não encontrado: {log_path}")
                return {"status": "error", "message": "Arquivo não encontrado"}

            with open(log_path, "r") as f:
                lines = f.readlines()

            for line in lines:
                # Detectar tentativas de login falhadas
                if "failed password" in line.lower() or "authentication failure" in line.lower():
                    analysis["failed_logins"] += 1

                # Contar tentativas de autenticação
                if "auth" in line.lower() or "login" in line.lower():
                    analysis["auth_attempts"] += 1

                # Extrair IPs (padrão simplificado)
                import re
                ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                analysis["unique_ips"].update(ips)

                # Detectar atividades suspeitas
                suspicious = ["sudo", "exploit", "backdoor", "payload"]
                if any(keyword in line.lower() for keyword in suspicious):
                    analysis["suspicious_activity"].append(line.strip())

            # Converter set para list para JSON serialization
            analysis["unique_ips"] = list(analysis["unique_ips"])
            analysis["suspicious_activity"] = analysis["suspicious_activity"][:10]  # Primeiras 10

            self.analysis["system"] = analysis
            self._save_analysis("system")

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing system logs: {str(e)}")
            return {"status": "error", "message": str(e)}

    def generate_statistics(self) -> Dict:
        """
        Gera estatísticas combinadas de todos os logs analisados.

        Returns:
            Dict com estatísticas
        """
        logger.info("Gerando estatísticas gerais")

        stats = {
            "timestamp": datetime.now().isoformat(),
            "total_analyses": len(self.analysis),
            "attacks_successful": 0,
            "total_failed_logins": 0,
            "total_auth_attempts": 0,
            "total_suspicious_activity": 0
        }

        for analysis_type, data in self.analysis.items():
            if analysis_type == "attacks" and data.get("successful"):
                stats["attacks_successful"] += 1

            if analysis_type == "system":
                stats["total_failed_logins"] += data.get("failed_logins", 0)
                stats["total_auth_attempts"] += data.get("auth_attempts", 0)
                stats["total_suspicious_activity"] += len(data.get("suspicious_activity", []))

        return stats

    def _save_analysis(self, analysis_type: str):
        """Salva análise em JSON."""
        output_file = self.log_dir / f"{analysis_type}_analysis.json"

        try:
            # Converter sets para lists antes de salvar
            data = json.loads(json.dumps(self.analysis.get(analysis_type, {}), default=str))

            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)

            logger.info(f"Análise salva em {output_file}")
        except Exception as e:
            logger.error(f"Erro ao salvar análise: {str(e)}")

    def create_html_report(self, output_file: str = "report.html") -> str:
        """
        Cria relatório HTML com análises.

        Args:
            output_file: Nome do arquivo de saída

        Returns:
            Caminho do arquivo criado
        """
        logger.info(f"Gerando relatório HTML: {output_file}")

        stats = self.generate_statistics()

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CyberLab - Relatório de Análise</title>
            <meta charset="utf-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 20px;
                    background: #f5f5f5;
                }}
                .container {{
                    max-width: 1000px;
                    margin: 0 auto;
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                h1 {{
                    color: #333;
                    border-bottom: 3px solid #0066cc;
                    padding-bottom: 10px;
                }}
                h2 {{
                    color: #0066cc;
                    margin-top: 30px;
                }}
                .stat-grid {{
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 20px;
                    margin: 20px 0;
                }}
                .stat-card {{
                    background: #f9f9f9;
                    border-left: 4px solid #0066cc;
                    padding: 15px;
                    border-radius: 4px;
                }}
                .stat-card h3 {{
                    margin: 0 0 10px 0;
                    color: #555;
                    font-size: 14px;
                }}
                .stat-card .value {{
                    font-size: 28px;
                    color: #0066cc;
                    font-weight: bold;
                }}
                .warning {{
                    border-left-color: #ff9800;
                }}
                .warning .value {{
                    color: #ff9800;
                }}
                .success {{
                    border-left-color: #4caf50;
                }}
                .success .value {{
                    color: #4caf50;
                }}
                .footer {{
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    text-align: center;
                    color: #999;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 CyberLab - Relatório de Análise de Segurança</h1>

                <div class="stat-grid">
                    <div class="stat-card">
                        <h3>Análises Realizadas</h3>
                        <div class="value">{stats['total_analyses']}</div>
                    </div>
                    <div class="stat-card success">
                        <h3>Ataques Bem-Sucedidos</h3>
                        <div class="value">{stats['attacks_successful']}</div>
                    </div>
                    <div class="stat-card warning">
                        <h3>Tentativas de Login Falhadas</h3>
                        <div class="value">{stats['total_failed_logins']}</div>
                    </div>
                    <div class="stat-card warning">
                        <h3>Tentativas de Autenticação</h3>
                        <div class="value">{stats['total_auth_attempts']}</div>
                    </div>
                </div>

                <h2>Detalhes Técnicos</h2>
                <p>Gerado em: <strong>{stats['timestamp']}</strong></p>

                <h2>⚠️ Atividades Suspeitas Detectadas</h2>
                <p>Total: <strong>{stats['total_suspicious_activity']}</strong></p>

                <div class="footer">
                    <p>CyberLab v1.0 | Laboratório Educacional de Segurança</p>
                    <p>⚠️ Ambiente controlado para fins educacionais apenas</p>
                </div>
            </div>
        </body>
        </html>
        """

        try:
            output_path = Path(output_file)
            with open(output_path, "w") as f:
                f.write(html_content)

            logger.info(f"Relatório salvo em {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Erro ao criar relatório: {str(e)}")
            return None


def main():
    """Teste do analisador."""
    analyzer = LogsAnalyzer()

    # Análise de exemplo
    print("Analisador de logs CyberLab")
    print("Uso: python logs_analyzer.py <log_file>")


if __name__ == "__main__":
    main()
