"""
image_forensics.py - Análise Forense de Imagem (ELA, ruído, metadados)

Detecção de manipulação/deepfake em imagens via técnicas forenses reais:

1. ELA (Error Level Analysis): recomprime a imagem em qualidade conhecida e mede
   a diferença. Regiões editadas/coladas têm nível de erro de compressão diferente
   do resto da imagem — aparecem "acesas" no mapa ELA.
2. Análise de ruído: inconsistências no padrão de ruído revelam splicing.
3. Metadados EXIF: ausência ou inconsistência sugere geração sintética.

Funciona standalone gerando uma imagem demo (com uma região "colada") e aceita
qualquer arquivo de imagem real.

Referência: técnica popularizada por FotoForensics; base de muitas ferramentas
de verificação (InVID/WeVerify).
"""

import io
import json
import logging
from typing import Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)

try:
    from PIL import Image, ImageChops, ImageDraw

    PIL_AVAILABLE = True
except Exception:  # pragma: no cover
    PIL_AVAILABLE = False
    logger.warning("PIL indisponível — image_forensics desabilitado.")


class ImageForensicsAnalyzer:
    """Análise forense de imagem com ELA e estatísticas de ruído."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/forensics")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.analyses = []

    def generate_demo_image(self, path: str, tampered: bool = True) -> str:
        """
        Gera imagem demo foto-realista; se tampered=True, cola uma região que foi
        recomprimida em qualidade muito menor — criando assinatura ELA distinta,
        exatamente como um splice/edição real deixaria.
        """
        if not PIL_AVAILABLE:
            return None
        # Base foto-realista: gradiente suave 2D (recomprime de forma homogênea)
        yy, xx = np.mgrid[0:256, 0:256]
        base = np.stack(
            [
                (128 + 100 * np.sin(xx / 40)).clip(0, 255),
                (128 + 100 * np.sin(yy / 40)).clip(0, 255),
                (128 + 80 * np.sin((xx + yy) / 50)).clip(0, 255),
            ],
            axis=2,
        ).astype(np.uint8)
        img = Image.fromarray(base, "RGB")

        if tampered:
            # Recorta uma região da própria imagem, recomprime em qualidade BAIXA
            # (dupla compressão) e cola de volta — artefato clássico detectado por ELA.
            region = img.crop((96, 96, 160, 160))
            buf = io.BytesIO()
            region.save(buf, "JPEG", quality=45)  # qualidade divergente
            region = Image.open(io.BytesIO(buf.getvalue()))
            img.paste(region, (96, 96))

        img.save(path, "JPEG", quality=92)
        return path

    def error_level_analysis(self, image_path: str, quality: int = 92) -> Tuple[np.ndarray, float]:
        """
        Executa ELA localizado: recomprime, mede diferença por pixel e procura por
        uma REGIÃO cujo nível de erro destoa do resto (assinatura de edição).

        Returns:
            (mapa_ela, ela_score) — score = quão destacada é a região mais anômala
            em relação à mediana dos blocos (localizado, não média global).
        """
        original = Image.open(image_path).convert("RGB")
        buf = io.BytesIO()
        original.save(buf, "JPEG", quality=quality)
        recompressed = Image.open(io.BytesIO(buf.getvalue()))

        ela = ImageChops.difference(original, recompressed)
        ela_array = np.asarray(ela).astype(np.float32)
        brightness = ela_array.mean(axis=2)

        # ELA localizado: brilho médio por bloco; anomalia = (max - mediana)/(mediana)
        h, w = brightness.shape
        bh, bw = h // 8, w // 8
        block_means = []
        for i in range(8):
            for j in range(8):
                block = brightness[i * bh : (i + 1) * bh, j * bw : (j + 1) * bw]
                block_means.append(block.mean())
        block_means = np.array(block_means)
        median = np.median(block_means) + 1e-6
        ela_score = float((block_means.max() - median) / median)
        return ela_array, ela_score

    def noise_consistency(self, image_path: str) -> float:
        """Mede consistência de ruído entre blocos (splicing quebra a homogeneidade)."""
        img = np.asarray(Image.open(image_path).convert("L")).astype(np.float32)
        h, w = img.shape
        bh, bw = h // 4, w // 4
        block_stds = []
        for i in range(4):
            for j in range(4):
                block = img[i * bh : (i + 1) * bh, j * bw : (j + 1) * bw]
                # Ruído de alta frequência via laplaciano simples
                lap = block[1:, 1:] - block[:-1, :-1]
                block_stds.append(lap.std())
        # Coeficiente de variação: alto => ruído inconsistente => suspeita
        cv = float(np.std(block_stds) / (np.mean(block_stds) + 1e-12))
        return cv

    def read_metadata(self, image_path: str) -> Dict:
        """Lê metadados EXIF (ausência é indício de imagem gerada/limpa)."""
        try:
            img = Image.open(image_path)
            exif = img.getexif()
            has_exif = len(exif) > 0
            return {
                "has_exif": has_exif,
                "exif_fields": len(exif),
                "format": img.format,
                "size": img.size,
            }
        except Exception as e:
            return {"has_exif": False, "error": str(e)}

    def analyze(self, image_path: str) -> Dict:
        """Análise forense completa de uma imagem."""
        if not PIL_AVAILABLE:
            return {"error": "PIL indisponível"}

        logger.info(f"Análise forense de imagem: {image_path}")
        ela_map, ela_score = self.error_level_analysis(image_path)
        noise_cv = self.noise_consistency(image_path)
        metadata = self.read_metadata(image_path)

        # Salvar mapa ELA como PNG (evidência visual)
        ela_vis = (255 * (ela_map / (ela_map.max() + 1e-12))).astype(np.uint8)
        ela_out = self.log_dir / f"ela_{Path(image_path).stem}.png"
        Image.fromarray(ela_vis).save(ela_out)

        # Verdict heurístico — ELA localizado é o sinal forte; EXIF é apenas indício fraco.
        indicators = []
        suspicion = 0.0

        # ELA: região destoa >20x da mediana => forte indício de edição
        if ela_score > 20.0:
            indicators.append("ELA localizado: região com nível de erro anômalo (splicing)")
            suspicion += 0.6
        elif ela_score > 12.0:
            suspicion += 0.15  # leve; compressão normal também gera variação

        # Ruído inconsistente entre blocos
        if noise_cv > 0.5:
            indicators.append("ruído inconsistente entre regiões")
            suspicion += 0.25

        # EXIF ausente: indício fraco (imagens processadas comumente perdem EXIF)
        if not metadata.get("has_exif"):
            suspicion += 0.1

        suspicion = min(1.0, suspicion)

        result = {
            "timestamp": datetime.now().isoformat(),
            "image_path": image_path,
            "ela_score": ela_score,
            "ela_map_saved": str(ela_out),
            "noise_consistency_cv": noise_cv,
            "metadata": metadata,
            "indicators": indicators,
            "manipulation_suspicion": float(suspicion),
            "verdict": (
                "SUSPEITA de manipulação"
                if suspicion > 0.5
                else "Consistente com imagem autêntica"
            ),
        }
        logger.info(f"  Veredito: {result['verdict']} (suspeita={suspicion:.2f})")
        self.analyses.append(result)
        return result

    def save(self) -> str:
        if not self.analyses:
            return None
        out = self.log_dir / f"image_forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump(self.analyses, f, indent=2)
        return str(out)


def demo():
    logging.basicConfig(level=logging.INFO)
    analyzer = ImageForensicsAnalyzer()
    demo_dir = Path("./results/forensics")
    demo_dir.mkdir(exist_ok=True, parents=True)

    tampered_path = str(demo_dir / "demo_tampered.jpg")
    clean_path = str(demo_dir / "demo_clean.jpg")
    analyzer.generate_demo_image(tampered_path, tampered=True)
    analyzer.generate_demo_image(clean_path, tampered=False)

    r1 = analyzer.analyze(tampered_path)
    r2 = analyzer.analyze(clean_path)

    print(f"\nImagem adulterada -> {r1['verdict']} (suspeita={r1['manipulation_suspicion']:.2f})")
    print(f"Imagem limpa      -> {r2['verdict']} (suspeita={r2['manipulation_suspicion']:.2f})")
    analyzer.save()


if __name__ == "__main__":
    demo()
