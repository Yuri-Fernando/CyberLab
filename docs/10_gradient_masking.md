# Auditoria de Gradient Masking

Robustez aparente pode ser consequência de gradientes quebrados ou de ataque mal configurado. O auditor combina sinais independentes:

- PGD não deveria ser sistematicamente mais fraco que FGSM;
- robust accuracy deve degradar coerentemente com epsilon;
- aumentar steps deve convergir ou manter a força;
- random restarts não deveriam revelar uma queda extrema inesperada;
- transfer e black-box mais fortes que white-box exigem investigação;
- componentes não diferenciáveis/estocásticos devem declarar necessidade de BPDA/EOT.

LOW, MEDIUM e HIGH são triagem, não certificado de robustez. Sempre registre parâmetros e teste ataques adaptativos.
