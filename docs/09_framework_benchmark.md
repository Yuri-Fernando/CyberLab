# Benchmark de Frameworks

O CyberLab mantém três camadas separadas:

1. implementação própria para explicar o algoritmo;
2. ART e Foolbox opcionais para paridade;
3. artefatos JSON/CSV para comparação auditável.

O módulo framework_benchmark.py executa o mesmo modelo e conjunto de dados, mede robust accuracy, attack success rate, L2, L∞ e runtime. Dependências opcionais ficam em requirements-adversarial.txt. Se não estiverem instaladas, o relatório registra unavailable sem fingir cobertura.

Antes de interpretar divergências, alinhe bounds, loss, epsilon, norma, random start e critério de sucesso.
