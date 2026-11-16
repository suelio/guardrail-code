# Atribuições e créditos de terceiros (`guardrail code`)

O motor principal de varredura (`core/scanner_engine.py`), analisador AST Python, auditoria `.gitignore`, gerador de guardrails, exportador de relatórios e catálogo de regras foram desenvolvidos especificamente para o projeto **guardrail code** utilizando a biblioteca padrão do Python.

As seguintes tecnologias, APIs públicas e bibliotecas de terceiros são utilizadas com suas respectivas licenças e atribuições:

1. **Flask** (Pallets Projects)
   - Uso: Servidor web HTTP local e renderização de templates Jinja2.
   - Licença: BSD-3-Clause
   - Referência: https://flask.palletsprojects.com/

2. **Bootstrap 5.3.3** (Bootstrap Authors / Twitter, Inc.)
   - Uso: Sistema de grid responsivo, modais e componentes de interface carregados via jsDelivr CDN.
   - Licença: MIT
   - Referência: https://getbootstrap.com/

3. **Inter e JetBrains Mono** (Rasmus Andersson / JetBrains)
   - Uso: Tipografia de interface e blocos de código via Google Fonts.
   - Licença: SIL Open Font License 1.1
   - Referência: https://fonts.google.com/

4. **PyPI JSON API & Python End-of-Life** (Python Software Foundation)
   - Uso: Verificação de existência de pacotes declarados contra alucinações de IA e consulta da versão oficial mais recente do Python.
   - Referência: https://pypi.org/

5. **OSV.dev Vulnerability Database API** (Google Open Source Security Team)
   - Uso: Consulta de vulnerabilidades conhecidas (CVEs) em pacotes Python.
   - Licença / Termos: Apache-2.0 / OSV Schema
   - Referência: https://osv.dev/
