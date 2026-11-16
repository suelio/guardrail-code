# guardrail code

Auditor rápido de segurança, vazamento de segredos, higiene Git, ambiente Python e guardrails para projetos desenvolvidos com auxílio de IA ("vibe coding") e ciência de dados.

## Visão geral

Construído com biblioteca padrão do Python (`os.scandir`, `ast`, `re`, `json`, `gc`, `urllib.request`) para varredura rápida com limpeza explícita de memória RAM após cada execução, interface web Flask + Bootstrap 5 bilíngue (PT-BR e EN), zero execução automática na abertura da página e catálogo interativo de testes agrupados por bloco (`/testes`).

### Recursos principais

1. **Segurança e credenciais (`SECRETS`)**
   - Detecta chaves OpenAI, Google/Gemini, AWS, GitHub, Stripe, JWTs literais, chaves privadas PEM/SSH e atribuições sensíveis com mascaramento automático do valor encontrado.
2. **Banco de dados e arquivos (`EXPOSED_DATA`)**
   - Identifica URIs de banco com senha, arquivos `.env` sem `.gitignore`, bancos locais (`.sqlite`, `.db`, `.duckdb`) dentro de pastas públicas (`public/`, `static/`, `htdocs/`) e `debug=True` ou `CORS(*)` irrestrito.
3. **Deploy e configuração (`DEPLOY_TRAPS`)**
   - Sinaliza URLs apontando para `localhost`/`127.0.0.1` (exceto fallbacks via `os.getenv`) e caminhos locais fixos (`C:\Users\...`, `/home/...`).
4. **Ciência de dados e SAST (`SAST_DS`)**
   - Analisa código `.py` e notebooks `.ipynb` para detectar SQL Injection, desserialização insegura (`pickle.load`, `joblib.load`, `torch.load` sem `weights_only=True`, `yaml.load` sem `SafeLoader`), `eval`/`exec`/`shell=True`, `verify=False` e outputs salvos em notebooks.
5. **Git e versionamento (`GIT_HYGIENE`)**
   - Audita cobertura do `.gitignore`, verifica `git ls-files` e adiciona regras essenciais com modal de confirmação antes de modificar o repositório.
6. **Auditoria de ambiente, runtime e módulos (`ENVIRONMENT`)**
   - Compara o Python local com a última versão oficial, detecta pacotes possivelmente alucinados por IA (HTTP 404 no PyPI), consulta CVEs na API OSV.dev e exige confirmação explícita antes de qualquer atualização, avisando que eventual downgrade precisa ser feito manualmente.
7. **Menu criar skill e guardrail IA (`/vibe-coding-guardrail`)**
   - Gera skills, regras e templates no idioma ativo do usuário (PT-BR ou EN), com construtor interativo por checkboxes e instalação em 1 clique (`SKILL.md`, `GEMINI.md`, `CLAUDE.md`, `.cursorrules`).
8. **Catálogo de testes, blocos e atualizações pelo GitHub (`/testes`)**
   - Separa as verificações por blocos temáticos, permite ativar ou desativar qualquer regra individualmente, oferece o botão `+ Adicionar mais testes` (módulos opcionais e regras regex customizadas) e permite verificar e baixar novos módulos direto do repositório oficial no GitHub (`https://github.com/suelio/guardrail-code`).
9. **Gestão de memória e persistência de sessão**
   - Executa coleta explícita de lixo (`gc.collect(2)` e liberação de working set) ao final das varreduras e preserva o estado da auditoria no navegador ao alternar entre abas ou páginas, limpando tudo pelo botão `Limpar dados`.

## Como executar

1. Iniciar o servidor web (porta `5006`):
   ```powershell
   python app.py
   ```
   Acesse `http://127.0.0.1:5006` no navegador (ou `http://127.0.0.1:5006/testes` para o catálogo de testes).

2. Executar a suíte de testes automatizados:
   ```powershell
   python -m unittest discover tests -v
   ```

## Licença e atribuições

- Distribuído sob a **Licença MIT** — consulte [LICENSE](LICENSE).
- Créditos de bibliotecas e APIs públicas utilizadas constam em [ATTRIBUTIONS.md](ATTRIBUTIONS.md).
