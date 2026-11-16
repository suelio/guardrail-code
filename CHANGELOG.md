# Changelog

## [0.1.0-beta] - 2026-11-16

### Adicionado
- Auditor estático rápido em Python (`os.scandir`, `ast`, `re`) para credenciais, bancos expostos, armadilhas de deploy, SAST em Python/Jupyter e higiene Git.
- Interface web Flask bilíngue (PT-BR e EN) sob o nome `guardrail code`, com persistência de resultados entre abas, overlay de carregamento e botão `Limpar dados`.
- Subpágina `/testes` com regras organizadas por blocos temáticos, ativação/desativação individual, módulos opcionais, regras regex customizadas e verificação/download de atualizações via GitHub.
- Gerador e instalador de guardrails e skills (`/vibe-coding-guardrail`, `GEMINI.md`, `CLAUDE.md`, `.cursorrules`) no idioma ativo.
- Gestão explícita de memória (`core/memory_manager.py` com `gc.collect(2)` e liberação de working set) e controles de segurança contra SSRF, ReDoS, command injection e path traversal.
- Licença MIT (`LICENSE`), atribuições (`ATTRIBUTIONS.md`), CI via GitHub Actions e página estática para GitHub Pages (`docs/index.html`).
