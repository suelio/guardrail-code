document.addEventListener('DOMContentLoaded', () => {
    const targetDirInput = document.getElementById('targetDirInput');
    const btnRunAudit = document.getElementById('btnRunAudit');
    const btnClearData = document.getElementById('btnClearData');
    const btnPickFolder = document.getElementById('btnPickFolder');
    const btnIdleBrowse = document.getElementById('btnIdleBrowse');
    const findingSearchInput = document.getElementById('findingSearchInput');

    const idleStateCard = document.getElementById('idleStateCard');
    const findingsToolbar = document.getElementById('findingsToolbar');
    const liveScanProvenance = document.getElementById('liveScanProvenance');
    const findingsList = document.getElementById('findingsList');
    const gitChecklistContainer = document.getElementById('gitChecklistContainer');
    const gitTrackedContainer = document.getElementById('gitTrackedContainer');
    const packagesTableWrap = document.getElementById('packagesTableWrap');
    const updateCommandLog = document.getElementById('updateCommandLog');

    const confirmUpdateModalEl = document.getElementById('confirmUpdateModal');
    const confirmUpdateModal = new bootstrap.Modal(confirmUpdateModalEl);
    const confirmGitModalEl = document.getElementById('confirmGitModal');
    const confirmGitModal = new bootstrap.Modal(confirmGitModalEl);
    const scanLoadingOverlay = document.getElementById('scanLoadingOverlay');
    const loadingTitle = document.getElementById('loadingTitle');
    const loadingStepText = document.getElementById('loadingStepText');
    const loadingProgressBar = document.getElementById('loadingProgressBar');

    let lastScanData = null;
    let lastEnvData = null;
    let pendingUpdateRequest = null;
    let currentCategoryFilter = 'ALL';
    let currentLang = localStorage.getItem('app_lang') === 'en' ? 'en' : 'pt';
    let customSkillMeta = null;

    const I18N = {
        pt: {
            docTitle: 'guardrail code — Auditor de segurança e ambiente',
            brandTitle: 'guardrail code',
            brandSub: 'Auditor de segurança, segredos, Git e ambiente Python',
            navAuditor: 'Auditor de projeto',
            navCreateSkill: 'Criar skill e guardrail',
            navTestsCatalog: 'Todos os testes',
            btnExportReport: 'Exportar relatório',
            btnHtml: 'Relatório HTML (impressão / PDF)',
            btnMd: 'Baixar Markdown (.md)',
            btnJson: 'Baixar dados estruturados (.json)',
            stepTargetLabel: 'Aponte a pasta do seu projeto local para verificar antes de publicar',
            btnPickFolder: 'Procurar pasta',
            btnClearData: 'Limpar dados',
            btnRunText: 'Executar verificação',
            kpiDeployStatus: 'Status de publicação',
            kpiWaiting: 'Nenhuma verificação executada',
            kpiWaitingSub: 'Escolha uma pasta e clique em Executar verificação.',
            kpiGitTitle: 'Proteção Git e .gitignore',
            kpiPyTitle: 'Ambiente e módulos',
            kpiSpeedTitle: 'Desempenho',
            kpiNotScanned: 'Aguardando pasta',
            headerIdleState: 'Nenhuma pasta carregada',
            idleTitle: 'Nenhum código foi analisado ainda',
            idleDesc: 'Este painel não carrega exemplos ou resultados prontos ao abrir. Selecione a pasta real do seu projeto no campo acima e clique em "Executar verificação" para auditar seus arquivos locais.',
            btnIdleBrowse: 'Escolher pasta do projeto agora',
            tab1: '1. Diagnóstico e correções',
            tab2: '2. Proteção Git e .gitignore',
            tab3: '3. Ambiente, runtime e módulos',
            tab4: '4. Criar skill e guardrail',
            catAll: 'Todos',
            catSecrets: 'Segurança e credenciais',
            catExposed: 'Banco de dados e arquivos',
            catDeploy: 'Deploy e configuração',
            catSast: 'Ciência de dados e SAST',
            catGit: 'Git e versionamento',
            searchPlaceholder: 'Filtrar por arquivo ou erro...',
            gitChecklistTitle: 'Checklist do arquivo .gitignore',
            gitChecklistSub: 'Verifica se segredos, bancos SQLite/DuckDB e modelos .pkl estão bloqueados antes de qualquer commit.',
            btnFixGit: 'Corrigir e blindar .gitignore automaticamente',
            gitTrackedTitle: 'Arquivos rastreados indevidamente',
            gitTrackedSub: 'Arquivos adicionados ao Git antes do .gitignore continuam sendo enviados. Veja abaixo se algum arquivo crítico aparece no histórico local:',
            tabNeedScan: 'Execute uma verificação de pasta para preencher o checklist do .gitignore.',
            pyRuntimeBadge: 'Auditoria de ambiente, runtime e módulos',
            envNeedScan: 'Escolha uma pasta e clique em Executar verificação para auditar o runtime e as dependências.',
            envFutureNotice: 'Atualmente audita Python, PyPI e CVEs da base OSV.dev, preparado para receber novos módulos de linguagens e infraestrutura.',
            btnCopyCmd: 'Copiar comando',
            btnUpgradePy: 'Atualizar Python',
            pkgTableTitle: 'Dependências, pacotes alucinados e vulnerabilidades (PyPI + OSV.dev)',
            btnRevalidatePypi: 'Revalidar ambiente',
            envTableIdle: 'Nenhuma auditoria de dependências executada ainda.',
            skillGuideBadge: 'Guia prático',
            skillGuideTitle: 'Como criar sua própria skill (passo a passo)',
            customBuilderTitle: 'Gerar skill personalizada',
            lblSkillSlug: 'Nome do comando (/):',
            lblDeployTrigger: 'Frase que libera deploy:',
            btnBuildCustomSkill: 'Gerar skill customizada no editor ao lado',
            lblPickTemplate: 'Modelos prontos (incluindo /vibe-coding-guardrail, GEMINI.md e .cursorrules):',
            btnInstallGuardrail: 'Salvar no projeto selecionado',
            btnCopyGuardrail: 'Copiar conteúdo',
            btnDownloadGuardrail: 'Baixar arquivo',
            modalFolderTitle: 'Escolher pasta do projeto',
            modalFolderSub: 'Navegue pelas pastas locais ou selecione um local base abaixo.',
            btnFolderUp: 'Subir pasta (..)',
            btnFolderConfirm: 'Selecionar esta pasta',
            confirmUpdTitle: 'Confirmar atualização no ambiente',
            confirmUpdWarnTitle: 'Aviso importante sobre reversão:',
            confirmUpdWarnBody: 'Depois de atualizado, se você precisar voltar para uma versão anterior (downgrade) por incompatibilidade em algum projeto, essa reversão terá que ser feita manualmente pelo terminal.',
            btnCancel: 'Cancelar',
            btnConfirmRunUpdate: 'Confirmar e atualizar agora',
            confirmGitTitle: 'Confirmar alteração no .gitignore',
            confirmGitNoteTitle: 'O que será feito no repositório:',
            confirmGitNoteBody: 'As regras ausentes acima serão acrescentadas ao arquivo .gitignore do projeto (criando o arquivo se ele não existir). Arquivos já rastreados no Git continuam precisando de git rm --cached manualmente.',
            btnConfirmRunGit: 'Confirmar e aplicar regras',
            riskBoxLabel: 'Riscos encontrados',
            fixBoxLabel: 'Como resolver',
            fixExampleLabel: 'Exemplo corrigido:',
            copyExampleBtn: 'Copiar exemplo',
            disableRuleBtn: 'Desativar este teste',
            fileWord: 'Arquivo',
            lineWord: 'Linha',
            rulesOk: 'regras OK',
            protected: 'Protegido',
            exposed: 'Exposto',
            scanning: 'Escaneando arquivos reais...',
            noFindingsTitle: 'Nenhum alerta neste filtro',
            noFindingsSub: 'Tudo limpo para esta categoria de verificação.',
            selectBtn: 'Selecionar',
            noSubfolders: 'Nenhuma subpasta encontrada aqui.',
            noGitRepo: 'Esta pasta ainda não possui repositório <code>.git</code> inicializado.',
            gitTrackedClean: 'Nenhum arquivo sensível rastreado pelo <code>git ls-files</code>.',
        },
        en: {
            docTitle: 'guardrail code — Security and environment auditor',
            brandTitle: 'guardrail code',
            brandSub: 'Security, secrets, Git, and Python environment auditor',
            navAuditor: 'Project auditor',
            navCreateSkill: 'Create skill and guardrail',
            navTestsCatalog: 'All tests',
            btnExportReport: 'Export report',
            btnHtml: 'HTML report (print / PDF)',
            btnMd: 'Download Markdown (.md)',
            btnJson: 'Download structured data (.json)',
            stepTargetLabel: 'Point to your local project folder to inspect before publishing',
            btnPickFolder: 'Browse folder',
            btnClearData: 'Clear data',
            btnRunText: 'Run security scan',
            kpiDeployStatus: 'Publish status',
            kpiWaiting: 'No scan executed yet',
            kpiWaitingSub: 'Pick a folder and click Run security scan.',
            kpiGitTitle: 'Git and .gitignore guard',
            kpiPyTitle: 'Environment and modules',
            kpiSpeedTitle: 'Performance',
            kpiNotScanned: 'Waiting for folder',
            headerIdleState: 'No folder loaded',
            idleTitle: 'No source code has been scanned yet',
            idleDesc: 'This dashboard does not preload sample projects on startup. Pick your real local folder above and click Run security scan to inspect your files.',
            btnIdleBrowse: 'Choose project folder now',
            tab1: '1. Findings and fixes',
            tab2: '2. Git and .gitignore protection',
            tab3: '3. Environment, runtime, and modules',
            tab4: '4. Create skill and guardrail',
            catAll: 'All',
            catSecrets: 'Security and credentials',
            catExposed: 'Databases and files',
            catDeploy: 'Deploy and configuration',
            catSast: 'Data science and SAST',
            catGit: 'Git and versioning',
            searchPlaceholder: 'Filter by file or finding...',
            gitChecklistTitle: '.gitignore coverage checklist',
            gitChecklistSub: 'Checks whether secrets, local SQLite/DuckDB databases, and .pkl models are blocked prior to any commit.',
            btnFixGit: 'Fix and harden .gitignore automatically',
            gitTrackedTitle: 'Tracked sensitive files',
            gitTrackedSub: 'Files committed before updating .gitignore keep syncing to Git. Inspect any flagged files below:',
            tabNeedScan: 'Run a folder scan to populate the .gitignore checklist.',
            pyRuntimeBadge: 'Environment, runtime, and modules audit',
            envNeedScan: 'Choose a folder and click Run security scan to inspect your runtime and dependencies.',
            envFutureNotice: 'Currently audits Python, PyPI, and OSV.dev CVEs, structured to support future language and infrastructure modules.',
            btnCopyCmd: 'Copy command',
            btnUpgradePy: 'Upgrade Python',
            pkgTableTitle: 'Dependencies, hallucinated packages, and CVEs (PyPI + OSV.dev)',
            btnRevalidatePypi: 'Re-check environment',
            envTableIdle: 'No dependency audit executed yet.',
            skillGuideBadge: 'Practical guide',
            skillGuideTitle: 'How to create your own skill (step by step)',
            customBuilderTitle: 'Generate custom guardrail skill',
            lblSkillSlug: 'Slash command name (/):',
            lblDeployTrigger: 'Explicit deploy trigger phrase:',
            btnBuildCustomSkill: 'Generate custom skill in editor',
            lblPickTemplate: 'Ready templates (including /vibe-coding-guardrail, GEMINI.md, and .cursorrules):',
            btnInstallGuardrail: 'Save to selected project',
            btnCopyGuardrail: 'Copy content',
            btnDownloadGuardrail: 'Download file',
            modalFolderTitle: 'Choose project folder',
            modalFolderSub: 'Browse local folders or pick a base directory below.',
            btnFolderUp: 'Go up (..)',
            btnFolderConfirm: 'Select this folder',
            confirmUpdTitle: 'Confirm environment update',
            confirmUpdWarnTitle: 'Important rollback notice:',
            confirmUpdWarnBody: 'Once updated, if you need to revert to a previous version due to project compatibility issues, the downgrade must be performed manually via terminal.',
            btnCancel: 'Cancel',
            btnConfirmRunUpdate: 'Confirm and update now',
            confirmGitTitle: 'Confirm .gitignore update',
            confirmGitNoteTitle: 'What will happen in the repository:',
            confirmGitNoteBody: 'The missing rules above will be appended to the project .gitignore file (creating it if absent). Files already tracked by Git still require manual git rm --cached.',
            btnConfirmRunGit: 'Confirm and apply rules',
            riskBoxLabel: 'Identified risks',
            fixBoxLabel: 'How to fix',
            fixExampleLabel: 'Fixed example:',
            copyExampleBtn: 'Copy example',
            disableRuleBtn: 'Disable this test',
            fileWord: 'File',
            lineWord: 'Line',
            rulesOk: 'rules OK',
            protected: 'Protected',
            exposed: 'Exposed',
            scanning: 'Scanning local disk files...',
            noFindingsTitle: 'No alerts in this filter',
            noFindingsSub: 'Everything looks clean for this security category.',
            selectBtn: 'Select',
            noSubfolders: 'No subfolders found here.',
            noGitRepo: 'This folder does not contain an initialized <code>.git</code> repository yet.',
            gitTrackedClean: 'No sensitive files tracked in <code>git ls-files</code>.',
        }
    };

    function t(key) {
        return (I18N[currentLang] && I18N[currentLang][key]) || I18N.pt[key] || key;
    }

    function applyTranslations() {
        document.documentElement.lang = currentLang === 'en' ? 'en' : 'pt-BR';
        document.title = t('docTitle');
        const dynamicIdsWhenLoaded = new Set([
            'activeProjectHeader',
            'kpiVerdict',
            'kpiCountsLine',
            'kpiGitSub',
            'kpiPythonSub',
            'pyPanelHeadline',
            'pyPanelDetails',
            'pkgSourceLabel',
        ]);
        document.querySelectorAll('[data-i18n]').forEach(el => {
            if ((lastScanData || lastEnvData) && dynamicIdsWhenLoaded.has(el.id)) return;
            el.textContent = t(el.dataset.i18n);
        });
        findingSearchInput.placeholder = t('searchPlaceholder');

        document.querySelectorAll('.lang-switch-btn').forEach(btn => {
            const active = btn.dataset.lang === currentLang;
            btn.className = `btn ${active ? 'btn-dark' : 'btn-outline-secondary'} fw-semibold lang-switch-btn`;
        });
        const testsLink = document.getElementById('navTestsLink');
        if (testsLink) testsLink.href = `/testes?lang=${currentLang}`;

        if (!lastScanData) {
            clearAllAuditState(false);
        }
    }

    document.querySelectorAll('.lang-switch-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.dataset.lang === currentLang) return;
            currentLang = btn.dataset.lang;
            localStorage.setItem('app_lang', currentLang);
            customSkillMeta = null;
            applyTranslations();
            loadGuardrailTemplates();
            if (lastScanData && targetDirInput.value.trim()) {
                runFullAudit();
            }
        });
    });

    // Clear all inputs, KPIs, and loaded scan data back to clean idle state.
    function clearAllAuditState(clearPath = true) {
        if (clearPath) targetDirInput.value = '';
        lastScanData = null;
        lastEnvData = null;
        currentCategoryFilter = 'ALL';
        localStorage.removeItem('gc_target_dir');
        localStorage.removeItem('gc_scan_data');
        localStorage.removeItem('gc_env_data');
        localStorage.removeItem('gc_active_tab');

        liveScanProvenance.style.display = 'none';
        liveScanProvenance.textContent = '';

        document.getElementById('kpiGradeBox').className = 'grade-badge-lg grade-IDLE';
        document.getElementById('kpiGradeLetter').textContent = '-';
        document.getElementById('kpiScoreText').textContent = '0/100';
        document.getElementById('kpiVerdict').textContent = t('kpiWaiting');
        document.getElementById('kpiCountsLine').textContent = t('kpiWaitingSub');

        document.getElementById('kpiGitStatus').textContent = '-';
        document.getElementById('kpiGitStatus').className = 'fw-bold mb-1 text-dark';
        document.getElementById('kpiGitSub').textContent = t('kpiNotScanned');

        document.getElementById('kpiPythonVer').textContent = '-';
        document.getElementById('kpiPythonSub').textContent = t('kpiNotScanned');

        document.getElementById('kpiSpeed').textContent = '0.00s';
        document.getElementById('kpiFiles').textContent = '0';

        document.getElementById('badgeTotalFindings').textContent = '0';
        document.getElementById('badgePkgIssues').textContent = '0';
        document.getElementById('activeProjectHeader').textContent = t('headerIdleState');

        idleStateCard.style.display = 'block';
        findingsToolbar.style.display = 'none';
        findingsList.innerHTML = '';

        document.getElementById('btnFixGitignore').disabled = true;
        gitChecklistContainer.innerHTML = `<div class="text-muted small py-3">${escapeHtml(t('tabNeedScan'))}</div>`;
        gitTrackedContainer.innerHTML = '';

        document.getElementById('pyPanelHeadline').textContent = t('envNeedScan');
        document.getElementById('pyPanelDetails').textContent = t('envFutureNotice');
        document.getElementById('pyUpgradeCmd').textContent = '-';
        document.getElementById('pkgSourceLabel').textContent = '-';
        document.getElementById('btnUpgradePython').disabled = true;
        document.getElementById('btnRefreshPythonAudit').disabled = true;
        packagesTableWrap.innerHTML = `<div class="text-muted small py-2">${escapeHtml(t('envTableIdle'))}</div>`;
        updateCommandLog.style.display = 'none';
    }

    btnClearData.addEventListener('click', () => {
        clearAllAuditState(true);
        showToast(currentLang === 'en' ? 'All scan results and fields cleared.' : 'Todos os dados e resultados foram limpos.', 'info');
    });

    // Inline toast alerts without browser popups.
    let toastTimer = null;
    window.showToast = function(msg, type = 'info') {
        const banner = document.getElementById('toastBanner');
        const alertEl = document.getElementById('toastAlert');
        document.getElementById('toastMessage').textContent = msg;
        alertEl.className = `alert alert-${type} alert-dismissible fade show border-0 shadow-sm mb-0 py-2 px-3 small d-flex justify-content-between align-items-center`;
        banner.style.display = 'block';
        if (toastTimer) clearTimeout(toastTimer);
        toastTimer = setTimeout(() => { banner.style.display = 'none'; }, 6000);
    };
    window.hideToast = function() {
        document.getElementById('toastBanner').style.display = 'none';
    };

    function openSkillCreationMenu() {
        const tabBtn = document.getElementById('tab-guardrail-btn');
        bootstrap.Tab.getOrCreateInstance(tabBtn).show();
        document.getElementById('mainStudioCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    document.getElementById('navCreateSkillBtn').addEventListener('click', openSkillCreationMenu);
    if (window.location.hash === '#guardrail') {
        setTimeout(openSkillCreationMenu, 150);
    }

    // Open built-in interactive browser directory explorer modal.
    const folderModalEl = document.getElementById('folderBrowserModal');
    const folderModal = new bootstrap.Modal(folderModalEl);
    const folderBrowserPathInput = document.getElementById('folderBrowserPathInput');
    const folderBookmarksBar = document.getElementById('folderBookmarksBar');
    const folderBrowserList = document.getElementById('folderBrowserList');
    let currentBrowseParent = '';

    function browseFolder(path) {
        fetch('/api/browse-dirs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path || '' })
        })
        .then(r => r.json())
        .then(data => {
            if (data.status !== 'success') {
                showToast(data.message || 'Erro ao listar pastas locais.', 'warning');
                return;
            }
            folderBrowserPathInput.value = data.current_path;
            currentBrowseParent = data.parent_path || '';
            document.getElementById('btnFolderGoUp').disabled = !currentBrowseParent;

            folderBookmarksBar.innerHTML = (data.bookmarks || []).map(b => `
                <button type="button" class="btn btn-sm btn-outline-secondary rounded-pill px-2 py-0 btn-bookmark-dir" data-path="${escapeAttr(b.path)}">
                    ${escapeHtml(b.label)}
                </button>
            `).join('');
            folderBookmarksBar.querySelectorAll('.btn-bookmark-dir').forEach(btn => {
                btn.addEventListener('click', () => browseFolder(btn.dataset.path));
            });

            if (!data.directories || data.directories.length === 0) {
                folderBrowserList.innerHTML = `<div class="list-group-item text-muted small">${escapeHtml(t('noSubfolders'))}</div>`;
                return;
            }
            folderBrowserList.innerHTML = data.directories.map(d => {
                const badges = (d.markers || []).map(m => `<span class="badge bg-primary-subtle text-primary border border-primary-subtle ms-1">${escapeHtml(m)}</span>`).join('');
                return `
                    <div class="list-group-item list-group-item-action d-flex justify-content-between align-items-center py-2">
                        <button type="button" class="btn btn-link text-start text-decoration-none text-dark fw-semibold p-0 flex-grow-1 btn-drill-dir" data-path="${escapeAttr(d.path)}">
                            ${escapeHtml(d.name)} ${badges}
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-primary rounded-pill px-3 py-0 btn-choose-dir" data-path="${escapeAttr(d.path)}">
                            ${escapeHtml(t('selectBtn'))}
                        </button>
                    </div>
                `;
            }).join('');

            folderBrowserList.querySelectorAll('.btn-drill-dir').forEach(btn => {
                btn.addEventListener('click', () => browseFolder(btn.dataset.path));
            });
            folderBrowserList.querySelectorAll('.btn-choose-dir').forEach(btn => {
                btn.addEventListener('click', () => selectProjectFolder(btn.dataset.path));
            });
        })
        .catch(() => showToast('Falha ao explorar diretórios no servidor.', 'danger'));
    }

    function selectProjectFolder(chosenPath) {
        targetDirInput.value = chosenPath;
        folderModal.hide();
        runFullAudit();
    }

    function openFolderExplorer() {
        browseFolder(targetDirInput.value.trim());
        folderModal.show();
    }
    btnPickFolder.addEventListener('click', openFolderExplorer);
    btnIdleBrowse.addEventListener('click', openFolderExplorer);

    document.getElementById('btnFolderGoUp').addEventListener('click', () => {
        if (currentBrowseParent) browseFolder(currentBrowseParent);
    });
    document.getElementById('btnFolderConfirmSelect').addEventListener('click', () => {
        if (folderBrowserPathInput.value) selectProjectFolder(folderBrowserPathInput.value);
    });

    btnRunAudit.addEventListener('click', runFullAudit);

    document.querySelectorAll('.filter-cat-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-cat-btn').forEach(b => {
                b.classList.remove('btn-dark', 'active');
                b.classList.add('btn-outline-secondary');
            });
            btn.classList.remove('btn-outline-secondary');
            btn.classList.add('btn-dark', 'active');
            currentCategoryFilter = btn.dataset.cat;
            renderFindingsList();
        });
    });
    findingSearchInput.addEventListener('input', renderFindingsList);

    document.getElementById('btnFixGitignore').addEventListener('click', () => {
        const dir = targetDirInput.value.trim();
        if (!dir) return;
        const ga = (lastScanData && lastScanData.git_audit) || {};
        const missing = ga.missing_patterns || [];
        document.getElementById('confirmGitTargetText').textContent = currentLang === 'en'
            ? `Apply protective .gitignore rules to "${dir}"?`
            : `Aplicar regras de proteção no arquivo .gitignore em "${dir}"?`;
        document.getElementById('confirmGitPatternsPreview').textContent = missing.length > 0
            ? missing.join('\n')
            : (currentLang === 'en' ? '# Essential security rules already present (verify/sync)' : '# Regras essenciais já presentes (verificar/sincronizar)');
        confirmGitModal.show();
    });

    document.getElementById('btnConfirmExecuteGit').addEventListener('click', () => {
        const dir = targetDirInput.value.trim();
        confirmGitModal.hide();
        if (!dir) return;
        fetch('/api/fix-gitignore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_dir: dir, lang: currentLang })
        })
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                showToast(data.message, 'success');
                if (data.scan_result) {
                    lastScanData = data.scan_result;
                    saveAuditSessionState();
                    renderScanResults(lastScanData);
                }
            } else {
                showToast(data.message || 'Falha ao atualizar .gitignore.', 'danger');
            }
        })
        .catch(() => showToast('Erro de comunicação ao atualizar .gitignore.', 'danger'));
    });

    document.getElementById('btnRefreshPythonAudit').addEventListener('click', runPythonEnvAudit);
    document.getElementById('btnCopyPyCmd').addEventListener('click', () => {
        const cmd = document.getElementById('pyUpgradeCmd').textContent;
        if (!cmd || cmd === '-') return;
        navigator.clipboard.writeText(cmd).then(() => showToast(
            currentLang === 'en' ? 'Upgrade command copied.' : 'Comando de atualização copiado.',
            'success'
        ));
    });

    // Open mandatory confirmation modal before running any package or Python upgrade.
    function requestUpdateWithConfirmation(action, pkgName, pySeries) {
        pendingUpdateRequest = { action, pkgName, pySeries };
        let targetText = '';
        let cmdPreview = '';
        if (action === 'upgrade_python') {
            targetText = currentLang === 'en'
                ? `You are about to upgrade Python to series ${pySeries}.`
                : `Você está prestes a atualizar o Python para a série ${pySeries}.`;
            cmdPreview = (lastEnvData && lastEnvData.runtime && lastEnvData.runtime.recommended_command) || `conda install -y python=${pySeries}`;
        } else {
            targetText = currentLang === 'en'
                ? `You are about to upgrade package "${pkgName}" to the latest PyPI version.`
                : `Você está prestes a atualizar o pacote "${pkgName}" para a versão mais recente do PyPI.`;
            cmdPreview = `python -m pip install --upgrade ${pkgName}`;
        }
        document.getElementById('confirmUpdTargetText').textContent = targetText;
        document.getElementById('confirmUpdCmdPreview').textContent = cmdPreview;
        confirmUpdateModal.show();
    }

    document.getElementById('btnUpgradePython').addEventListener('click', () => {
        if (!lastEnvData || !lastEnvData.runtime) return;
        const series = lastEnvData.runtime.latest_official_series || '3.13';
        requestUpdateWithConfirmation('upgrade_python', '', series);
    });

    document.getElementById('btnConfirmExecuteUpdate').addEventListener('click', () => {
        if (!pendingUpdateRequest) return;
        const { action, pkgName, pySeries } = pendingUpdateRequest;
        confirmUpdateModal.hide();
        executeEnvUpdate(action, pkgName, pySeries);
    });

    document.getElementById('btnExportHtml').addEventListener('click', () => exportReport('html'));
    document.getElementById('btnExportMd').addEventListener('click', () => exportReport('markdown'));
    document.getElementById('btnExportJson').addEventListener('click', () => exportReport('json'));

    function saveAuditSessionState() {
        try {
            localStorage.setItem('gc_target_dir', targetDirInput.value.trim());
            if (lastScanData) localStorage.setItem('gc_scan_data', JSON.stringify(lastScanData));
            if (lastEnvData) localStorage.setItem('gc_env_data', JSON.stringify(lastEnvData));
        } catch (err) {
            // Ignore storage quota errors cleanly.
        }
    }

    function sleepMs(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function runFullAudit() {
        const targetDir = targetDirInput.value.trim();
        if (!targetDir) {
            showToast(
                currentLang === 'en' ? 'Choose a folder before running the security scan.' : 'Escolha a pasta do seu projeto antes de clicar em Executar verificação.',
                'warning'
            );
            return;
        }

        const isEn = currentLang === 'en';
        loadingTitle.textContent = isEn ? 'Scanning project security...' : 'Analisando segurança do projeto...';
        loadingStepText.textContent = isEn ? 'Reading local files and active rules...' : 'Lendo arquivos locais e verificando regras ativas...';
        loadingProgressBar.style.width = '30%';
        scanLoadingOverlay.style.display = 'flex';

        const step1Timer = setTimeout(() => {
            loadingStepText.textContent = isEn ? 'Inspecting Python AST, secrets, and Git hygiene...' : 'Analisando AST Python, credenciais e proteção Git...';
            loadingProgressBar.style.width = '70%';
        }, 350);
        const step2Timer = setTimeout(() => {
            loadingStepText.textContent = isEn ? 'Consolidating findings and score...' : 'Consolidando achados e calculando nota...';
            loadingProgressBar.style.width = '92%';
        }, 720);

        document.getElementById('activeProjectHeader').textContent = t('scanning');
        const scanPromise = fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_dir: targetDir, lang: currentLang })
        }).then(r => r.json());

        Promise.all([scanPromise, sleepMs(1050)])
            .then(([data]) => {
                clearTimeout(step1Timer);
                clearTimeout(step2Timer);
                loadingProgressBar.style.width = '100%';
                scanLoadingOverlay.style.display = 'none';
                if (data.status === 'success') {
                    lastScanData = data;
                    saveAuditSessionState();
                    renderScanResults(data);
                } else {
                    showToast(data.message || 'Erro ao escanear diretório.', 'danger');
                }
            })
            .catch(() => {
                clearTimeout(step1Timer);
                clearTimeout(step2Timer);
                scanLoadingOverlay.style.display = 'none';
                showToast('Falha na comunicação com o servidor.', 'danger');
            });

        runPythonEnvAudit();
    }

    function runPythonEnvAudit() {
        const targetDir = targetDirInput.value.trim();
        if (!targetDir) return;
        document.getElementById('kpiPythonVer').textContent = '...';
        fetch('/api/check-python', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_dir: targetDir, lang: currentLang })
        })
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                lastEnvData = data;
                saveAuditSessionState();
                renderPythonEnv(data);
            }
        })
        .catch(() => {
            document.getElementById('kpiPythonVer').textContent = 'Offline';
        });
    }

    function renderScanResults(data) {
        idleStateCard.style.display = 'none';
        findingsToolbar.style.display = 'block';

        liveScanProvenance.style.display = 'block';
        liveScanProvenance.textContent = currentLang === 'en'
            ? `Live scan completed directly on "${data.target_dir}" at ${data.scan_timestamp} (${data.files_scanned} files read from disk; ${data.active_rules_count} active tests, ${data.disabled_rules_count} disabled).`
            : `Verificação executada ao vivo em "${data.target_dir}" às ${data.scan_timestamp} (${data.files_scanned} arquivos reais lidos do disco; ${data.active_rules_count} testes ativos, ${data.disabled_rules_count} desativados).`;

        document.getElementById('activeProjectHeader').textContent = `${data.project_name} (${data.target_dir})`;

        const gradeBox = document.getElementById('kpiGradeBox');
        gradeBox.className = `grade-badge-lg grade-${data.grade}`;
        document.getElementById('kpiGradeLetter').textContent = data.grade;
        document.getElementById('kpiScoreText').textContent = `${data.score}/100`;
        document.getElementById('kpiVerdict').textContent = data.verdict;

        const sc = data.severity_counts || {};
        document.getElementById('kpiCountsLine').textContent = currentLang === 'en'
            ? `${sc.CRITICAL || 0} critical, ${sc.HIGH || 0} high, ${sc.MEDIUM || 0} medium, ${sc.LOW || 0} low`
            : `${sc.CRITICAL || 0} críticos, ${sc.HIGH || 0} altos, ${sc.MEDIUM || 0} médios, ${sc.LOW || 0} baixos`;

        document.getElementById('kpiSpeed').textContent = `${(Number(data.scan_time_ms || 0) / 1000).toFixed(2)}s`;
        document.getElementById('kpiFiles').textContent = currentLang === 'en'
            ? `${data.files_scanned} files (${data.total_lines} lines)`
            : `${data.files_scanned} arquivos (${data.total_lines} linhas)`;
        document.getElementById('badgeTotalFindings').textContent = data.total_findings;

        const ga = data.git_audit || {};
        const gitOk = ga.protected_count === ga.total_rules && (!ga.tracked_sensitive_files || ga.tracked_sensitive_files.length === 0);
        document.getElementById('kpiGitStatus').textContent = `${ga.protected_count || 0}/${ga.total_rules || 0} ${t('rulesOk')}`;
        document.getElementById('kpiGitStatus').className = `fw-bold mb-1 ${gitOk ? 'text-success' : 'text-danger'}`;
        if (currentLang === 'en') {
            document.getElementById('kpiGitSub').textContent = ga.has_gitignore
                ? (ga.missing_patterns && ga.missing_patterns.length ? `${ga.missing_patterns.length} gap(s) in .gitignore` : 'Essential protection complete')
                : 'Missing .gitignore file!';
        } else {
            document.getElementById('kpiGitSub').textContent = ga.has_gitignore
                ? (ga.missing_patterns && ga.missing_patterns.length ? `${ga.missing_patterns.length} lacuna(s) no .gitignore` : 'Blindagem essencial completa')
                : 'Sem arquivo .gitignore!';
        }

        document.getElementById('btnFixGitignore').disabled = false;
        renderFindingsList();
        renderGitTab(ga);
    }

    function renderFindingsList() {
        if (!lastScanData) return;
        const query = findingSearchInput.value.trim().toLowerCase();
        const filtered = (lastScanData.findings || []).filter(f => {
            if (currentCategoryFilter !== 'ALL' && f.category !== currentCategoryFilter) return false;
            if (query) {
                const hay = `${f.title} ${f.file_path} ${f.rule_id} ${f.plain_why}`.toLowerCase();
                if (!hay.includes(query)) return false;
            }
            return true;
        });

        if (filtered.length === 0) {
            findingsList.innerHTML = `
                <div class="alert alert-success border-0 rounded-4 p-4 mb-0">
                    <h6 class="fw-bold mb-1">${escapeHtml(t('noFindingsTitle'))}</h6>
                    <span class="small">${escapeHtml(t('noFindingsSub'))}</span>
                </div>`;
            return;
        }

        findingsList.innerHTML = '';
        filtered.forEach(f => {
            const card = document.createElement('div');
            card.className = `finding-card sev-${f.severity} p-3`;
            const fixExampleHtml = f.fix_example
                ? `<div class="mt-2 position-relative">
                       <div class="d-flex justify-content-between align-items-center mb-1">
                           <span class="small fw-semibold text-success-emphasis">${escapeHtml(t('fixExampleLabel'))}</span>
                           <button type="button" class="btn btn-sm btn-outline-success py-0 px-2 btn-copy-fix">${escapeHtml(t('copyExampleBtn'))}</button>
                       </div>
                       <pre class="snippet-code mb-0">${escapeHtml(f.fix_example)}</pre>
                   </div>`
                : '';

            card.innerHTML = `
                <div class="d-flex justify-content-between align-items-start flex-wrap gap-2 mb-2">
                    <div class="d-flex align-items-center flex-wrap gap-2">
                        <span class="sev-pill sev-pill-${f.severity}">${escapeHtml(f.severity)}</span>
                        <span class="badge bg-light text-dark border">${escapeHtml(f.category_label)}</span>
                        <h6 class="fw-bold mb-0 text-dark">${escapeHtml(f.title)}</h6>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        <code class="small text-secondary">${escapeHtml(f.rule_id)}</code>
                        <button type="button" class="btn btn-sm btn-outline-secondary rounded-pill px-2 py-0 btn-disable-rule" data-rule-id="${escapeAttr(f.rule_id)}">
                            ${escapeHtml(t('disableRuleBtn'))}
                        </button>
                    </div>
                </div>

                <div class="small text-secondary mb-2">
                    ${escapeHtml(t('fileWord'))}: <strong class="font-monospace text-dark">${escapeHtml(f.file_path)}</strong> &bull; ${escapeHtml(t('lineWord'))} <strong>${f.line}</strong>
                </div>

                <pre class="snippet-code mb-3">${escapeHtml(f.snippet)}</pre>

                <div class="row g-2">
                    <div class="col-md-6">
                        <div class="dummy-explain-box p-3 h-100">
                            <span class="fw-bold small text-dark d-block mb-1">${escapeHtml(t('riskBoxLabel'))}</span>
                            <p class="small text-secondary mb-0">${escapeHtml(f.plain_why)}</p>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="dummy-fix-box p-3 h-100">
                            <span class="fw-bold small text-success-emphasis d-block mb-1">${escapeHtml(t('fixBoxLabel'))}</span>
                            <p class="small text-dark mb-0">${escapeHtml(f.how_to_fix)}</p>
                            ${fixExampleHtml}
                        </div>
                    </div>
                </div>
            `;

            const copyBtn = card.querySelector('.btn-copy-fix');
            if (copyBtn) {
                copyBtn.addEventListener('click', () => {
                    navigator.clipboard.writeText(f.fix_example).then(() => showToast(
                        currentLang === 'en' ? 'Fix example copied.' : 'Exemplo de correção copiado.',
                        'success'
                    ));
                });
            }

            card.querySelector('.btn-disable-rule').addEventListener('click', () => {
                fetch('/api/tests/toggle-rule', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ rule_id: f.rule_id, enabled: false, lang: currentLang })
                })
                .then(r => r.json())
                .then(res => {
                    if (res.status === 'success') {
                        showToast(
                            currentLang === 'en'
                                ? `Test ${f.rule_id} disabled. Re-enable anytime under All tests.`
                                : `Teste ${f.rule_id} desativado. Você pode reativar quando quiser em Todos os testes.`,
                            'info'
                        );
                        runFullAudit();
                    }
                });
            });

            findingsList.appendChild(card);
        });
    }

    function renderGitTab(ga) {
        const rows = (ga.checklist || []).map(item => `
            <tr>
                <td class="font-monospace fw-semibold">${escapeHtml(item.pattern)}</td>
                <td>${escapeHtml(item.description)}</td>
                <td><span class="sev-pill sev-pill-${item.severity}">${item.severity}</span></td>
                <td>
                    ${item.covered
                        ? `<span class="badge bg-success-subtle text-success border border-success-subtle">${escapeHtml(t('protected'))}</span>`
                        : `<span class="badge bg-danger-subtle text-danger border border-danger-subtle">${escapeHtml(t('exposed'))}</span>`}
                </td>
            </tr>
        `).join('');

        const hPat = currentLang === 'en' ? 'Pattern' : 'Padrão';
        const hProt = currentLang === 'en' ? 'Covers' : 'O que protege';
        const hRisk = currentLang === 'en' ? 'Risk' : 'Risco';
        gitChecklistContainer.innerHTML = `
            <table class="table table-sm align-middle mb-0">
                <thead class="table-light">
                    <tr><th>${hPat}</th><th>${hProt}</th><th>${hRisk}</th><th>Status</th></tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;

        if (!ga.is_git_repo) {
            gitTrackedContainer.innerHTML = `<div class="alert alert-light border mb-0">${t('noGitRepo')}</div>`;
        } else if (!ga.tracked_sensitive_files || ga.tracked_sensitive_files.length === 0) {
            gitTrackedContainer.innerHTML = `<div class="alert alert-success border-0 mb-0">${t('gitTrackedClean')}</div>`;
        } else {
            const hdr = currentLang === 'en' ? 'Attention:' : 'Atenção:';
            const sub = currentLang === 'en' ? 'These sensitive files are already indexed by Git:' : 'Estes arquivos já estão no índice do Git:';
            gitTrackedContainer.innerHTML = `
                <div class="alert alert-danger border-0">
                    <strong>${hdr}</strong> ${sub}
                    <ul class="mb-2 mt-1 ps-3 font-monospace">${ga.tracked_sensitive_files.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul>
                    <small><code>git rm --cached "file"</code></small>
                </div>
            `;
        }
    }

    function renderPythonEnv(data) {
        const rt = data.runtime || {};
        const sm = data.summary || {};

        document.getElementById('btnUpgradePython').disabled = false;
        document.getElementById('btnRefreshPythonAudit').disabled = false;

        document.getElementById('kpiPythonVer').textContent = `Python ${rt.current_version}`;
        document.getElementById('kpiPythonSub').textContent = `${currentLang === 'en' ? 'Official' : 'Oficial'}: ${rt.latest_official_version} (${rt.status_label})`;

        document.getElementById('pyPanelHeadline').textContent = currentLang === 'en'
            ? `Installed Python: ${rt.current_version} | Latest official (${rt.source}): ${rt.latest_official_version}`
            : `Python instalado: ${rt.current_version} | Última versão oficial (${rt.source}): ${rt.latest_official_version}`;

        document.getElementById('pyPanelDetails').textContent = currentLang === 'en'
            ? `${rt.status_label} (End of life for series ${rt.current_series}: ${rt.eol_date}). ${rt.is_anaconda ? 'Anaconda environment active.' : 'Standard Python runtime.'}`
            : `${rt.status_label} (Fim de suporte da série ${rt.current_series}: ${rt.eol_date}). ${rt.is_anaconda ? 'Ambiente Anaconda detectado.' : 'Ambiente Python padrão.'}`;

        document.getElementById('pyUpgradeCmd').textContent = rt.recommended_command || '';

        const totalIssues = (sm.vulnerable || 0) + (sm.hallucinated || 0) + (sm.outdated || 0);
        document.getElementById('badgePkgIssues').textContent = totalIssues;
        document.getElementById('pkgSourceLabel').textContent = currentLang === 'en'
            ? (data.package_source === 'requirements.txt'
                ? 'Inspecting dependencies listed in target requirements.txt.'
                : 'No requirements.txt found — inspecting core installed packages in this environment.')
            : (data.package_source === 'requirements.txt'
                ? 'Lendo dependências declaradas no requirements.txt do projeto alvo.'
                : 'Projeto sem requirements.txt — auditando pacotes principais instalados neste ambiente.');

        const pkgs = data.packages || [];
        if (pkgs.length === 0) {
            packagesTableWrap.innerHTML = `<div class="text-muted small">${currentLang === 'en' ? 'No packages found.' : 'Nenhum pacote encontrado para auditar.'}</div>`;
            return;
        }

        const rowsHtml = pkgs.map(p => {
            let statusBadge = '<span class="badge bg-success-subtle text-success">OK</span>';
            let vulnText = `<span class="text-muted small">${currentLang === 'en' ? 'No known CVEs' : 'Nenhuma CVE conhecida'}</span>`;

            if (p.status === 'HALLUCINATED') {
                statusBadge = `<span class="badge bg-danger text-white">${currentLang === 'en' ? 'HALLUCINATED (PyPI 404)' : 'ALUCINADO (404 no PyPI)'}</span>`;
                vulnText = `<span class="text-danger small fw-semibold">${currentLang === 'en' ? 'Package missing on PyPI! High slopsquatting supply-chain risk.' : 'Este nome não existe no PyPI! Risco de ataque supply-chain (slopsquatting).'}</span>`;
            } else if (p.status === 'VULNERABLE') {
                statusBadge = `<span class="badge bg-danger text-white">${currentLang === 'en' ? 'VULNERABLE' : 'VULNERÁVEL'} (${p.vulnerabilities.length} CVE)</span>`;
                vulnText = p.vulnerabilities.map(v => `<div class="small text-danger"><strong>${escapeHtml(v.id)}</strong>: ${escapeHtml(v.summary)}</div>`).join('');
            } else if (p.status === 'OUTDATED') {
                statusBadge = `<span class="badge bg-warning-subtle text-warning-emphasis border border-warning-subtle">${currentLang === 'en' ? 'Outdated' : 'Desatualizado'}</span>`;
            }

            const upgLabel = currentLang === 'en' ? 'Upgrade' : 'Atualizar';
            const actionBtn = p.status !== 'HALLUCINATED' && (p.outdated || p.status === 'VULNERABLE')
                ? `<button type="button" class="btn btn-sm btn-outline-primary rounded-pill px-3 py-0 btn-upgrade-pkg" data-pkg="${escapeAttr(p.name)}">${upgLabel}</button>`
                : '<span class="text-muted small">-</span>';

            return `
                <tr>
                    <td class="font-monospace fw-bold">${escapeHtml(p.name)}</td>
                    <td class="font-monospace small">${escapeHtml(p.declared_spec)} (inst: ${escapeHtml(p.installed_version)})</td>
                    <td class="font-monospace small">${escapeHtml(p.latest_pypi || '-')}</td>
                    <td>${statusBadge}</td>
                    <td>${vulnText}</td>
                    <td>${actionBtn}</td>
                </tr>
            `;
        }).join('');

        const hPkg = currentLang === 'en' ? 'Package' : 'Pacote';
        const hCur = currentLang === 'en' ? 'In use' : 'Versão em uso';
        const hOff = currentLang === 'en' ? 'PyPI latest' : 'PyPI oficial';
        const hVul = currentLang === 'en' ? 'Vulnerabilities (OSV.dev)' : 'Vulnerabilidades (OSV.dev)';
        const hAct = currentLang === 'en' ? 'Action' : 'Ação';

        packagesTableWrap.innerHTML = `
            <table class="table table-sm table-hover align-middle mb-0">
                <thead class="table-light">
                    <tr><th>${hPkg}</th><th>${hCur}</th><th>${hOff}</th><th>Status</th><th>${hVul}</th><th>${hAct}</th></tr>
                </thead>
                <tbody>${rowsHtml}</tbody>
            </table>
        `;

        packagesTableWrap.querySelectorAll('.btn-upgrade-pkg').forEach(btn => {
            btn.addEventListener('click', () => requestUpdateWithConfirmation('upgrade_package', btn.dataset.pkg, ''));
        });
    }

    function executeEnvUpdate(action, pkgName, pySeries) {
        updateCommandLog.style.display = 'block';
        updateCommandLog.textContent = `Running update (${action}: ${pkgName || pySeries})...`;
        showToast(currentLang === 'en' ? 'Running Anaconda update...' : 'Executando atualização via Anaconda...', 'info');

        fetch('/api/update-env', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action, package_name: pkgName, target_python_series: pySeries })
        })
        .then(r => r.json())
        .then(data => {
            updateCommandLog.textContent = `$ ${data.command || action}\n\n${data.output || data.message || ''}`;
            if (data.status === 'success') {
                showToast(data.message, 'success');
                runPythonEnvAudit();
            } else {
                showToast(data.message || 'Upgrade failed.', 'danger');
            }
        })
        .catch(() => showToast('Communication error during upgrade.', 'danger'));
    }

    // Load Guardrail Skills, creation instructions, and custom builder matching active language.
    let guardrailTemplates = {};
    const guardrailSelect = document.getElementById('guardrailTemplateSelect');
    const guardrailPreview = document.getElementById('guardrailPreviewTextarea');
    const guardrailDestBadge = document.getElementById('guardrailDestBadge');
    const guardrailDesc = document.getElementById('guardrailTemplateDesc');

    function loadGuardrailTemplates() {
        fetch(`/api/guardrails?lang=${encodeURIComponent(currentLang)}`)
            .then(r => r.json())
            .then(data => {
                if (data.status !== 'success') return;

                const stepsEl = document.getElementById('skillCreationStepsList');
                stepsEl.innerHTML = (data.how_to_create_steps || []).map(s => `
                    <div class="p-2 px-3 border rounded-3 bg-light-subtle">
                        <strong class="small text-dark d-block">${escapeHtml(s.step)}</strong>
                        <span class="text-secondary" style="font-size: 0.78rem;">${escapeHtml(s.text)}</span>
                    </div>
                `).join('');

                const pillarsEl = document.getElementById('guardrailPillarsCheckList');
                pillarsEl.innerHTML = (data.pillars || []).map(p => `
                    <label class="p-2 px-3 border rounded-3 bg-light-subtle d-flex align-items-start gap-2" style="cursor: pointer;">
                        <input type="checkbox" class="form-check-input mt-1 custom-pillar-chk" value="${escapeAttr(p.key)}" checked>
                        <div>
                            <strong class="small text-dark d-block">${escapeHtml(p.title)}</strong>
                            <span class="text-secondary" style="font-size: 0.76rem;">${escapeHtml(p.detail)}</span>
                        </div>
                    </label>
                `).join('');

                guardrailTemplates = {};
                const prevKey = guardrailSelect.value;
                guardrailSelect.innerHTML = (data.templates || []).map(t => {
                    guardrailTemplates[t.key] = t;
                    return `<option value="${escapeAttr(t.key)}">${escapeHtml(t.title)}</option>`;
                }).join('');
                if (prevKey && guardrailTemplates[prevKey]) {
                    guardrailSelect.value = prevKey;
                }
                if (!customSkillMeta) renderSelectedGuardrail();
            })
            .catch(() => {});
    }

    function renderSelectedGuardrail() {
        customSkillMeta = null;
        const tpl = guardrailTemplates[guardrailSelect.value];
        if (!tpl) return;
        guardrailDestBadge.textContent = tpl.relative_install_path;
        guardrailDesc.textContent = tpl.description;
        guardrailPreview.value = tpl.content;
    }

    guardrailSelect.addEventListener('change', renderSelectedGuardrail);

    document.getElementById('btnBuildCustomSkill').addEventListener('click', () => {
        const slug = document.getElementById('customSkillSlug').value.trim() || 'meu-guardrail';
        const publishKw = document.getElementById('customPublishKeyword').value.trim() || (currentLang === 'en' ? 'publish' : 'publicar');
        const pillars = Array.from(document.querySelectorAll('.custom-pillar-chk:checked')).map(c => c.value);

        fetch('/api/build-custom-skill', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                skill_slug: slug,
                publish_keyword: publishKw,
                pillars: pillars,
                lang: currentLang
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                customSkillMeta = data;
                guardrailDestBadge.textContent = data.relative_install_path;
                guardrailDesc.textContent = currentLang === 'en'
                    ? `Custom skill generated for /${data.skill_name}. Click "Save to selected project" to install.`
                    : `Skill customizada gerada para /${data.skill_name}. Clique em "Salvar no projeto selecionado" para gravar.`;
                guardrailPreview.value = data.content;
                showToast(currentLang === 'en' ? 'Custom skill generated in editor.' : 'Skill customizada gerada no editor.', 'success');
            }
        })
        .catch(() => showToast('Error building custom skill.', 'danger'));
    });

    document.getElementById('btnInstallGuardrail').addEventListener('click', () => {
        const targetDir = targetDirInput.value.trim();
        if (!targetDir) {
            showToast(
                currentLang === 'en' ? 'Choose a project folder first to save the skill inside it.' : 'Escolha primeiro a pasta do projeto acima para salvar a skill dentro dela.',
                'warning'
            );
            return;
        }
        const key = customSkillMeta ? 'custom_skill' : guardrailSelect.value;

        fetch('/api/install-guardrail', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_dir: targetDir,
                template_key: key,
                custom_skill_slug: customSkillMeta ? customSkillMeta.skill_name : '',
                content: guardrailPreview.value,
                lang: currentLang
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                showToast(data.message, 'success');
            } else {
                showToast(data.message || 'Error saving guardrail.', 'danger');
            }
        })
        .catch(() => showToast('Communication error saving guardrail.', 'danger'));
    });

    document.getElementById('btnCopyGuardrail').addEventListener('click', () => {
        navigator.clipboard.writeText(guardrailPreview.value).then(() => {
            showToast(currentLang === 'en' ? 'Guardrail copied to clipboard.' : 'Conteúdo do guardrail copiado.', 'success');
        });
    });

    document.getElementById('btnDownloadGuardrail').addEventListener('click', () => {
        const tpl = guardrailTemplates[guardrailSelect.value];
        const filename = customSkillMeta ? customSkillMeta.download_name : (tpl ? tpl.download_name : 'GUARDRAIL.md');
        const blob = new Blob([guardrailPreview.value], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    });

    function exportReport(format) {
        const targetDir = targetDirInput.value.trim();
        if (!lastScanData && !targetDir) {
            showToast(
                currentLang === 'en' ? 'Run a scan on a folder before exporting a report.' : 'Execute uma verificação em alguma pasta antes de exportar o relatório.',
                'warning'
            );
            return;
        }
        fetch('/api/export-report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_dir: targetDir,
                format: format,
                lang: currentLang,
                scan_data: lastScanData,
                env_data: lastEnvData
            })
        })
        .then(async resp => {
            const text = await resp.text();
            if (!resp.ok) throw new Error('Export failed');
            if (format === 'html') {
                const w = window.open('', '_blank');
                w.document.open();
                w.document.write(text);
                w.document.close();
            } else {
                const blob = new Blob([text], { type: format === 'json' ? 'application/json' : 'text/markdown' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = format === 'json' ? 'project_exposure_report.json' : 'project_exposure_report.md';
                a.click();
                URL.revokeObjectURL(url);
            }
        })
        .catch(() => showToast('Error exporting report.', 'danger'));
    }

    function escapeHtml(txt) {
        const div = document.createElement('div');
        div.textContent = txt == null ? '' : String(txt);
        return div.innerHTML;
    }

    function escapeAttr(txt) {
        return (txt == null ? '' : String(txt)).replace(/"/g, '&quot;');
    }

    function restoreAuditSessionState() {
        try {
            const savedDir = localStorage.getItem('gc_target_dir');
            const savedScan = localStorage.getItem('gc_scan_data');
            const savedEnv = localStorage.getItem('gc_env_data');
            const savedTab = localStorage.getItem('gc_active_tab');
            if (savedDir && savedScan) {
                targetDirInput.value = savedDir;
                lastScanData = JSON.parse(savedScan);
                renderScanResults(lastScanData);
            }
            if (savedEnv) {
                lastEnvData = JSON.parse(savedEnv);
                renderPythonEnv(lastEnvData);
            }
            if (savedTab) {
                const tabTrigger = document.querySelector(`#auditTabs button[data-bs-target="${savedTab}"]`);
                if (tabTrigger) bootstrap.Tab.getOrCreateInstance(tabTrigger).show();
            }
        } catch (err) {
            // Ignore corrupt storage cleanly.
        }
    }

    document.querySelectorAll('#auditTabs button[data-bs-toggle="tab"]').forEach(btn => {
        btn.addEventListener('shown.bs.tab', e => {
            const target = e.target.getAttribute('data-bs-target');
            if (target) localStorage.setItem('gc_active_tab', target);
        });
    });

    // Initialize UI text and skill templates; restore persisted results when returning from /testes or switching tabs.
    restoreAuditSessionState();
    applyTranslations();
    loadGuardrailTemplates();

    window.addEventListener('pageshow', () => {
        if (!lastScanData && localStorage.getItem('gc_scan_data')) {
            restoreAuditSessionState();
        }
    });
});
