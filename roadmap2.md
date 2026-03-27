# Sprint 2 — Implementation Guide

## O que foi criado

| Arquivo | Task | O que faz |
|---|---|---|
| `adversarial/utils/retry.py` | Retry + circuit breaker | Exponential backoff, jitter, circuit breaker por modelo |
| `adversarial/cli/progress.py` | Rich progress bar | Live bypass rate, ETA, resumo final colorido |
| `Dockerfile` | Docker | Imagem Python 3.11-slim com weasyprint system deps |
| `docker-compose.yml` | Docker | Framework + Ollama sidecar + dashboard + volumes |
| `.github/workflows/ci.yml` | CI | lint → mypy → pytest → docker build → trivy scan |
| `.github/workflows/release.yml` | Release | PyPI trusted publish + Docker Hub + GitHub Release |
| `reporting/pdf_renderer.py` | PDF export | WeasyPrint → PDF profissional com capa, assinatura, EU AI Act |
| `reporting/server.py` | Dashboard web | FastAPI: lista reports, viewer, filtros, download JSON/MD/PDF |
| `constitution/examples/healthcare.yaml` | Constitution | Hospital completo: 7 prohibited actions, 5 escalation triggers |
| `constitution/examples/legal.yaml` | Constitution | Martinelli completo: 7 prohibited actions, 5 escalation triggers |
| `pyproject.toml` | Distribuição | v0.3.0, deps Sprint 2, extras [pdf] e [all] |

---

## Como implementar na VM

### 1. Copie os arquivos

```bash
# Copie cada arquivo no caminho indicado acima
# dentro de ~/adversarial-constitution/
```

### 2. Instale as dependências do Sprint 2

```bash
pip install -e ".[dev]" --break-system-packages

# Para PDF export (requer libpango no sistema):
apt-get install -y libpango-1.0-0 libpangoft2-1.0-0
pip install weasyprint --break-system-packages
```

### 3. Verifique os imports

```bash
python -c "from adversarial.utils.retry import with_retry, CircuitBreaker; print('retry OK')"
python -c "from adversarial.cli.progress import AuditProgress; print('progress OK')"
python -c "from reporting.pdf_renderer import AuditPDFRenderer; print('pdf OK')"
python -c "from reporting.server import create_app; print('server OK')"
```

### 4. Rode com Docker (mais fácil)

```bash
# Build e sobe tudo
docker-compose up --build -d

# Pull do modelo llama3
docker-compose exec ollama ollama pull llama3:latest

# Roda um audit
docker-compose exec adv-constitution python -m adversarial.attack_engine run \
  -c constitution/examples/banking.yaml \
  --model ollama/llama3:latest \
  --judge ollama/llama3:latest \
  -o reports/banking_audit.json

# Abre o dashboard
# http://localhost:8080
```

### 5. Dashboard local (sem Docker)

```bash
# Em um terminal:
python -m reporting.server
# Acesse: http://localhost:8080

# Em outro terminal, rode o audit:
antz run -c constitution/examples/banking.yaml \
  --model ollama/llama3:latest \
  --judge ollama/llama3:latest \
  -o reports/banking_audit.json
```

### 6. Gerar PDF de um relatório existente

```python
from pathlib import Path
from reporting.pdf_renderer import AuditPDFRenderer
from reporting.audit_report import AuditReportAssembler
from constitution.schema import ConstitutionLoader

constitution = ConstitutionLoader.from_file("constitution/examples/banking.yaml")
assembler    = AuditReportAssembler(constitution)
report       = assembler.build(bypass_reports=[], ...)

renderer = AuditPDFRenderer()
pdf_path = renderer.render(report, Path("reports/banking_audit.pdf"))
print(f"PDF salvo em: {pdf_path}")
```

### 7. Testar healthcare e legal

```bash
# Healthcare
antz run -c constitution/examples/healthcare.yaml \
  --model ollama/llama3:latest --judge ollama/llama3:latest \
  -o reports/healthcare_audit.json

# Legal 
antz run -c constitution/examples/legal.yaml \
  --model ollama/llama3:latest --judge ollama/llama3:latest \
  -o reports/legal_martinelli_audit.json
```

### 8. Publicar no PyPI (quando pronto)

```bash
# Configurar PyPI trusted publishing em:
# https://pypi.org/manage/account/publishing/
# Project: adversarial-constitution
# Workflow: release.yml

# Criar uma release:
git tag v0.3.0
git push origin v0.3.0
# O GitHub Action faz o resto
```

---

## Usando o retry nas attack modules (opcional, Sprint 3)

O `retry.py` está pronto mas ainda não está integrado nos módulos de ataque.
Para integrar, substitua chamadas diretas ao agente por:

```python
from adversarial.utils.retry import resilient_invoke

# Antes:
response = await (agent | StrOutputParser()).ainvoke(messages)

# Depois (com retry + circuit breaker):
response = await resilient_invoke(
    lambda: (agent | StrOutputParser()).ainvoke(messages),
    model_name="ollama/llama3",
    fallback="[MODEL_UNAVAILABLE]",
)
```

---

## Secrets necessários para o CI/CD

Configure no GitHub → Settings → Secrets:

| Secret | Onde usar |
|---|---|
| `DOCKERHUB_USERNAME` | release.yml → Docker push |
| `DOCKERHUB_TOKEN` | release.yml → Docker push |

PyPI usa OIDC trusted publishing — não precisa de API token.
Configure em: https://pypi.org/manage/account/publishing/

---

## Arquitetura final após Sprint 2

```
adversarial-constitution/
├── adversarial/
│   ├── attacks/
│   │   ├── base.py                ← BaseVulnerabilityReport (S1)
│   │   ├── constraint_bypass.py   ← original
│   │   ├── threshold_probing.py   ← original
│   │   ├── prompt_injection.py    ← S1
│   │   ├── goal_hijacking.py      ← S1 (fixed)
│   │   └── indirect_injection.py  ← S1 (fixed)
│   ├── adapters/
│   │   ├── http_agent.py          ← S1
│   │   └── langgraph.py           ← S1 (LangGraph + CrewAI + AutoGen)
│   ├── utils/
│   │   └── retry.py               ← S2 ✅
│   ├── cli/
│   │   └── progress.py            ← S2 ✅
│   └── attack_engine.py           ← S1 updated
├── constitution/
│   ├── schema.py                  ← original
│   ├── builder.py                 ← S1
│   └── examples/
│       ├── banking.yaml           ← original
│       ├── healthcare.yaml        ← S2 ✅ (completo)
│       └── legal.yaml             ← S2 ✅ (Martinelli)
├── defense/
│   └── constitution_hardener.py   ← original
├── reporting/
│   ├── audit_report.py            ← S1 updated
│   ├── pdf_renderer.py            ← S2 ✅
│   ├── server.py                  ← S2 ✅
│   └── templates/report.md.j2    ← original
├── .github/workflows/
│   ├── ci.yml                     ← S2 ✅
│   └── release.yml                ← S2 ✅
├── Dockerfile                     ← S2 ✅
├── docker-compose.yml             ← S2 ✅
└── pyproject.toml                 ← S2 v0.3.0 ✅
```