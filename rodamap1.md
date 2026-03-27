# Sprint 1 — Implementation Guide

## O que foi criado/modificado

### Novos arquivos

| Arquivo | O que faz |
|---|---|
| `adversarial/attacks/base.py` | `BaseVulnerabilityReport` — tipo unificado para todos os ataques |
| `adversarial/attacks/prompt_injection.py` | Ataque de injeção direta, role confusion, system override |
| `adversarial/attacks/goal_hijacking.py` | Refatorado: LCEL pipe chain + `to_base()` + 5 técnicas de hijacking |
| `adversarial/attacks/indirect_injection.py` | Refatorado: 5 vetores (RAG, email, tool, web, calendar) + `to_base()` |
| `adversarial/adapters/__init__.py` | Exports limpos dos adapters |
| `adversarial/adapters/http_agent.py` | `HTTPAgentAdapter` — qualquer REST API como BaseChatModel |
| `adversarial/adapters/langgraph.py` | `LangGraphAdapter`, `CrewAIAdapter`, `AutoGenAdapter` |
| `constitution/builder.py` | CLI interativo `antz init` — gera YAML + MD para cliente assinar |
| `pyproject.toml` | Atualizado: versão 0.2.0, entry point `antz`, dep `langchain-litellm` |

### Arquivos modificados

| Arquivo | O que mudou |
|---|---|
| `adversarial/attack_engine.py` | Integra os 5 ataques, flags `--agent-url`/`--agent-type`, subcommand `init` |
| `reporting/audit_report.py` | Aceita `extra_base_reports`, `_flatten_base()`, citações regulatórias por attack type |

---

## Como implementar na VM

### 1. Copie os arquivos para o repositório

```bash
# Na VM, dentro de ~/adversarial-constitution/
# Copie cada arquivo nos caminhos indicados acima
```

### 2. Reinstale o pacote

```bash
pip install -e ".[dev]" --break-system-packages
```

### 3. Verifique os imports

```bash
python -c "from adversarial.attacks.prompt_injection import PromptInjectionAttack; print('OK')"
python -c "from adversarial.adapters import HTTPAgentAdapter; print('OK')"
python -c "from constitution.builder import cli_init; print('OK')"
```

### 4. Rode os testes existentes

```bash
pytest tests/ -v
```

### 5. Teste o constitution builder

```bash
antz init
# ou
python -m adversarial.attack_engine init
```

### 6. Rode o audit completo (5 ataques)

```bash
python -m adversarial.attack_engine run \
  -c constitution/examples/banking.yaml \
  --model ollama/llama3:latest \
  --judge ollama/llama3:latest \
  -o reports/audit_report.json
```

### 7. Teste o HTTP adapter (black-box)

```bash
python -m adversarial.attack_engine run \
  -c constitution/examples/banking.yaml \
  --agent-url http://seu-agente.com/api/chat \
  --agent-headers "Authorization:Bearer seu-token" \
  --judge ollama/llama3:latest \
  -o reports/audit_report.json
```

---

## Uso programático dos adapters

### LangGraph

```python
from adversarial.adapters import LangGraphAdapter
from adversarial.attacks.constraint_bypass import ConstraintBypassAttack

graph   = seu_graph.compile()
adapter = LangGraphAdapter(graph=graph, input_key="messages", output_key="messages")
attack  = ConstraintBypassAttack(adapter, judge_agent, constitution)
reports = await attack.run()
```

### CrewAI

```python
from adversarial.adapters import CrewAIAdapter

crew    = Crew(agents=[...], tasks=[...])
adapter = CrewAIAdapter(crew=crew, input_variable="customer_request")
attack  = ConstraintBypassAttack(adapter, judge_agent, constitution)
```

### HTTP Black-box

```python
from adversarial.adapters import HTTPAgentAdapter

adapter = HTTPAgentAdapter(
    url="https://meu-agente.com/api/chat",
    headers={"Authorization": "Bearer sk-..."},
    message_field="message",       # campo que o agente espera
    response_field="choices.0.message.content",  # dot-path para extrair resposta
)
ok, info = await adapter.probe()   # verifica conectividade antes de atacar
```

---

## O que vem no Sprint 2

- [ ] Retry + exponential backoff (tenacity)
- [ ] Rich progress bar com ETA e taxa de bypass em tempo real
- [ ] Dockerfile + docker-compose
- [ ] GitHub Actions CI
- [ ] PDF export do audit report (weasyprint)
- [ ] `antz audit serve` — dashboard web local (FastAPI)
- [ ] PyPI publish
- [ ] healthcare.yaml e legal.yaml completos