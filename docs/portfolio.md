# Portfolio summary

Use the wording below only while it accurately reflects the repository state.
The project is a learning scaffold, not an enterprise-grade or production-certified
gateway.

## Resume entry (LaTeX)

```latex
\project{LLM Security Gateway + Controlled Red-Teaming}
        {https://github.com/ATishere/llm-security-gateway}
\begin{itemize}
    \item Built a FastAPI gateway prototype with heuristic prompt-injection checks,
          Unicode normalization, configurable shadow/enforce behavior, and PII masking.
    \item Added an Anthropic Messages-compatible asynchronous upstream adapter with
          timeout and response inspection; included optional Presidio integration.
    \item Implemented a bounded optional LangGraph/Garak evaluation workflow for
          explicitly authorized loopback targets, including JSONL parsing and tests.
    \item Added Docker/Compose and GitHub Actions checks for lint and unit tests;
          CI does not run attack campaigns.
    \item \textbf{Tech:} Python, FastAPI, Pydantic Settings, HTTPX, Presidio (optional),
          Garak (optional), LangGraph (optional), Docker, GitHub Actions
\end{itemize}
```

Do not claim measured accuracy, latency, full OWASP/MITRE coverage, Redis,
Llama Guard, PyRIT, TAP/PAIR, CVSS scoring, or automatic red-team scans in CI:
those are not implemented or measured in this repository.
