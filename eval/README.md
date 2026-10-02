# Private evaluation

`target_app/` is a small Flask storefront containing deliberately planted
defects across every category the agent reports on: code security, dependencies,
secrets, container configuration, HTTP security headers, accessibility, broken
functionality and performance.

It exists because OWASP Juice Shop cannot serve as evaluation evidence: it is
widely represented in model training data. This app is new, and its code carries
no comments pointing at the defects, so neither the scanners nor the model are
helped.

`answer_sheet.json` lists every planted defect and how a correct detection is
recognised. **It is private**: it is git-ignored and must not be published,
otherwise the evaluation can be tuned against it. It sits outside
`target_app/`, so the agent never scans it.

Run the evaluation with:

```powershell
.\.venv\Scripts\python.exe -m qa_agent evaluate --runs 3
```

The harness starts the app on `127.0.0.1:5055` (never with Flask's debugger),
runs the full agent against both its source and the running instance, scores
the findings against the answer sheet, and writes `eval/results/<timestamp>.json`.
