# nuclei local web GUI (Option A)

Tiny FastAPI wrapper around the `nuclei` CLI. No Go changes needed.

## Prereqs

```bash
make build            # produces ./bin/nuclei (or put nuclei on PATH / set NUCLEI_BIN)
pip install -r gui/requirements.txt
```

## Run

```bash
python gui/app.py
# open http://127.0.0.1:9057
```

## Inputs — all four covered

| UI choice | What the server does |
|---|---|
| plain URLs (`list`) | writes pasted/uploaded lines to `jobs/<id>/input.used`, runs `-im list` |
| OpenAPI 3 (`openapi`) | passes file through, `-im openapi` |
| Swagger 2 (`swagger`) | passes file through, `-im swagger` |
| Postman collection (`postman`) | `postman_to_openapi.py` converts to OpenAPI 3 JSON, then `-im openapi`. Supports nested folders, headers, query/path params, raw JSON bodies, apiKey/basic/bearer auth. Drops disabled entries; `{{variables}}` become `test`. |

`auto-detect` sniffs the upload (Postman JSON shape, `openapi:`/`swagger:` markers, Burp XML, raw HTTP) and falls back to `list`.

## Outputs

Each job dir (`gui/jobs/<id>/`) gets `findings.txt`, `results.json` (`-je`),
`report.sarif` (`-se`), `report.pdf` (`-pe`), markdown dir (`-me`), and `run.log`.
The UI polls `/api/jobs/<id>/log` + `/results` and lists everything under
`/api/jobs/<id>/files` as download links.

## Notes / limits

- Binds to `127.0.0.1` only; no auth — local use.
- `gui/jobs/` is git-ignored scratch space; delete old job dirs freely.
- Converter CLI also works standalone: `python gui/postman_to_openapi.py collection.json openapi.json`.
