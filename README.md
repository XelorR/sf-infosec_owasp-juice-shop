# OWASP Juice Shop

## Checklist

### Отчёт должен иметь следующую структуру:

- [ ] Введение — описание приложения.
- [ ] Результаты статического анализа — общие, можно без детализации.
- [ ] Уязвимости из OWASP Top-10, обнаруженные в результате статического анализа, — минимум пять штук.
- [ ] Демонстрация эксплуатации трёх уязвимостей из OWASP Top-10 — скриншоты эксплуатации, проведённой с помощью инструмента Burp Suite. Выбор этих уязвимостей остаётся на ваше усмотрение.
- [ ] Рекомендации по устранению к трём продемонстрированным уязвимостям — можно взять основу с сайта MITRE ATT&CK под найденные CWE.

### В отчёте обязательно должны присутствовать:

- [ ] Скриншоты (минимум два) или выгрузка результатов статического сканирования в пункте 2.
- [ ] Список уязвимостей из OWASP Top-10 с доказательствами в пункте 3 (в виде скриншотов, найденных анализатором уязвимостей; отдельно от остальных уязвимостей).
- [ ] Скриншоты из Burp Suite в пункте 4, а также обязательно текстовое описание эксплуатации: что необходимо сделать, чтобы воспроизвести уязвимость.

### Tools:

- [ ] `semgrep login` and authorize with github
- [ ] burp suite community

#### Semgrep command log

install semgrep
```bash
pipx install semgrep
```

clone juice code
```bash
git clone git@github.com:juice-shop/juice-shop.git
cd juice-shop
```

scan
```bash
semgrep scan --config=auto --json -o results-semgrep.json
```

check
```bash
cat results-semgrep.json | jq . | vim -
```

high level, keys
``` bash
cat results-semgrep.json | jq 'keys[]'
```

```
"errors"
"interfile_languages_used"
"paths"
"results"
"skipped_rules"
"version"
```

example error

``` bash
cat results-semgrep.json | jq '.errors[31]'
```

```json
{
  "code": 2,
  "level": "warn",
  "message": "Timeout when running javascript.lang.security.insecure-object-assign.insecure-object-assign on frontend/src/assets/private/three.js:\n ",
  "path": "frontend/src/assets/private/three.js",
  "rule_id": "javascript.lang.security.insecure-object-assign.insecure-object-assign",
  "type": "Timeout"
}
```

[semgrep results](./results-semgrep.json)

## Report
