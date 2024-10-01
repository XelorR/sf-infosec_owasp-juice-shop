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
semgrep scan --config=auto --json -o results.json
```

check
```bash
cat results.json | jq . | vim -
```

high lever, keys

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

[semgrep results](./results-semgrep.json)

## Report
