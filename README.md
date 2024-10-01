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

<details>

<summary>first scan, figuring out how does it work</summary>

[first results](./results-semgrep.json)

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

example result

```bash
cat results-semgrep.json | jq '.results[65]'
```

```json
{
  "check_id": "javascript.express.security.audit.xss.pug.explicit-unescape.template-explicit-unescape",
  "end": {
    "col": 40,
    "line": 79,
    "offset": 3969
  },
  "extra": {
    "engine_kind": "OSS",
    "fingerprint": "a15f585b68d6d123be356ae999949a88694dcee167c404b60d277df0ecb69aceaa54652bb72451e4c0cd5b1e6152730adc6dc1c6487ae2b3dc443410f1188dc4_0",
    "is_ignored": false,
    "lines": "            if (splitted.length != 2) {",
    "message": "Detected an explicit unescape in a Pug template, using either '!=' or '!{...}'. If external data can reach these locations, your application is exposed to a cross-site scripting (XSS) vulnerability. If you must do this, ensure no external data can reach this location.",
    "metadata": {
      "category": "security",
      "confidence": "LOW",
      "cwe": [
        "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
      ],
      "cwe2021-top25": true,
      "cwe2022-top25": true,
      "impact": "MEDIUM",
      "license": "Commons Clause License Condition v1.0[LGPL-2.1-only]",
      "likelihood": "LOW",
      "owasp": [
        "A07:2017 - Cross-Site Scripting (XSS)",
        "A03:2021 - Injection"
      ],
      "references": [
        "https://pugjs.org/language/code.html#unescaped-buffered-code",
        "https://pugjs.org/language/attributes.html#unescaped-attributes"
      ],
      "semgrep.dev": {
        "rule": {
          "origin": "community",
          "r_id": 9287,
          "rule_id": "WAUonl",
          "rv_id": 834091,
          "url": "https://semgrep.dev/playground/r/ZRTlPA9/javascript.express.security.audit.xss.pug.explicit-unescape.template-explicit-unescape",
          "version_id": "ZRTlPA9"
        }
      },
      "shortlink": "https://sg.run/3xbe",
      "source": "https://semgrep.dev/r/javascript.express.security.audit.xss.pug.explicit-unescape.template-explicit-unescape",
      "subcategory": [
        "audit"
      ],
      "technology": [
        "express"
      ],
      "vulnerability_class": [
        "Cross-Site-Scripting (XSS)"
      ]
    },
    "metavars": {
      "$1": {
        "abstract_content": "!=",
        "end": {
          "col": 35,
          "line": 79,
          "offset": 3964
        },
        "start": {
          "col": 33,
          "line": 79,
          "offset": 3962
        }
      }
    },
    "severity": "WARNING",
    "validation_state": "NO_VALIDATOR"
  },
  "path": "views/promotionVideo.pug",
  "start": {
    "col": 13,
    "line": 79,
    "offset": 3942
  }
}
```

</details>

[second scan](./results-top10owasp-semgrep.json) - owasp top 10

``` bash
semgrep --config "p/owasp-top-ten" --json -o results-top10owasp-semgrep.json
```

## Report
