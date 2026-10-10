# Docker Compose Validator

Docker Compose fayllarini xavfsizlik (security misconfigurations), resurs cheklovlari va eng yaxshi amaliyotlar bo'yicha tahlil qiluvchi tezkor linter va CI/CD vositasi.

## Xavfsizlik Qoidalari
- **SEC002**: `privileged: true` rejimi (host tizimiga to'liq kirish xavfi).
- **SEC003**: `network_mode: host` (portlar to'qnashuvi va izolyatsiya buzilishi).
- **SEC004**: `environment` bo'limida ochiq (hardcoded) parollar, API kalitlar yoki tokenlar.
- **SEC005**: Xavfli host jildlari (`/var/run/docker.sock`, `/etc`, `/`).
- **REL001**: Konteyner uchun `healthcheck` yo'qligi.
- **REL002**: CPU yoki xotira (RAM) limitlari belgilanmaganligi (OOM xavfi).

## Ishlatish
```bash
compose-validator docker-compose.yml
compose-validator docker-compose.yml --json
compose-validator docker-compose.yml --fail-on-warning
```

## Python API
```python
from compose_validator import ComposeValidator

validator = ComposeValidator()
issues = validator.validate_content(open("docker-compose.yml").read())
for issue in issues:
    print(issue)
```

## Testlar
```bash
pytest tests/ -v
```

## Litsenziya
MIT
