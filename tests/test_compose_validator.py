import pytest
from compose_validator.validator import ComposeValidator, Severity


def test_validator_detects_privileged_and_sensitive_env():
    yaml_bad = """
version: '3.8'
services:
  web:
    image: nginx:alpine
    privileged: true
    environment:
      - DB_PASSWORD=SuperSecretPass123!
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
    validator = ComposeValidator()
    issues = validator.validate_content(yaml_bad)

    error_rules = [i.rule_id for i in issues if i.severity == Severity.ERROR]
    assert "SEC002" in error_rules  # privileged
    assert "SEC004" in error_rules  # sensitive env
    assert "SEC005" in error_rules  # dangerous volume docker.sock


def test_validator_clean_service():
    yaml_good = """
version: '3.8'
services:
  app:
    image: myapp:1.0.0
    environment:
      - DB_PASSWORD=${DB_PASSWORD}
    deploy:
      resources:
        limits:
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
"""
    validator = ComposeValidator()
    issues = validator.validate_content(yaml_good)

    errors = [i for i in issues if i.severity == Severity.ERROR]
    assert len(errors) == 0
    warnings = [i for i in issues if i.severity == Severity.WARNING]
    assert len(warnings) == 0


def test_validator_yaml_parse_error():
    validator = ComposeValidator()
    issues = validator.validate_content("invalid: yaml: [syntax error")
    assert any(i.rule_id == "SEC000" for i in issues)
