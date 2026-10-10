import re
from typing import List, Dict, Any, Optional
import yaml


class Severity:
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class ValidationIssue:
    def __init__(self, service: str, rule_id: str, severity: str, message: str):
        self.service = service
        self.rule_id = rule_id
        self.severity = severity
        self.message = message

    def to_dict(self) -> Dict[str, str]:
        return {
            "service": self.service,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
        }

    def __repr__(self) -> str:
        return f"[{self.severity}] {self.service}: {self.message} ({self.rule_id})"


class ComposeValidator:
    """Docker Compose fayllarini tahlil qilish va xavfsizlik tekshiruvlarini o'tkazish."""

    SENSITIVE_ENV_PATTERNS = [
        re.compile(r"(?i)(password|passwd|secret|api_key|token|auth_token)\s*=\s*['\"]?[^$\s{]+['\"]?"),
    ]

    DANGEROUS_VOLUMES = [
        "/var/run/docker.sock",
        "/",
        "/etc",
        "/proc",
        "/sys",
    ]

    def __init__(self):
        pass

    def validate_content(self, yaml_content: str) -> List[ValidationIssue]:
        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            return [ValidationIssue(service="global", rule_id="SEC000", severity=Severity.ERROR, message=f"YAML xatosi: {e}")]

        if not isinstance(data, dict):
            return [ValidationIssue(service="global", rule_id="SEC000", severity=Severity.ERROR, message="Noto'g'ri Compose formati")]

        services = data.get("services", {})
        if not services or not isinstance(services, dict):
            return [ValidationIssue(service="global", rule_id="SEC001", severity=Severity.WARNING, message="'services' bo'limi topilmadi yoki bo'sh")]

        issues: List[ValidationIssue] = []

        for name, cfg in services.items():
            if not isinstance(cfg, dict):
                continue
            self._check_service(name, cfg, issues)

        return issues

    def _check_service(self, name: str, cfg: Dict[str, Any], issues: List[ValidationIssue]):
        # 1. Privileged mode
        if cfg.get("privileged") is True:
            issues.append(
                ValidationIssue(
                    service=name,
                    rule_id="SEC002",
                    severity=Severity.ERROR,
                    message="Konteyner 'privileged: true' rejimida ishlamasligi kerak (host tizimiga to'liq kirish xavfi)",
                )
            )

        # 2. Host network mode
        if cfg.get("network_mode") == "host":
            issues.append(
                ValidationIssue(
                    service=name,
                    rule_id="SEC003",
                    severity=Severity.WARNING,
                    message="'network_mode: host' tarmog'i portlar to'qnashuvi va xavfsizlik izolyatsiyasini susaytiradi",
                )
            )

        # 3. Environment plain-text sirlar
        envs = cfg.get("environment")
        if isinstance(envs, list):
            for env_str in envs:
                if isinstance(env_str, str):
                    for pat in self.SENSITIVE_ENV_PATTERNS:
                        if pat.search(env_str):
                            issues.append(
                                ValidationIssue(
                                    service=name,
                                    rule_id="SEC004",
                                    severity=Severity.ERROR,
                                    message=f"Atrof-muhit o'zgaruvchisida ochiq maxfiy kalit aniqlandi: '{env_str.split('=')[0]}'",
                                )
                            )
        elif isinstance(envs, dict):
            for k, v in envs.items():
                if v and not str(v).startswith("${"):
                    for pat in [re.compile(r"(?i)(password|secret|api_key|token)")]:
                        if pat.search(k):
                            issues.append(
                                ValidationIssue(
                                    service=name,
                                    rule_id="SEC004",
                                    severity=Severity.ERROR,
                                    message=f"Atrof-muhit o'zgaruvchisida ochiq maxfiy qiymat: '{k}'",
                                )
                            )

        # 4. Xavfli jildlar (Volume mounts)
        volumes = cfg.get("volumes", [])
        if isinstance(volumes, list):
            for vol in volumes:
                host_path = str(vol).split(":")[0].strip()
                if host_path in self.DANGEROUS_VOLUMES:
                    issues.append(
                        ValidationIssue(
                            service=name,
                            rule_id="SEC005",
                            severity=Severity.ERROR,
                            message=f"Xavfli host yo'li ulangan: '{host_path}'",
                        )
                    )

        # 5. Healthcheck mavjudligi
        if "healthcheck" not in cfg:
            issues.append(
                ValidationIssue(
                    service=name,
                    rule_id="REL001",
                    severity=Severity.INFO,
                    message="Konteyner salomatligini kuzatish uchun 'healthcheck' tavsiya etiladi",
                )
            )

        # 6. Resurs limitlari
        has_limits = False
        deploy = cfg.get("deploy", {})
        if isinstance(deploy, dict):
            resources = deploy.get("resources", {})
            if isinstance(resources, dict) and "limits" in resources:
                has_limits = True
        if "mem_limit" in cfg or "cpus" in cfg:
            has_limits = True

        if not has_limits:
            issues.append(
                ValidationIssue(
                    service=name,
                    rule_id="REL002",
                    severity=Severity.WARNING,
                    message="Konteyner xotira (RAM) yoki CPU limitlarisiz sozlangan (OOM xavfi)",
                )
            )
