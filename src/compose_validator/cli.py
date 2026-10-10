import argparse
import sys
import json
import os
from .validator import ComposeValidator, Severity


def main():
    parser = argparse.ArgumentParser(description="Docker Compose Validator - Xavfsizlik va barqarorlik linteri")
    parser.add_argument("file", help="docker-compose.yml fayliga yo'l")
    parser.add_argument("--json", action="store_true", help="Natijalarni JSON formatida chiqarish")
    parser.add_argument("--fail-on-warning", action="store_true", help="Ogohlantirishlar bo'lsa ham xatolik qaytarish")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Xatolik: Fayl topilmadi: {args.file}", file=sys.stderr)
        sys.exit(2)

    with open(args.file, "r", encoding="utf-8") as f:
        content = f.read()

    validator = ComposeValidator()
    issues = validator.validate_content(content)

    has_error = any(i.severity == Severity.ERROR for i in issues)
    has_warning = any(i.severity == Severity.WARNING for i in issues)

    if args.json:
        print(json.dumps([i.to_dict() for i in issues], indent=2))
    else:
        if not issues:
            print(f"✅ {args.file}: Barcha xavfsizlik va arxitektura tekshiruvlaridan muvaffaqiyatli o'tdi!")
        else:
            print(f"Tekshiruv natijalari ({args.file}):")
            for i in issues:
                print(f"  {i}")

    if has_error or (args.fail_on_warning and has_warning):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
