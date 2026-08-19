"""Allow running the CLI via ``python -m file_encryptor``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())