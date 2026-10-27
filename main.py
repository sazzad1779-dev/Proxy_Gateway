"""Entry point: `python main.py -- <chatbot-cli ...>` wraps any CLI with the
llmlogs proxy so its prompts/responses land in llmlogs.db. Same as capture.py.
"""
from capture import main_cli


def main():
    raise SystemExit(main_cli())


if __name__ == "__main__":
    main()
