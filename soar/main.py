"""
CyberNest SOAR Engine — Main Entry Point.

Thin wrapper around soar.consumer for direct invocation:
    python main.py
    python -m soar.main
"""

from soar.consumer import main

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
